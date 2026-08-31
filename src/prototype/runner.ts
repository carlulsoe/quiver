import { init, type ConversationStreamChunk, type PromptUsage } from "@flue/runtime";
import { start } from "@flue/runtime/node";
import { AdaptiveCoordinator } from "./adaptive-coordinator.ts";
import { createExplorerAgent, createValidatorAgent } from "./agents.ts";
import { CampaignLedger } from "./campaign-ledger.ts";
import { ChainBudgetExceededError, replayExploitChain } from "./exploit-chain.ts";
import { GLM_FLASH_MODEL } from "./models.ts";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { ScopedTarget } from "./scoped-target.ts";
import {
  createCampaignBudget,
  createCampaignState,
  reduceCampaign,
  type CampaignAction,
  type CampaignState,
} from "./state.ts";
import { assertValidTargetProfile, type TargetProfile } from "./target-profile.ts";

export interface RunCampaignOptions {
  target: URL;
  profile: TargetProfile;
  requestBudget?: number;
  explorerCount?: number;
  onState?: (state: CampaignState, action?: CampaignAction) => void;
  openApi?: unknown;
  context?: string;
}

export interface CampaignRun {
  profileId: string;
  reproductionAuthentication?: TargetProfile["reproductionAuthentication"];
  model: string;
  durationMs: number;
  usage: PromptUsage;
  state: CampaignState;
  events: RunEvent[];
}

export interface RunEvent {
  sequence: number;
  elapsedMs: number;
  type: "state" | "request" | "tool-call" | "tool-output" | "tool-error";
  data: Record<string, unknown>;
}

export async function runCampaign(options: RunCampaignOptions): Promise<CampaignRun> {
  assertValidTargetProfile(options.profile);
  await using artifacts = new ProofArtifactStore();
  const startedAt = performance.now();
  const budget = createCampaignBudget(options.requestBudget ?? 30);
  const explorerCount = options.explorerCount ?? 2;
  const events: RunEvent[] = [];
  const usage = emptyUsage();
  const record = (type: RunEvent["type"], data: Record<string, unknown>) => {
    events.push({
      sequence: events.length + 1,
      elapsedMs: Math.round(performance.now() - startedAt),
      type,
      data,
    });
  };
  const captureAgentEvent = (agentId: string, chunk: ConversationStreamChunk) => {
    if (chunk.type === "tool-input") {
      record("tool-call", {
        agentId,
        toolCallId: chunk.toolCallId,
        toolName: chunk.toolName,
        input: chunk.input,
      });
    } else if (chunk.type === "tool-output") {
      record("tool-output", {
        agentId,
        toolCallId: chunk.toolCallId,
        output: chunk.output,
        durationMs: chunk.durationMs,
      });
    } else if (chunk.type === "tool-output-error") {
      record("tool-error", {
        agentId,
        toolCallId: chunk.toolCallId,
        error: chunk.errorText,
        durationMs: chunk.durationMs,
      });
    }
  };
  const captureUsage = (metadata: Record<string, unknown> | undefined) => {
    const value = metadata?.quiverUsage;
    if (!isPromptUsage(value)) return;
    usage.input += value.input;
    usage.output += value.output;
    usage.cacheRead += value.cacheRead;
    usage.cacheWrite += value.cacheWrite;
    usage.totalTokens += value.totalTokens;
    usage.cost.input += value.cost.input;
    usage.cost.output += value.cost.output;
    usage.cost.cacheRead += value.cost.cacheRead;
    usage.cost.cacheWrite += value.cost.cacheWrite;
    usage.cost.total += value.cost.total;
  };
  let state = createCampaignState(
    `${options.target.origin}${options.target.pathname}${options.target.search}`,
    budget,
    explorerCount,
  );
  const dispatch = (action: CampaignAction) => {
    state = reduceCampaign(state, action);
    record("state", {
      action: action.type,
      phase: state.phase,
      requestsUsed: state.requests.total,
      testedRequestCount: state.testedRequests.length,
      findingCount: state.findings.length,
      validationCount: state.validations.length,
      exploitChainCount: state.exploitChains.length,
    });
    options.onState?.(state, action);
  };
  options.onState?.(state);

  try {
    const explorationTarget = new ScopedTarget({
      target: options.target,
      requestBudget: budget.exploration,
      allowedRequests: options.profile.allowedRequests,
      deniedRequests: options.profile.deniedRequests,
      onRequest: (request) => {
        record("request", { phase: "exploration", ...request });
        dispatch({ type: "request", phase: "exploration" });
      },
      openApi: options.openApi,
      maximumImpactLevel: options.profile.maximumImpactLevel ?? "observation",
    });
    const coordinator = new AdaptiveCoordinator({
      supportsAuthentication: options.profile.authenticate !== undefined,
    });
    const ledger = new CampaignLedger({
      onTestedRequest: (request) => {
        coordinator.observeRequest(request);
        dispatch({ type: "request-tested", request });
      },
      onFinding: (finding) => {
        coordinator.observeFinding(finding);
        dispatch({ type: "finding", finding });
      },
      onExploitChain: (chain) => dispatch({ type: "exploit-chain", chain }),
    });
    if (options.profile.authenticate) {
      await explorationTarget.runProfileSetup(() =>
        options.profile.authenticate!(explorationTarget),
      );
    }
    dispatch({ type: "phase", phase: "exploring" });
    const focuses = [
      "broken authorization and cross-object access, using identifiers discovered in one response against other GET endpoints",
      "excessive or sensitive data exposure and security misconfiguration",
      "route-level authentication gaps and object-detail authorization controls not yet tested by the other explorers",
    ];
    const explorers = Array.from({ length: explorerCount }, (_, index) =>
      createExplorerAgent(
        `explorer-${index + 1}`,
        focuses[index] ?? "the remaining REST attack surface not covered by other explorers",
        explorationTarget,
        options.profile,
        ledger,
        coordinator,
        artifacts,
        dispatch,
        options.context,
      ),
    );
    let validationTarget: ScopedTarget | undefined;
    const Validator = createValidatorAgent(
      () => state.findings,
      () => {
        if (!validationTarget) throw new Error("Validation target is not ready");
        return validationTarget;
      },
      options.profile,
      artifacts,
      dispatch,
    );
    await using _campaignRuntime = await start({ agents: [...explorers, Validator] });
    {
      await Promise.all(
        explorers.map(async (Explorer, index) => {
          const id = `explorer-${index + 1}`;
          dispatch({ type: "agent", id, status: "running" });
          try {
            const agent = init(Explorer);
            const receipt = await agent.dispatch("Begin the bounded REST security campaign.");
            const reply = await agent.read(receipt, {
              onEvent: (chunk) => captureAgentEvent(id, chunk),
            });
            captureUsage(reply.metadata);
            dispatch({
              type: "agent",
              id,
              status: "finished",
              summary: reply.text.slice(0, 100),
            });
          } catch (error) {
            dispatch({ type: "agent", id, status: "failed", summary: String(error) });
          } finally {
            coordinator.release(id);
          }
        }),
      );
    }

    dispatch({ type: "reclaim-exploration-budget" });
    dispatch({ type: "phase", phase: "validating" });
    if (state.findings.length > 0) {
      validationTarget = new ScopedTarget({
        target: options.target,
        requestBudget: state.budget.validation,
        allowedRequests: [
          ...(options.profile.allowedRequests ?? []),
          ...state.findings.flatMap((finding) =>
            finding.reproduction.map(({ method = "GET", path }) => ({ method, path })),
          ),
        ],
        deniedRequests: options.profile.deniedRequests,
        onRequest: (request) => {
          record("request", { phase: "validation", ...request });
          dispatch({ type: "request", phase: "validation" });
        },
        maximumImpactLevel: options.profile.maximumImpactLevel ?? "observation",
      });
      if (
        options.profile.authenticate &&
        state.findings.some(
          (finding) =>
            finding.reproduction.some((request) => request.authenticated) ||
            (finding.proof.type === "browser-visible-effect" && finding.proof.pageAuthenticated),
        )
      ) {
        await validationTarget.runProfileSetup(() =>
          options.profile.authenticate!(validationTarget!),
        );
      }
      dispatch({ type: "agent", id: "validator", status: "running" });
      const validator = init(Validator);
      const receipt = await validator.dispatch("Validate every submitted campaign finding.");
      const reply = await validator.read(receipt, {
        onEvent: (chunk) => captureAgentEvent("validator", chunk),
      });
      captureUsage(reply.metadata);
      dispatch({
        type: "agent",
        id: "validator",
        status: "finished",
        summary: reply.text.slice(0, 100),
      });
    } else {
      dispatch({
        type: "agent",
        id: "validator",
        status: "finished",
        summary: "No findings required validation.",
      });
    }
    for (const chain of state.exploitChains) {
      if (!validationTarget) break;
      try {
        dispatch({
          type: "exploit-chain-validation",
          validation: await replayExploitChain(
            validationTarget,
            chain,
            state.findings,
            options.profile,
            artifacts,
          ),
        });
      } catch (error) {
        if (error instanceof ChainBudgetExceededError) continue;
        dispatch({
          type: "exploit-chain-validation",
          validation: {
            fingerprint: chain.fingerprint,
            status: "rejected",
            summary: error instanceof Error ? error.message : String(error),
            checks: [
              {
                passed: false,
                description: "ordered exploit-chain replay completed without an error",
              },
            ],
          },
        });
      }
    }
    dispatch({ type: "phase", phase: "complete" });
  } catch (error) {
    dispatch({ type: "failed", error: error instanceof Error ? error.message : String(error) });
  }

  return {
    profileId: options.profile.id,
    reproductionAuthentication: options.profile.reproductionAuthentication,
    model: GLM_FLASH_MODEL,
    durationMs: Math.round(performance.now() - startedAt),
    usage,
    state,
    events,
  };
}

function emptyUsage(): PromptUsage {
  return {
    input: 0,
    output: 0,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens: 0,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  };
}

function isPromptUsage(value: unknown): value is PromptUsage {
  if (!value || typeof value !== "object") return false;
  const usage = value as Partial<PromptUsage>;
  return (
    typeof usage.input === "number" &&
    typeof usage.output === "number" &&
    typeof usage.cacheRead === "number" &&
    typeof usage.cacheWrite === "number" &&
    typeof usage.totalTokens === "number" &&
    !!usage.cost &&
    typeof usage.cost.input === "number" &&
    typeof usage.cost.output === "number" &&
    typeof usage.cost.cacheRead === "number" &&
    typeof usage.cost.cacheWrite === "number" &&
    typeof usage.cost.total === "number"
  );
}
