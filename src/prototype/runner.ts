import { init, type ConversationStreamChunk } from "@flue/runtime";
import { start } from "@flue/runtime/node";
import { createExplorerAgent, createValidatorAgent } from "./agents.ts";
import { CampaignLedger } from "./campaign-ledger.ts";
import { GLM_FLASH_MODEL } from "./models.ts";
import { ScopedTarget } from "./scoped-target.ts";
import {
  createCampaignBudget,
  createCampaignState,
  reduceCampaign,
  type CampaignAction,
  type CampaignState,
} from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";

export interface RunCampaignOptions {
  target: URL;
  profile: TargetProfile;
  requestBudget?: number;
  explorerCount?: number;
  onState?: (state: CampaignState, action?: CampaignAction) => void;
}

export interface CampaignRun {
  profileId: string;
  model: string;
  durationMs: number;
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
  const startedAt = performance.now();
  const budget = createCampaignBudget(options.requestBudget ?? 30);
  const explorerCount = options.explorerCount ?? 2;
  const events: RunEvent[] = [];
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
    });
    const ledger = new CampaignLedger({
      onTestedRequest: (request) => dispatch({ type: "request-tested", request }),
      onFinding: (finding) => dispatch({ type: "finding", finding }),
    });
    if (options.profile.authenticate) await options.profile.authenticate(explorationTarget);
    dispatch({ type: "phase", phase: "exploring" });
    const focuses = [
      "broken authorization and cross-object access, using identifiers discovered in one response against other GET endpoints",
      "excessive or sensitive data exposure and security misconfiguration",
    ];
    const explorers = Array.from({ length: explorerCount }, (_, index) =>
      createExplorerAgent(
        `explorer-${index + 1}`,
        focuses[index] ?? "the remaining read-only attack surface not covered by other explorers",
        explorationTarget,
        options.profile,
        ledger,
      ),
    );
    {
      await using _explorerRuntime = await start({ agents: explorers });
      await Promise.all(
        explorers.map(async (Explorer, index) => {
          const id = `explorer-${index + 1}`;
          dispatch({ type: "agent", id, status: "running" });
          try {
            const agent = init(Explorer);
            const receipt = await agent.dispatch("Begin the bounded read-only campaign.");
            const reply = await agent.read(receipt, {
              onEvent: (chunk) => captureAgentEvent(id, chunk),
            });
            dispatch({
              type: "agent",
              id,
              status: "finished",
              summary: reply.text.slice(0, 100),
            });
          } catch (error) {
            dispatch({ type: "agent", id, status: "failed", summary: String(error) });
          }
        }),
      );
    }

    dispatch({ type: "reclaim-exploration-budget" });
    dispatch({ type: "phase", phase: "validating" });
    if (state.findings.length > 0) {
      const validationTarget = new ScopedTarget({
        target: options.target,
        requestBudget: state.budget.validation,
        allowedRequests: options.profile.allowedRequests,
        deniedRequests: options.profile.deniedRequests,
        onRequest: (request) => {
          record("request", { phase: "validation", ...request });
          dispatch({ type: "request", phase: "validation" });
        },
      });
      if (
        options.profile.authenticate &&
        state.findings.some((finding) =>
          finding.reproduction.some((request) => request.authenticated),
        )
      ) {
        await options.profile.authenticate(validationTarget);
      }

      dispatch({ type: "agent", id: "validator", status: "running" });
      const Validator = createValidatorAgent(
        state.findings,
        validationTarget,
        options.profile,
        dispatch,
      );
      {
        await using _validatorRuntime = await start({ agents: [Validator] });
        const validator = init(Validator);
        const receipt = await validator.dispatch("Validate every submitted campaign finding.");
        const reply = await validator.read(receipt, {
          onEvent: (chunk) => captureAgentEvent("validator", chunk),
        });
        dispatch({
          type: "agent",
          id: "validator",
          status: "finished",
          summary: reply.text.slice(0, 100),
        });
      }
    } else {
      dispatch({
        type: "agent",
        id: "validator",
        status: "finished",
        summary: "No findings required validation.",
      });
    }
    dispatch({ type: "phase", phase: "complete" });
  } catch (error) {
    dispatch({ type: "failed", error: error instanceof Error ? error.message : String(error) });
  }

  return {
    profileId: options.profile.id,
    model: GLM_FLASH_MODEL,
    durationMs: Math.round(performance.now() - startedAt),
    state,
    events,
  };
}
