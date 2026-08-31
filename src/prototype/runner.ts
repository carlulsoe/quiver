import { init, type ConversationStreamChunk, type PromptUsage } from "@flue/runtime";
import { start } from "@flue/runtime/node";
import { PersistentCoordinator } from "./adaptive-coordinator.ts";
import { createExplorerAgent, createValidatorAgent } from "./agents.ts";
import { CampaignLedger } from "./campaign-ledger.ts";
import { GLM_FLASH_MODEL } from "./models.ts";
import { RequestBudgetExceededError, ScopedTarget } from "./scoped-target.ts";
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
    });
    options.onState?.(state, action);
  };
  options.onState?.(state);

  try {
    const coordinator = new PersistentCoordinator({
      supportsAuthentication: options.profile.authenticate !== undefined,
      requestBudget: budget.exploration,
      expectedWorkers: explorerCount,
      onChange: (snapshot) => dispatch({ type: "coordinator-snapshot", snapshot }),
    });
    dispatch({ type: "coordinator-snapshot", snapshot: coordinator.snapshot() });
    const explorationTarget = new ScopedTarget({
      target: options.target,
      requestBudget: budget.exploration,
      allowedRequests: options.profile.allowedRequests,
      deniedRequests: options.profile.deniedRequests,
      onRequest: (request) => {
        coordinator.observeBudgetUse();
        record("request", { phase: "exploration", ...request });
        dispatch({ type: "request", phase: "exploration" });
      },
      openApi: options.openApi,
    });
    let enqueueValidation = (_fingerprint: string) => {};
    const ledger = new CampaignLedger({
      onTestedRequest: (request) => {
        coordinator.observeRequest(request);
        dispatch({ type: "request-tested", request });
      },
      onFinding: (finding) => {
        const fingerprint = coordinator.observeFinding(finding);
        dispatch({ type: "finding", finding });
        enqueueValidation(fingerprint);
      },
    });
    if (options.profile.authenticate) await options.profile.authenticate(explorationTarget);
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
        dispatch,
        options.context,
      ),
    );
    const specialistLimit = Math.min(2, explorerCount);
    const specialistDefinitions = Array.from({ length: specialistLimit }, (_, index) => {
      const id = `specialist-${index + 1}`;
      return createExplorerAgent(
        id,
        () => coordinator.focusFor(id) ?? "high-confidence hypotheses retained by the coordinator",
        explorationTarget,
        options.profile,
        ledger,
        coordinator,
        dispatch,
        options.context,
      );
    });
    const validationTarget = new ScopedTarget({
      target: options.target,
      requestBudget: budget.validation,
      allowedRequests: options.profile.allowedRequests,
      deniedRequests: options.profile.deniedRequests,
      onRequest: (request) => {
        record("request", { phase: "validation", ...request });
        dispatch({ type: "request", phase: "validation" });
      },
    });
    const Validator = createValidatorAgent(
      () => state.findings,
      () => validationTarget,
      options.profile,
      (action, mission) => {
        if (action.type === "validation") {
          coordinator.recordValidation(
            action.validation.fingerprint,
            action.validation.status,
            mission.validatorId,
          );
        }
        dispatch(action);
      },
      "validator",
    );
    let validationAuthentication: Promise<unknown> | undefined;
    let validationMissionIndex = 0;
    let validationChain = Promise.resolve();
    const validateFinding = async (fingerprint: string) => {
      if (state.validations.some((validation) => validation.fingerprint === fingerprint)) {
        return;
      }
      const finding = state.findings.find((item) => item.fingerprint === fingerprint);
      if (!finding) return;
      validationTarget.allowRequests(
        finding.reproduction.map(({ method = "GET", path }) => ({ method, path })),
      );
      if (
        options.profile.authenticate &&
        finding.reproduction.some((request) => request.authenticated)
      ) {
        validationAuthentication ??= options.profile.authenticate(validationTarget);
        await validationAuthentication;
      }
      if (
        validationTarget.requestBudget - validationTarget.requestsUsed <
        finding.reproduction.length
      ) {
        return;
      }
      const validatorId =
        validationMissionIndex === 0 ? "validator" : `validator-${validationMissionIndex + 1}`;
      validationMissionIndex += 1;
      if (!coordinator.claimValidation(validatorId, fingerprint)) return;
      if (validatorId !== "validator") {
        dispatch({ type: "agent-spawned", id: validatorId, role: "validator" });
      }
      dispatch({ type: "agent", id: validatorId, status: "running" });
      try {
        const validator = init(Validator, { id: `mission-${validationMissionIndex}` });
        const receipt = await validator.dispatch({
          message: `Validate only finding ${fingerprint}, submit its outcome, then finish validation.`,
          initialData: { fingerprint, validatorId },
        });
        const reply = await validator.read(receipt, {
          onEvent: (chunk) => captureAgentEvent(validatorId, chunk),
        });
        captureUsage(reply.metadata);
        const completed = state.validations.some(
          (validation) => validation.fingerprint === fingerprint,
        );
        if (!completed) coordinator.releaseValidation(fingerprint);
        dispatch({
          type: "agent",
          id: validatorId,
          status: "finished",
          summary: completed ? reply.text.slice(0, 100) : "Replay produced no submitted outcome.",
        });
      } catch (error) {
        coordinator.releaseValidation(fingerprint);
        const budgetExhausted =
          error instanceof RequestBudgetExceededError ||
          String(error).includes("Request budget exhausted");
        dispatch({
          type: "agent",
          id: validatorId,
          status: budgetExhausted ? "finished" : "failed",
          summary: budgetExhausted
            ? "Deferred until validation budget is reclaimed."
            : String(error),
        });
      }
    };
    enqueueValidation = (fingerprint) => {
      validationChain = validationChain.then(() => validateFinding(fingerprint));
    };

    await using _campaignRuntime = await start({
      agents: [...explorers, ...specialistDefinitions, Validator],
    });
    const runWorker = async (
      Explorer: (typeof explorers)[number],
      id: string,
      instruction: string,
    ) => {
      dispatch({ type: "agent", id, status: "running" });
      let summary = "Worker exited without a model summary.";
      try {
        const agent = init(Explorer);
        const receipt = await agent.dispatch(instruction);
        const reply = await agent.read(receipt, {
          onEvent: (chunk) => captureAgentEvent(id, chunk),
        });
        captureUsage(reply.metadata);
        summary = reply.text.slice(0, 100);
        dispatch({ type: "agent", id, status: "finished", summary });
      } catch (error) {
        summary = String(error);
        dispatch({ type: "agent", id, status: "failed", summary });
      } finally {
        if (!coordinator.snapshot().debriefs.some((debrief) => debrief.agentId === id)) {
          coordinator.debrief(id, { summary, exhausted: true });
        }
        coordinator.release(id);
      }
    };
    await Promise.all(
      explorers.map((Explorer, index) =>
        runWorker(Explorer, `explorer-${index + 1}`, "Begin the bounded REST security campaign."),
      ),
    );

    const specialistPlans = coordinator.planSpecialists(specialistLimit);
    await Promise.all(
      specialistPlans.map((plan, index) => {
        dispatch({ type: "agent-spawned", id: plan.agentId, role: "specialist" });
        return runWorker(
          specialistDefinitions[index]!,
          plan.agentId,
          `Investigate the coordinator's assigned ${plan.specialty} hypotheses with a fresh perspective.`,
        );
      }),
    );

    await validationChain;
    dispatch({ type: "reclaim-exploration-budget" });
    dispatch({ type: "phase", phase: "validating" });
    validationTarget.extendRequestBudget(state.budget.validation - validationTarget.requestBudget);
    for (const item of coordinator.snapshot().validationQueue) {
      if (item.status === "queued") enqueueValidation(item.fingerprint);
    }
    await validationChain;
    if (state.findings.length === 0) {
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
