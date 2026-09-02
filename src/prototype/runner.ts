import { init, type ConversationStreamChunk, type PromptUsage } from "@flue/runtime";
import { start } from "@flue/runtime/node";
import { PersistentCoordinator } from "./adaptive-coordinator.ts";
import { createExplorerAgent, createValidatorAgent } from "./agents.ts";
import { CampaignLedger } from "./campaign-ledger.ts";
import { InMemoryCampaignStore, type CampaignStore } from "./campaign-store.ts";
import { ChainBudgetExceededError, replayExploitChain } from "./exploit-chain.ts";
import {
  createModelRouter,
  estimateTokens,
  routeTriageRequirements,
  shouldFallbackModel,
  specialistRequirements,
  validationRequirements,
  type MissionRequirements,
  type ModelRoute,
  type ModelRouter,
} from "./model-routing.ts";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { RequestBudgetExceededError, ScopedTarget } from "./scoped-target.ts";
import {
  createCampaignBudget,
  createCampaignState,
  type CampaignAction,
  type CampaignState,
} from "./state.ts";
import { assertValidTargetProfile, type TargetProfile } from "./target-profile.ts";
import { actorIds } from "./sessions.ts";
import { createBoundedToolAdapters } from "./tool-adapters.ts";
import { DefaultVerificationEngine, ReplayBudgetExceededError } from "./verification.ts";

export interface RunCampaignOptions {
  target: URL;
  profile: TargetProfile;
  requestBudget?: number;
  explorerCount?: number;
  onState?: (state: CampaignState, action?: CampaignAction) => void;
  openApi?: unknown;
  context?: string;
  campaignId?: string;
  campaignStore?: CampaignStore;
  modelRouter?: ModelRouter;
}

export interface MissionUsage {
  missionId: string;
  role: "explorer" | "specialist" | "validator";
  requirements: MissionRequirements;
  attemptedModels: string[];
  model?: string;
  usage: PromptUsage;
}

export interface CampaignRun {
  profileId: string;
  reproductionAuthentication?: TargetProfile["reproductionAuthentication"];
  model: string;
  durationMs: number;
  usage: PromptUsage;
  missionUsage: MissionUsage[];
  state: CampaignState;
  events: RunEvent[];
}

export interface RunEvent {
  sequence: number;
  elapsedMs: number;
  type: "state" | "request" | "model-route" | "tool-call" | "tool-output" | "tool-error";
  data: Record<string, unknown>;
}

export async function runCampaign(options: RunCampaignOptions): Promise<CampaignRun> {
  assertValidTargetProfile(options.profile);
  await using artifacts = new ProofArtifactStore();
  const verification = new DefaultVerificationEngine(options.profile, artifacts);
  const startedAt = performance.now();
  const explorerCount = options.explorerCount ?? 2;
  const events: RunEvent[] = [];
  const usage = emptyUsage();
  const missionUsage: MissionUsage[] = [];
  const modelRouter = options.modelRouter ?? createModelRouter();
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
  const captureUsage = (metadata: Record<string, unknown> | undefined, mission: MissionUsage) => {
    const value = metadata?.quiverUsage;
    if (!isPromptUsage(value)) return;
    addUsage(usage, value);
    addUsage(mission.usage, value);
    if (typeof metadata?.quiverModel === "string") mission.model = metadata.quiverModel;
  };
  const campaignId = options.campaignId ?? options.profile.id;
  const campaignStore =
    options.campaignStore ??
    new InMemoryCampaignStore([
      [
        campaignId,
        createCampaignState(
          `${options.target.origin}${options.target.pathname}${options.target.search}`,
          createCampaignBudget(options.requestBudget ?? 30),
          explorerCount,
        ),
      ],
    ]);
  let state = campaignStore.load(campaignId);
  assertFreshCampaign(state, campaignId, options.target);
  const budget = state.budget;
  const dispatch = (action: CampaignAction) => {
    campaignStore.apply(action);
    state = campaignStore.checkpoint();
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
    const coordinator = new PersistentCoordinator({
      actorIds: [actorIds.anonymous, ...(options.profile.actorIds ?? [])],
      requestBudget: budget.exploration,
      expectedWorkers: explorerCount,
      onChange: (snapshot) => dispatch({ type: "coordinator-snapshot", snapshot }),
    });
    dispatch({ type: "coordinator-snapshot", snapshot: coordinator.snapshot() });
    const explorationTarget = new ScopedTarget({
      target: options.target,
      requestBudget: budget.exploration,
      allowedRequests: options.profile.allowedRequests,
      setupRequests: options.profile.setupRequests,
      deniedRequests: options.profile.deniedRequests,
      onRequest: (request) => {
        coordinator.observeBudgetUse();
        record("request", { phase: "exploration", ...request });
        dispatch({ type: "request", phase: "exploration" });
      },
      openApi: options.openApi,
      attackSurfaceOrigins: options.profile.attackSurfaceOrigins,
      maximumImpactLevel: options.profile.maximumImpactLevel ?? "observation",
    });
    const boundedAdapters = createBoundedToolAdapters({
      target: explorationTarget,
      profile: options.profile,
      artifacts,
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
    const contextTokens = estimateTokens({
      context: options.context,
      openApi: options.openApi,
      manifest: options.profile.manifest,
    });
    const triageRoute = () => modelRouter.route(routeTriageRequirements(contextTokens));
    const explorers = Array.from({ length: explorerCount }, (_, index) => {
      const id = `explorer-${index + 1}`;
      const cursor = createRouteCursor(triageRoute());
      return {
        id,
        cursor,
        definition: createExplorerAgent(
          id,
          focuses[index] ?? "the remaining REST attack surface not covered by other explorers",
          explorationTarget,
          options.profile,
          ledger,
          coordinator,
          artifacts,
          boundedAdapters,
          verification,
          dispatch,
          () => currentModel(cursor),
          options.context,
        ),
      };
    });
    const specialistLimit = Math.min(2, explorerCount);
    const specialistDefinitions = Array.from({ length: specialistLimit }, (_, index) => {
      const id = `specialist-${index + 1}`;
      const cursor = createRouteCursor(triageRoute());
      return {
        id,
        cursor,
        definition: createExplorerAgent(
          id,
          () =>
            coordinator.focusFor(id) ?? "high-confidence hypotheses retained by the coordinator",
          explorationTarget,
          options.profile,
          ledger,
          coordinator,
          artifacts,
          boundedAdapters,
          verification,
          dispatch,
          () => currentModel(cursor),
          options.context,
        ),
      };
    });
    const validationTarget = new ScopedTarget({
      target: options.target,
      requestBudget: budget.validation,
      allowedRequests: options.profile.allowedRequests,
      setupRequests: options.profile.setupRequests,
      deniedRequests: options.profile.deniedRequests,
      onRequest: (request) => {
        record("request", { phase: "validation", ...request });
        dispatch({ type: "request", phase: "validation" });
      },
      maximumImpactLevel: options.profile.maximumImpactLevel ?? "observation",
      attackSurfaceOrigins: options.profile.attackSurfaceOrigins,
    });
    const validatorCursor = createRouteCursor(modelRouter.route(validationRequirements(0)));
    const Validator = createValidatorAgent(
      () => state.findings,
      () => validationTarget,
      options.profile,
      verification,
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
      () => currentModel(validatorCursor),
      "validator",
    );
    let validationMissionIndex = 0;
    let validationChain = Promise.resolve();
    const validateFinding = async (fingerprint: string) => {
      if (state.validations.some((validation) => validation.fingerprint === fingerprint)) {
        return;
      }
      const finding = state.findings.find((item) => item.fingerprint === fingerprint);
      if (!finding) return;
      const validatorId =
        validationMissionIndex === 0 ? "validator" : `validator-${validationMissionIndex + 1}`;
      validationMissionIndex += 1;
      if (!coordinator.claimValidation(validatorId, fingerprint)) return;
      resetRoute(
        validatorCursor,
        modelRouter.route(validationRequirements(estimateTokens(finding))),
      );
      const mission = beginMissionUsage(
        missionUsage,
        validatorId,
        "validator",
        validatorCursor.route,
      );
      if (validatorId !== "validator") {
        dispatch({ type: "agent-spawned", id: validatorId, role: "validator" });
      }
      dispatch({ type: "agent", id: validatorId, status: "running" });
      try {
        let replyText = "";
        while (true) {
          let toolInvoked = false;
          recordModelAttempt(record, mission, currentModel(validatorCursor));
          try {
            const validator = init(Validator, {
              id: `mission-${validationMissionIndex}-attempt-${validatorCursor.index + 1}`,
            });
            const receipt = await validator.dispatch({
              message: `Validate only finding ${fingerprint}, submit its outcome, then finish validation.`,
              initialData: { fingerprint, validatorId },
            });
            const reply = await validator.read(receipt, {
              onEvent: (chunk) => {
                if (chunk.type === "tool-input") toolInvoked = true;
                captureAgentEvent(validatorId, chunk);
              },
            });
            captureUsage(reply.metadata, mission);
            replyText = reply.text;
            break;
          } catch (error) {
            if (!advanceFallback(validatorCursor, error, toolInvoked)) throw error;
          }
        }
        const completed = state.validations.some(
          (validation) => validation.fingerprint === fingerprint,
        );
        if (!completed) coordinator.releaseValidation(fingerprint);
        dispatch({
          type: "agent",
          id: validatorId,
          status: "finished",
          summary: completed ? replyText.slice(0, 100) : "Replay produced no submitted outcome.",
        });
      } catch (error) {
        coordinator.releaseValidation(fingerprint);
        const budgetExhausted = isRequestBudgetExhausted(error);
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
      agents: [
        ...explorers.map(({ definition }) => definition),
        ...specialistDefinitions.map(({ definition }) => definition),
        Validator,
      ],
    });
    const runWorker = async (
      worker: (typeof explorers)[number],
      role: "explorer" | "specialist",
      instruction: string,
    ) => {
      const { definition: Explorer, id, cursor } = worker;
      const mission = beginMissionUsage(missionUsage, id, role, cursor.route);
      dispatch({ type: "agent", id, status: "running" });
      let summary = "Worker exited without a model summary.";
      try {
        while (true) {
          let toolInvoked = false;
          recordModelAttempt(record, mission, currentModel(cursor));
          try {
            const agent = init(Explorer, { id: `${id}-attempt-${cursor.index + 1}` });
            const receipt = await agent.dispatch(instruction);
            const reply = await agent.read(receipt, {
              onEvent: (chunk) => {
                if (chunk.type === "tool-input") toolInvoked = true;
                captureAgentEvent(id, chunk);
              },
            });
            captureUsage(reply.metadata, mission);
            summary = reply.text.slice(0, 100);
            break;
          } catch (error) {
            if (!advanceFallback(cursor, error, toolInvoked)) throw error;
          }
        }
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
      explorers.map((worker) =>
        runWorker(worker, "explorer", "Begin the bounded REST security campaign."),
      ),
    );

    const specialistPlans = coordinator.planSpecialists(specialistLimit);
    await Promise.all(
      specialistPlans.map((plan, index) => {
        dispatch({ type: "agent-spawned", id: plan.agentId, role: "specialist" });
        const worker = specialistDefinitions[index]!;
        resetRoute(
          worker.cursor,
          modelRouter.route(
            specialistRequirements({
              specialty: plan.specialty,
              contextTokens,
              browserBacked: isBrowserBacked(options.profile),
            }),
          ),
        );
        return runWorker(
          worker,
          "specialist",
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
    for (const chain of state.exploitChains) {
      try {
        dispatch({
          type: "exploit-chain-validation",
          validation: await replayExploitChain(
            validationTarget,
            chain,
            state.findings,
            options.profile,
            verification,
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
    model: missionUsage[0]?.model ?? missionUsage[0]?.attemptedModels[0] ?? "unrouted",
    durationMs: Math.round(performance.now() - startedAt),
    usage,
    missionUsage,
    state,
    events,
  };
}

interface RouteCursor {
  route: ModelRoute;
  index: number;
}

function createRouteCursor(route: ModelRoute): RouteCursor {
  return { route, index: 0 };
}

function resetRoute(cursor: RouteCursor, route: ModelRoute): void {
  cursor.route = route;
  cursor.index = 0;
}

function currentModel(cursor: RouteCursor) {
  const model = cursor.route.candidates[cursor.index];
  if (!model) throw new Error("Model route has no current candidate");
  return model;
}

function advanceFallback(cursor: RouteCursor, error: unknown, toolInvoked: boolean): boolean {
  if (!shouldFallbackModel(error, toolInvoked)) return false;
  if (cursor.index + 1 >= cursor.route.candidates.length) return false;
  cursor.index += 1;
  return true;
}

function beginMissionUsage(
  accounts: MissionUsage[],
  missionId: string,
  role: MissionUsage["role"],
  route: ModelRoute,
): MissionUsage {
  const account: MissionUsage = {
    missionId,
    role,
    requirements: {
      ...route.requirements,
      capabilities: [...route.requirements.capabilities],
    },
    attemptedModels: [],
    usage: emptyUsage(),
  };
  accounts.push(account);
  return account;
}

function recordModelAttempt(
  record: (type: RunEvent["type"], data: Record<string, unknown>) => void,
  mission: MissionUsage,
  model: ModelRoute["candidates"][number],
): void {
  mission.attemptedModels.push(model.model);
  record("model-route", {
    missionId: mission.missionId,
    role: mission.role,
    model: model.model,
    attempt: mission.attemptedModels.length,
    requirements: mission.requirements,
  });
}

function isBrowserBacked(profile: TargetProfile): boolean {
  return (
    profile.proofPolicies?.some(({ kind }) => kind === "browser-effect") === true ||
    profile.manifest?.identities.some(
      ({ authentication }) => authentication?.kind === "browser-login",
    ) === true
  );
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

function addUsage(total: PromptUsage, value: PromptUsage): void {
  total.input += value.input;
  total.output += value.output;
  total.cacheRead += value.cacheRead;
  total.cacheWrite += value.cacheWrite;
  total.totalTokens += value.totalTokens;
  total.cost.input += value.cost.input;
  total.cost.output += value.cost.output;
  total.cost.cacheRead += value.cost.cacheRead;
  total.cost.cacheWrite += value.cost.cacheWrite;
  total.cost.total += value.cost.total;
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

function isRequestBudgetExhausted(error: unknown): boolean {
  return (
    error instanceof RequestBudgetExceededError ||
    error instanceof ReplayBudgetExceededError ||
    String(error).includes("Request budget exhausted")
  );
}

function assertFreshCampaign(state: CampaignState, campaignId: string, target: URL): void {
  const expectedTarget = `${target.origin}${target.pathname}${target.search}`;
  const hasPriorWork =
    state.requests.total !== 0 ||
    state.requests.exploration !== 0 ||
    state.requests.validation !== 0 ||
    state.testedRequests.length !== 0 ||
    state.findings.length !== 0 ||
    state.validations.length !== 0 ||
    state.exploitChains.length !== 0 ||
    state.exploitChainValidations.length !== 0 ||
    state.agents.some(({ status }) => status !== "queued");
  if (state.phase !== "starting" || hasPriorWork) {
    throw new Error(
      `Campaign ${campaignId} is not a fresh starting checkpoint; campaign resume is not supported`,
    );
  }
  if (state.target !== expectedTarget) {
    throw new Error(`Campaign ${campaignId} targets ${state.target}, not ${expectedTarget}`);
  }
}
