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
  exploitChainJobId,
  type CampaignAction,
  type CampaignState,
  validationJobId,
} from "./state.ts";
import { assertValidTargetProfile, type TargetProfile } from "./target-profile.ts";
import { actorIds } from "./sessions.ts";
import { createBoundedToolAdapters } from "./tool-adapters.ts";
import { DefaultVerificationEngine, ReplayBudgetExceededError } from "./verification.ts";
import {
  CampaignCancelledError,
  CampaignHaltedError,
  CampaignPausedError,
  OutsideTestingWindowError,
  RuntimeSafetyController,
} from "./runtime-safety.ts";

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
  let state: CampaignState;
  try {
    state = campaignStore.load(campaignId);
  } catch (error) {
    if (!(error instanceof Error) || error.message !== `Unknown campaign ${campaignId}`) {
      throw error;
    }
    state = campaignStore.create(
      campaignId,
      createCampaignState(
        `${options.target.origin}${options.target.pathname}${options.target.search}`,
        createCampaignBudget(options.requestBudget ?? 30),
        explorerCount,
      ),
    );
  }
  assertCampaignTarget(state, campaignId, options.target);
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
  dispatch({ type: "recover" });
  if (state.phase !== "complete" && state.phase !== "failed") {
    while (state.requests.exploration < state.coordination.budget.consumed) {
      dispatch({ type: "request", phase: "exploration" });
    }
  }
  options.onState?.(state);

  if (
    state.phase === "complete" ||
    state.phase === "failed" ||
    state.runtime.control !== "running"
  ) {
    return campaignRun(options, startedAt, usage, missionUsage, state, events);
  }
  const resumedPhase = state.phase;

  const runtimeSafety = new RuntimeSafetyController(options.profile.runtimeSafety, {
    controlStatus: () => campaignStore.checkpoint().runtime.control,
    initialConsecutiveFailures: state.runtime.consecutiveFailures,
    initialDisruptiveResponses: state.runtime.disruptiveResponses,
    onSuccess: () => dispatch({ type: "runtime-success" }),
    onFailure: (disruptive) => dispatch({ type: "runtime-failure", disruptive }),
    onHalt: (reason) => dispatch({ type: "halt", reason }),
  });

  try {
    const coordinator = new PersistentCoordinator({
      actorIds: [actorIds.anonymous, ...(options.profile.actorIds ?? [])],
      requestBudget: budget.exploration,
      expectedWorkers: explorerCount,
      onChange: (snapshot) => dispatch({ type: "coordinator-snapshot", snapshot }),
      restore: {
        snapshot: state.coordination,
        operations: state.discoveredOperations,
        testedRequests: state.testedRequests,
        findings: state.findings,
        validations: state.validations,
        explorationRequests: state.requests.exploration,
      },
    });
    for (const job of state.runtime.jobs) {
      if (job.kind === "validation" && job.status === "queued") {
        coordinator.releaseValidation(job.fingerprint);
      }
    }
    dispatch({ type: "coordinator-snapshot", snapshot: coordinator.snapshot() });
    for (const plan of coordinator.snapshot().specialists) {
      if (!state.agents.some(({ id }) => id === plan.agentId)) {
        dispatch({ type: "agent-spawned", id: plan.agentId, role: "specialist" });
      }
    }
    const explorationTarget = new ScopedTarget({
      target: options.target,
      requestBudget: Math.max(0, budget.exploration - state.requests.exploration),
      allowedRequests: options.profile.allowedRequests,
      setupRequests: options.profile.setupRequests,
      deniedRequests: options.profile.deniedRequests,
      onRequest: (request) => {
        record("request", { phase: "exploration", ...request });
        dispatch({ type: "request", phase: "exploration" });
        coordinator.observeBudgetUse();
      },
      openApi: options.openApi,
      attackSurfaceOrigins: options.profile.attackSurfaceOrigins,
      maximumImpactLevel: options.profile.maximumImpactLevel ?? "observation",
      runtimeSafety,
    });
    let enqueueValidation: (fingerprint: string, finalAttempt?: boolean) => void = () => {};
    const boundedAdapters = createBoundedToolAdapters({
      target: explorationTarget,
      profile: options.profile,
      artifacts,
    });
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
      requestBudget: Math.max(0, budget.validation - state.requests.validation),
      allowedRequests: options.profile.allowedRequests,
      setupRequests: options.profile.setupRequests,
      deniedRequests: options.profile.deniedRequests,
      onRequest: (request) => {
        record("request", { phase: "validation", ...request });
        dispatch({ type: "request", phase: "validation" });
      },
      maximumImpactLevel: options.profile.maximumImpactLevel ?? "observation",
      attackSurfaceOrigins: options.profile.attackSurfaceOrigins,
      runtimeSafety,
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
    const validateFinding = async (fingerprint: string, finalAttempt = false) => {
      if (state.validations.some((validation) => validation.fingerprint === fingerprint)) {
        return;
      }
      const finding = state.findings.find((item) => item.fingerprint === fingerprint);
      if (!finding) return;
      const jobId = validationJobId(fingerprint);
      if (state.runtime.jobs.find((job) => job.id === jobId)?.status !== "queued") return;
      const validatorId =
        validationMissionIndex === 0 ? "validator" : `validator-${validationMissionIndex + 1}`;
      validationMissionIndex += 1;
      const validationRoute = modelRouter.route(validationRequirements(estimateTokens(finding)));
      if (!coordinator.claimValidation(validatorId, fingerprint)) return;
      resetRoute(validatorCursor, validationRoute);
      const mission = beginMissionUsage(
        missionUsage,
        validatorId,
        "validator",
        validatorCursor.route,
      );
      dispatch({ type: "job-started", id: jobId });
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
        if (!completed) {
          coordinator.releaseValidation(fingerprint);
          dispatch({
            type: "job-failed",
            id: jobId,
            error: "Replay produced no submitted outcome",
            retryable: !finalAttempt,
          });
        }
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
          type: "job-failed",
          id: jobId,
          error: error instanceof Error ? error.message : String(error),
          retryable: isRuntimeStopError(error) || (!finalAttempt && budgetExhausted),
        });
        dispatch({
          type: "agent",
          id: validatorId,
          status: budgetExhausted ? "finished" : "failed",
          summary: budgetExhausted
            ? "Deferred until validation budget is reclaimed."
            : String(error),
        });
        if (isRuntimeStopError(error)) throw error;
      }
    };
    enqueueValidation = (fingerprint, finalAttempt = false) => {
      validationChain = validationChain.then(() => validateFinding(fingerprint, finalAttempt));
    };

    await using _campaignRuntime = await start({
      agents: [
        ...explorers.map(({ definition }) => definition),
        ...specialistDefinitions.map(({ definition }) => definition),
        Validator,
      ],
    });
    if (resumedPhase === "validating" && options.profile.authenticate) {
      const pendingFingerprints = new Set(
        state.runtime.jobs.flatMap((job) => {
          if (job.status !== "queued") return [];
          if (job.kind === "validation") return [job.fingerprint];
          const chain = state.exploitChains.find(
            ({ fingerprint }) => fingerprint === job.fingerprint,
          );
          return chain?.links.flatMap(({ from, to }) => [from.fingerprint, to.fingerprint]) ?? [];
        }),
      );
      const validationActorIds = [
        ...new Set(
          state.findings
            .filter(({ fingerprint }) => pendingFingerprints.has(fingerprint))
            .flatMap((finding) => [
              ...finding.reproduction.map(({ actorId }) => actorId),
              ...(finding.proof.type === "browser-visible-effect"
                ? [finding.proof.pageActorId]
                : []),
            ])
            .filter((id) => id !== actorIds.anonymous),
        ),
      ];
      if (validationActorIds.length > 0) {
        try {
          await validationTarget.runProfileSetup(() =>
            options.profile.authenticate!(validationTarget, validationActorIds),
          );
        } catch (error) {
          if (isRequestBudgetExhausted(error)) {
            const reason = "Remaining budget cannot restore validation authentication";
            dispatch({ type: "halt", reason });
            throw new CampaignHaltedError(reason);
          }
          throw error;
        }
      }
    }
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
        if (isRuntimeStopError(error)) {
          dispatch({ type: "agent", id, status: "queued", summary: String(error) });
          throw error;
        }
        summary = String(error);
        dispatch({ type: "agent", id, status: "failed", summary });
      } finally {
        if (!coordinator.snapshot().debriefs.some((debrief) => debrief.agentId === id)) {
          coordinator.debrief(id, { summary, exhausted: true });
        }
        coordinator.release(id);
      }
    };
    if (state.phase !== "validating") {
      if (options.profile.authenticate) {
        await explorationTarget.runProfileSetup(() =>
          options.profile.authenticate!(explorationTarget),
        );
      }
      dispatch({ type: "phase", phase: "exploring" });
      await Promise.all(
        explorers.flatMap((worker) => {
          const agent = state.agents.find((candidate) => candidate.id === worker.id);
          return agent?.status === "finished"
            ? []
            : [runWorker(worker, "explorer", "Resume the bounded REST security campaign.")];
        }),
      );

      if (!state.agents.some(({ role }) => role === "specialist")) {
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
      } else {
        const pendingSpecialists = state.agents.filter(
          ({ role, status }) => role === "specialist" && status !== "finished",
        );
        await Promise.all(
          pendingSpecialists.map((agent) => {
            const worker = specialistDefinition(agent.id, specialistDefinitions);
            const plan = coordinator
              .snapshot()
              .specialists.find(({ agentId }) => agentId === agent.id);
            if (!plan) throw new Error(`No persisted specialist plan exists for ${agent.id}`);
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
              "Resume the coordinator's assigned specialist investigation.",
            );
          }),
        );
      }

      await validationChain;
      dispatch({ type: "reclaim-exploration-budget" });
      dispatch({ type: "phase", phase: "validating" });
      validationTarget.extendRequestBudget(
        state.budget.validation - state.requests.validation - validationTarget.requestBudget,
      );
    }
    for (const job of state.runtime.jobs) {
      if (job.kind === "validation" && job.status === "queued") {
        enqueueValidation(job.fingerprint, true);
      }
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
      const jobId = exploitChainJobId(chain.fingerprint);
      if (state.runtime.jobs.find((job) => job.id === jobId)?.status !== "queued") continue;
      dispatch({ type: "job-started", id: jobId });
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
        if (error instanceof ChainBudgetExceededError || isRuntimeStopError(error)) {
          dispatch({
            type: "job-failed",
            id: jobId,
            error: error instanceof Error ? error.message : String(error),
            retryable: isRuntimeStopError(error),
          });
          if (isRuntimeStopError(error)) throw error;
          continue;
        }
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
    const unfinishedJobs = state.runtime.jobs.filter(({ status }) =>
      ["queued", "running"].includes(status),
    );
    if (unfinishedJobs.length > 0) {
      const reason = `Campaign has ${unfinishedJobs.length} unfinished durable proof jobs`;
      dispatch({ type: "halt", reason });
      throw new CampaignHaltedError(reason);
    }
    runtimeSafety.assertReady();
    dispatch({ type: "phase", phase: "complete" });
  } catch (error) {
    if (!isRuntimeStopError(error)) {
      dispatch({ type: "failed", error: error instanceof Error ? error.message : String(error) });
    }
  }

  return campaignRun(options, startedAt, usage, missionUsage, state, events);
}

function campaignRun(
  options: RunCampaignOptions,
  startedAt: number,
  usage: PromptUsage,
  missionUsage: MissionUsage[],
  state: CampaignState,
  events: RunEvent[],
): CampaignRun {
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

function assertCampaignTarget(state: CampaignState, campaignId: string, target: URL): void {
  const expectedTarget = `${target.origin}${target.pathname}${target.search}`;
  if (state.target !== expectedTarget) {
    throw new Error(`Campaign ${campaignId} targets ${state.target}, not ${expectedTarget}`);
  }
}

function isRuntimeStopError(error: unknown): boolean {
  return (
    error instanceof CampaignPausedError ||
    error instanceof CampaignCancelledError ||
    error instanceof CampaignHaltedError ||
    error instanceof OutsideTestingWindowError
  );
}

function specialistDefinition<T>(id: string, definitions: readonly T[]): T {
  const match = /^specialist-(\d+)$/.exec(id);
  const index = match ? Number(match[1]) - 1 : -1;
  const definition = definitions[index];
  if (!definition) throw new Error(`No persisted specialist definition exists for ${id}`);
  return definition;
}
