import { init, type ConversationStreamChunk, type PromptUsage } from "@flue/runtime";
import { start } from "@flue/runtime/node";
import { PersistentCoordinator } from "./adaptive-coordinator.ts";
import { createExplorerAgent, createValidatorAgent } from "./agents.ts";
import { CampaignLedger } from "./campaign-ledger.ts";
import { InMemoryCampaignStore, type CampaignStore } from "./campaign-store.ts";
import { ChainBudgetExceededError, replayExploitChain } from "./exploit-chain.ts";
import { GLM_FLASH_MODEL } from "./models.ts";
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
  const verification = new DefaultVerificationEngine(options.profile, artifacts);
  const startedAt = performance.now();
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
    return campaignRun(options, startedAt, usage, state, events);
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
    const explorers = Array.from({ length: explorerCount }, (_, index) =>
      createExplorerAgent(
        `explorer-${index + 1}`,
        focuses[index] ?? "the remaining REST attack surface not covered by other explorers",
        explorationTarget,
        options.profile,
        ledger,
        coordinator,
        artifacts,
        verification,
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
        artifacts,
        verification,
        dispatch,
        options.context,
      );
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
      if (!coordinator.claimValidation(validatorId, fingerprint)) return;
      dispatch({ type: "job-started", id: jobId });
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
          summary: completed ? reply.text.slice(0, 100) : "Replay produced no submitted outcome.",
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
      agents: [...explorers, ...specialistDefinitions, Validator],
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
        explorers.flatMap((Explorer, index) => {
          const id = `explorer-${index + 1}`;
          const agent = state.agents.find((candidate) => candidate.id === id);
          return agent?.status === "finished"
            ? []
            : [runWorker(Explorer, id, "Resume the bounded REST security campaign.")];
        }),
      );

      if (!state.agents.some(({ role }) => role === "specialist")) {
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
      } else {
        const pendingSpecialists = state.agents.filter(
          ({ role, status }) => role === "specialist" && status !== "finished",
        );
        await Promise.all(
          pendingSpecialists.map((agent) =>
            runWorker(
              specialistDefinition(agent.id, specialistDefinitions),
              agent.id,
              "Resume the coordinator's assigned specialist investigation.",
            ),
          ),
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

  return campaignRun(options, startedAt, usage, state, events);
}

function campaignRun(
  options: RunCampaignOptions,
  startedAt: number,
  usage: PromptUsage,
  state: CampaignState,
  events: RunEvent[],
): CampaignRun {
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
