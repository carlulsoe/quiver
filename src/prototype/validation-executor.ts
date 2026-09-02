import { init } from "@flue/runtime";
import type { PersistentCoordinator } from "./adaptive-coordinator.ts";
import { createValidatorAgent } from "./agents.ts";
import type { CampaignSession } from "./campaign-session.ts";
import { ChainBudgetExceededError, replayExploitChain } from "./exploit-chain.ts";
import { estimateTokens, validationRequirements, type ModelRouter } from "./model-routing.ts";
import { RoutedMission } from "./mission-runtime.ts";
import { isRequestBudgetExhausted, isRuntimeStopError } from "./runner-errors.ts";
import { CampaignHaltedError, type RuntimeSafetyController } from "./runtime-safety.ts";
import { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import { exploitChainJobId, validationJobId } from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";
import type { VerificationEngine } from "./verification.ts";

interface ValidationExecutorOptions {
  target: URL;
  profile: TargetProfile;
  session: CampaignSession;
  coordinator: PersistentCoordinator;
  modelRouter: ModelRouter;
  verification: VerificationEngine;
  runtimeSafety: RuntimeSafetyController;
}

/** Owns durable proof jobs, including mutation boundaries and serialized validation. */
export class ValidationExecutor {
  readonly target: ScopedTarget;
  readonly agentDefinition: ReturnType<typeof createValidatorAgent>;
  #options: ValidationExecutorOptions;
  #cursor: RoutedMission;
  #activeJobId: string | undefined;
  #missionIndex = 0;
  #chain = Promise.resolve();

  constructor(options: ValidationExecutorOptions) {
    this.#options = options;
    const { session, profile, coordinator } = options;
    this.target = new ScopedTarget({
      target: options.target,
      requestBudget: Math.max(
        0,
        session.state.budget.validation - session.state.requests.validation,
      ),
      allowedRequests: profile.allowedRequests,
      setupRequests: profile.setupRequests,
      deniedRequests: profile.deniedRequests,
      onRequest: (request) => {
        if (
          this.#activeJobId &&
          !request.setup &&
          !["GET", "HEAD", "OPTIONS"].includes(request.method.toUpperCase()) &&
          !session.state.runtime.jobs.find(({ id }) => id === this.#activeJobId)?.mutationStarted
        ) {
          session.dispatch({ type: "job-mutation-started", id: this.#activeJobId });
        }
        session.record("request", { phase: "validation", ...request });
        session.dispatch({ type: "request", phase: "validation" });
      },
      maximumImpactLevel: profile.maximumImpactLevel ?? "observation",
      attackSurfaceOrigins: profile.attackSurfaceOrigins,
      runtimeSafety: options.runtimeSafety,
    });
    this.#cursor = new RoutedMission(options.modelRouter.route(validationRequirements(0)));
    this.agentDefinition = createValidatorAgent(
      () => session.state.findings,
      () => this.target,
      profile,
      options.verification,
      (action, mission) => {
        if (action.type === "validation") {
          coordinator.recordValidation(
            action.validation.fingerprint,
            action.validation.status,
            mission.validatorId,
          );
        }
        session.dispatch(action);
      },
      () => this.#cursor.model,
      "validator",
    );
  }

  enqueue(fingerprint: string, finalAttempt = false): void {
    this.#chain = this.#chain.then(() => this.validateFinding(fingerprint, finalAttempt));
  }

  drain(): Promise<void> {
    return this.#chain;
  }

  async restoreAuthentication(resumedPhase: string): Promise<void> {
    const { profile, session } = this.#options;
    if (resumedPhase !== "validating" || !profile.authenticate) return;
    const pendingFingerprints = new Set(
      session.state.runtime.jobs.flatMap((job) => {
        if (job.status !== "queued") return [];
        if (job.kind === "validation") return [job.fingerprint];
        const chain = session.state.exploitChains.find(
          ({ fingerprint }) => fingerprint === job.fingerprint,
        );
        return chain?.links.flatMap(({ from, to }) => [from.fingerprint, to.fingerprint]) ?? [];
      }),
    );
    const actorIdsToRestore = [
      ...new Set(
        session.state.findings
          .filter(({ fingerprint }) => pendingFingerprints.has(fingerprint))
          .flatMap((finding) => [
            ...finding.reproduction.map(({ actorId }) => actorId),
            ...(finding.proof.type === "browser-visible-effect" ? [finding.proof.pageActorId] : []),
          ])
          .filter((id) => id !== actorIds.anonymous),
      ),
    ];
    if (actorIdsToRestore.length === 0) return;
    try {
      await this.target.runProfileSetup(() =>
        profile.authenticate!(this.target, actorIdsToRestore),
      );
    } catch (error) {
      if (isRequestBudgetExhausted(error)) {
        const reason = "Remaining budget cannot restore validation authentication";
        session.dispatch({ type: "halt", reason });
        throw new CampaignHaltedError(reason);
      }
      throw error;
    }
  }

  reclaimExplorationBudget(): void {
    const { session } = this.#options;
    session.dispatch({ type: "reclaim-exploration-budget" });
    session.dispatch({ type: "phase", phase: "validating" });
    this.target.extendRequestBudget(
      session.state.budget.validation -
        session.state.requests.validation -
        this.target.requestBudget,
    );
  }

  async runPendingFindings(): Promise<void> {
    const { session } = this.#options;
    for (const job of session.state.runtime.jobs) {
      if (job.kind === "validation" && job.status === "queued") {
        this.enqueue(job.fingerprint, true);
      }
    }
    await this.drain();
    if (session.state.findings.length === 0) {
      session.dispatch({
        type: "agent",
        id: "validator",
        status: "finished",
        summary: "No findings required validation.",
      });
    }
  }

  async runExploitChains(): Promise<void> {
    const { session, profile, verification } = this.#options;
    for (const chain of session.state.exploitChains) {
      const jobId = exploitChainJobId(chain.fingerprint);
      if (session.state.runtime.jobs.find(({ id }) => id === jobId)?.status !== "queued") continue;
      session.dispatch({ type: "job-started", id: jobId });
      this.#activeJobId = jobId;
      try {
        session.dispatch({
          type: "exploit-chain-validation",
          validation: await replayExploitChain(
            this.target,
            chain,
            session.state.findings,
            profile,
            verification,
          ),
        });
      } catch (error) {
        const mutationStarted =
          session.state.runtime.jobs.find(({ id }) => id === jobId)?.mutationStarted === true;
        if (
          error instanceof ChainBudgetExceededError ||
          isRuntimeStopError(error) ||
          mutationStarted
        ) {
          session.dispatch({
            type: "job-failed",
            id: jobId,
            error: error instanceof Error ? error.message : String(error),
            retryable: isRuntimeStopError(error),
          });
          if (isRuntimeStopError(error)) throw error;
          continue;
        }
        session.dispatch({
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
      } finally {
        if (this.#activeJobId === jobId) this.#activeJobId = undefined;
      }
    }
  }

  assertAllJobsFinished(): void {
    const unfinished = this.#options.session.state.runtime.jobs.filter(({ status }) =>
      ["queued", "running"].includes(status),
    );
    if (unfinished.length === 0) return;
    const reason = `Campaign has ${unfinished.length} unfinished durable proof jobs`;
    this.#options.session.dispatch({ type: "halt", reason });
    throw new CampaignHaltedError(reason);
  }

  private async validateFinding(fingerprint: string, finalAttempt: boolean): Promise<void> {
    const { session, coordinator, modelRouter } = this.#options;
    if (session.state.validations.some((item) => item.fingerprint === fingerprint)) return;
    const finding = session.state.findings.find((item) => item.fingerprint === fingerprint);
    if (!finding) return;
    const jobId = validationJobId(fingerprint);
    if (session.state.runtime.jobs.find(({ id }) => id === jobId)?.status !== "queued") return;
    const validatorId =
      this.#missionIndex === 0 ? "validator" : `validator-${this.#missionIndex + 1}`;
    this.#missionIndex += 1;
    if (!coordinator.claimValidation(validatorId, fingerprint)) return;
    this.#cursor.reset(modelRouter.route(validationRequirements(estimateTokens(finding))));
    const mission = session.beginMission(validatorId, "validator", this.#cursor.route);
    session.dispatch({ type: "job-started", id: jobId });
    this.#activeJobId = jobId;
    if (validatorId !== "validator") {
      session.dispatch({ type: "agent-spawned", id: validatorId, role: "validator" });
    }
    session.dispatch({ type: "agent", id: validatorId, status: "running" });
    try {
      let replyText = "";
      await this.#cursor.run(
        async (_model, markToolInvoked) => {
          const validator = init(this.agentDefinition, {
            id: `mission-${this.#missionIndex}-attempt-${mission.attemptedModels.length}`,
          });
          const receipt = await validator.dispatch({
            message: `Validate only finding ${fingerprint}, submit its outcome, then finish validation.`,
            initialData: { fingerprint, validatorId },
          });
          const reply = await validator.read(receipt, {
            onEvent: (chunk) => {
              if (chunk.type === "tool-input") markToolInvoked();
              session.captureAgentEvent(validatorId, chunk);
            },
          });
          session.captureUsage(reply.metadata, mission);
          replyText = reply.text;
        },
        (model) => session.recordModelAttempt(mission, model),
      );
      const completed = session.state.validations.some(
        (validation) => validation.fingerprint === fingerprint,
      );
      if (!completed) {
        coordinator.releaseValidation(fingerprint);
        session.dispatch({
          type: "job-failed",
          id: jobId,
          error: "Replay produced no submitted outcome",
          retryable: !finalAttempt,
        });
      }
      session.dispatch({
        type: "agent",
        id: validatorId,
        status: "finished",
        summary: completed ? replyText.slice(0, 100) : "Replay produced no submitted outcome.",
      });
    } catch (error) {
      coordinator.releaseValidation(fingerprint);
      const budgetExhausted = isRequestBudgetExhausted(error);
      session.dispatch({
        type: "job-failed",
        id: jobId,
        error: error instanceof Error ? error.message : String(error),
        retryable: isRuntimeStopError(error) || (!finalAttempt && budgetExhausted),
      });
      session.dispatch({
        type: "agent",
        id: validatorId,
        status: budgetExhausted ? "finished" : "failed",
        summary: budgetExhausted ? "Deferred until validation budget is reclaimed." : String(error),
      });
      if (isRuntimeStopError(error)) throw error;
    } finally {
      if (this.#activeJobId === jobId) this.#activeJobId = undefined;
    }
  }
}
