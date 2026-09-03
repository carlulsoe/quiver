import { createValidatorAgent } from "./agents.ts";
import { validationRequirements } from "./model-routing.ts";
import { RoutedMission } from "./mission-runtime.ts";
import { isRequestBudgetExhausted } from "./runner-errors.ts";
import { CampaignHaltedError } from "./runtime-safety.ts";
import { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import { runExploitChainJobs } from "./validation-executor-chains.ts";
import { executeValidationFinding } from "./validation-executor-finding.ts";
import type { ValidationExecutorOptions } from "./validation-executor-types.ts";

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
          request.context !== "authentication" &&
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
      await this.target.runProfileSetup("authentication", () =>
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

  runExploitChains(): Promise<void> {
    return runExploitChainJobs(this.#options, this.target, (jobId) => {
      this.#activeJobId = jobId;
    });
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

  private validateFinding(fingerprint: string, finalAttempt: boolean): Promise<void> {
    return executeValidationFinding(
      {
        options: this.#options,
        cursor: this.#cursor,
        agentDefinition: this.agentDefinition,
        missionIndex: this.#missionIndex,
        advanceMissionIndex: () => {
          this.#missionIndex += 1;
        },
        setActiveJobId: (jobId) => {
          this.#activeJobId = jobId;
        },
      },
      fingerprint,
      finalAttempt,
    );
  }
}
