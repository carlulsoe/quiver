import { init } from "@flue/runtime";
import { PersistentCoordinator } from "./adaptive-coordinator.ts";
import { createExplorerAgent } from "./agents.ts";
import { CampaignLedger } from "./campaign-ledger.ts";
import type { CampaignSession } from "./campaign-session.ts";
import {
  estimateTokens,
  routeTriageRequirements,
  specialistRequirements,
  type ModelRouter,
} from "./model-routing.ts";
import { RoutedMission } from "./mission-runtime.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import { isRuntimeStopError } from "./runner-errors.ts";
import type { RuntimeSafetyController } from "./runtime-safety.ts";
import { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import type { TargetProfile } from "./target-profile.ts";
import { createBoundedToolAdapters } from "./tool-adapters.ts";
import type { VerificationEngine } from "./verification.ts";

interface ExplorationExecutorOptions {
  target: URL;
  profile: TargetProfile;
  explorerCount: number;
  openApi?: unknown;
  context?: string;
  session: CampaignSession;
  modelRouter: ModelRouter;
  artifacts: ProofArtifactStore;
  verification: VerificationEngine;
  runtimeSafety: RuntimeSafetyController;
}

interface ExplorationWorker {
  id: string;
  cursor: RoutedMission;
  definition: ReturnType<typeof createExplorerAgent>;
}

/** Owns worker allocation, specialist recovery, and exploration lifecycle policy. */
export class ExplorationExecutor {
  readonly coordinator: PersistentCoordinator;
  readonly agentDefinitions: ReturnType<typeof createExplorerAgent>[];
  readonly target: ScopedTarget;
  #options: ExplorationExecutorOptions;
  #explorers: ExplorationWorker[];
  #specialists: ExplorationWorker[];
  #specialistLimit: number;
  #contextTokens: number;
  #enqueueValidation: (fingerprint: string) => void = () => {};

  constructor(options: ExplorationExecutorOptions) {
    this.#options = options;
    const { session, profile, explorerCount } = options;
    const dispatch = session.dispatch.bind(session);
    this.coordinator = new PersistentCoordinator({
      actorIds: [actorIds.anonymous, ...(profile.actorIds ?? [])],
      requestBudget: session.state.budget.exploration,
      expectedWorkers: explorerCount,
      onChange: (snapshot) => dispatch({ type: "coordinator-snapshot", snapshot }),
      restore: {
        snapshot: session.state.coordination,
        operations: session.state.discoveredOperations,
        testedRequests: session.state.testedRequests,
        findings: session.state.findings,
        validations: session.state.validations,
        explorationRequests: session.state.requests.exploration,
      },
    });
    for (const job of session.state.runtime.jobs) {
      if (job.kind === "validation" && job.status === "queued") {
        this.coordinator.releaseValidation(job.fingerprint);
      }
    }
    dispatch({ type: "coordinator-snapshot", snapshot: this.coordinator.snapshot() });
    for (const plan of this.coordinator.snapshot().specialists) {
      if (!session.state.agents.some(({ id }) => id === plan.agentId)) {
        dispatch({ type: "agent-spawned", id: plan.agentId, role: "specialist" });
      }
    }
    const target = new ScopedTarget({
      target: options.target,
      requestBudget: Math.max(
        0,
        session.state.budget.exploration - session.state.requests.exploration,
      ),
      allowedRequests: profile.allowedRequests,
      setupRequests: profile.setupRequests,
      deniedRequests: profile.deniedRequests,
      onRequest: (request) => {
        session.record("request", { phase: "exploration", ...request });
        dispatch({ type: "request", phase: "exploration" });
        this.coordinator.observeBudgetUse();
      },
      openApi: options.openApi,
      attackSurfaceOrigins: profile.attackSurfaceOrigins,
      maximumImpactLevel: profile.maximumImpactLevel ?? "observation",
      runtimeSafety: options.runtimeSafety,
    });
    this.target = target;
    const adapters = createBoundedToolAdapters({
      target,
      profile,
      artifacts: options.artifacts,
    });
    const ledger = new CampaignLedger({
      onTestedRequest: (request) => {
        this.coordinator.observeRequest(request);
        dispatch({ type: "request-tested", request });
      },
      onFinding: (finding) => {
        const fingerprint = this.coordinator.observeFinding(finding);
        dispatch({ type: "finding", finding });
        this.#enqueueValidation(fingerprint);
      },
      onExploitChain: (chain) => dispatch({ type: "exploit-chain", chain }),
    });
    this.#contextTokens = estimateTokens({
      context: options.context,
      openApi: options.openApi,
      manifest: profile.manifest,
    });
    const triageRoute = () =>
      options.modelRouter.route(routeTriageRequirements(this.#contextTokens));
    const focuses = [
      "broken authorization and cross-object access, using identifiers discovered in one response against other GET endpoints",
      "excessive or sensitive data exposure and security misconfiguration",
      "route-level authentication gaps and object-detail authorization controls not yet tested by the other explorers",
    ];
    const createWorker = (id: string, focus: string | (() => string)): ExplorationWorker => {
      const cursor = new RoutedMission(triageRoute());
      return {
        id,
        cursor,
        definition: createExplorerAgent(
          id,
          focus,
          target,
          profile,
          ledger,
          this.coordinator,
          options.artifacts,
          adapters,
          options.verification,
          dispatch,
          () => cursor.model,
          options.context,
        ),
      };
    };
    this.#explorers = Array.from({ length: explorerCount }, (_, index) => {
      const id = `explorer-${index + 1}`;
      return createWorker(
        id,
        focuses[index] ?? "the remaining REST attack surface not covered by other explorers",
      );
    });
    this.#specialistLimit = Math.min(2, explorerCount);
    this.#specialists = Array.from({ length: this.#specialistLimit }, (_, index) => {
      const id = `specialist-${index + 1}`;
      return createWorker(
        id,
        () =>
          this.coordinator.focusFor(id) ?? "high-confidence hypotheses retained by the coordinator",
      );
    });
    this.agentDefinitions = [
      ...this.#explorers.map(({ definition }) => definition),
      ...this.#specialists.map(({ definition }) => definition),
    ];
  }

  setValidationEnqueuer(enqueue: (fingerprint: string) => void): void {
    this.#enqueueValidation = enqueue;
  }

  async run(): Promise<void> {
    const { profile, session, modelRouter } = this.#options;
    const dispatch = session.dispatch.bind(session);
    if (profile.authenticate) {
      // Agent requests share this target, so setup is intentionally owned by this executor.
      await this.target.runProfileSetup(() => profile.authenticate!(this.target));
    }
    dispatch({ type: "phase", phase: "exploring" });
    await Promise.all(
      this.#explorers.flatMap((worker) => {
        const agent = session.state.agents.find(({ id }) => id === worker.id);
        return agent?.status === "finished"
          ? []
          : [this.runWorker(worker, "explorer", "Resume the bounded REST security campaign.")];
      }),
    );
    if (!session.state.agents.some(({ role }) => role === "specialist")) {
      const plans = this.coordinator.planSpecialists(this.#specialistLimit);
      await Promise.all(
        plans.map((plan, index) => {
          dispatch({ type: "agent-spawned", id: plan.agentId, role: "specialist" });
          const worker = this.#specialists[index]!;
          this.routeSpecialist(worker, plan.specialty, modelRouter);
          return this.runWorker(
            worker,
            "specialist",
            `Investigate the coordinator's assigned ${plan.specialty} hypotheses with a fresh perspective.`,
          );
        }),
      );
      return;
    }
    const pending = session.state.agents.filter(
      ({ role, status }) => role === "specialist" && status !== "finished",
    );
    await Promise.all(
      pending.map((agent) => {
        const worker = specialistDefinition(agent.id, this.#specialists);
        const plan = this.coordinator
          .snapshot()
          .specialists.find(({ agentId }) => agentId === agent.id);
        if (!plan) throw new Error(`No persisted specialist plan exists for ${agent.id}`);
        this.routeSpecialist(worker, plan.specialty, modelRouter);
        return this.runWorker(
          worker,
          "specialist",
          "Resume the coordinator's assigned specialist investigation.",
        );
      }),
    );
  }

  async runWorker(
    worker: ExplorationWorker,
    role: "explorer" | "specialist",
    instruction: string,
  ): Promise<void> {
    const { session } = this.#options;
    const { definition: Agent, id, cursor } = worker;
    const mission = session.beginMission(id, role, cursor.route);
    session.dispatch({ type: "agent", id, status: "running" });
    let summary = "Worker exited without a model summary.";
    try {
      await cursor.run(
        async (_model, markToolInvoked) => {
          const agent = init(Agent, { id: `${id}-attempt-${mission.attemptedModels.length}` });
          const receipt = await agent.dispatch(instruction);
          const reply = await agent.read(receipt, {
            onEvent: (chunk) => {
              if (chunk.type === "tool-input") markToolInvoked();
              session.captureAgentEvent(id, chunk);
            },
          });
          session.captureUsage(reply.metadata, mission);
          summary = reply.text.slice(0, 100);
        },
        (model) => session.recordModelAttempt(mission, model),
      );
      session.dispatch({ type: "agent", id, status: "finished", summary });
    } catch (error) {
      if (isRuntimeStopError(error)) {
        session.dispatch({ type: "agent", id, status: "queued", summary: String(error) });
        throw error;
      }
      summary = String(error);
      session.dispatch({ type: "agent", id, status: "failed", summary });
    } finally {
      if (!this.coordinator.snapshot().debriefs.some((debrief) => debrief.agentId === id)) {
        this.coordinator.debrief(id, { summary, exhausted: true });
      }
      this.coordinator.release(id);
    }
  }

  private routeSpecialist(
    worker: ExplorationWorker,
    specialty: Parameters<typeof specialistRequirements>[0]["specialty"],
    modelRouter: ModelRouter,
  ): void {
    worker.cursor.reset(
      modelRouter.route(
        specialistRequirements({
          specialty,
          contextTokens: this.#contextTokens,
          browserBacked: isBrowserBacked(this.#options.profile),
        }),
      ),
    );
  }
}

function isBrowserBacked(profile: TargetProfile): boolean {
  return (
    profile.proofPolicies?.some(({ kind }) => kind === "browser-effect") === true ||
    profile.manifest?.identities.some(
      ({ authentication }) => authentication?.kind === "browser-login",
    ) === true
  );
}

function specialistDefinition<T>(id: string, definitions: readonly T[]): T {
  const match = /^specialist-(\d+)$/.exec(id);
  const index = match ? Number(match[1]) - 1 : -1;
  const definition = definitions[index];
  if (!definition) throw new Error(`No persisted specialist definition exists for ${id}`);
  return definition;
}
