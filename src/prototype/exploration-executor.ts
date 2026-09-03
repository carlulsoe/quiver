import { init } from "@flue/runtime";
import type { PersistentCoordinator } from "./adaptive-coordinator.ts";
import {
  createExplorationResources,
  isBrowserBacked,
  specialistDefinition,
  type ExplorationExecutorOptions,
  type ExplorationWorker,
} from "./exploration-resources.ts";
import { specialistRequirements, type ModelRouter } from "./model-routing.ts";
import { isRuntimeStopError } from "./runner-errors.ts";
import type { ScopedTarget } from "./scoped-target.ts";

export class ExplorationExecutor {
  readonly coordinator: PersistentCoordinator;
  readonly agentDefinitions: ExplorationWorker["definition"][];
  readonly target: ScopedTarget;
  #options: ExplorationExecutorOptions;
  #explorers: ExplorationWorker[];
  #specialists: ExplorationWorker[];
  #specialistLimit: number;
  #contextTokens: number;
  #enqueueValidation: (fingerprint: string) => void = () => {};

  constructor(options: ExplorationExecutorOptions) {
    this.#options = options;
    const resources = createExplorationResources(options, (fingerprint) =>
      this.#enqueueValidation(fingerprint),
    );
    this.coordinator = resources.coordinator;
    this.target = resources.target;
    this.#explorers = resources.explorers;
    this.#specialists = resources.specialists;
    this.#specialistLimit = resources.specialistLimit;
    this.#contextTokens = resources.contextTokens;
    this.agentDefinitions = resources.agentDefinitions;
  }

  setValidationEnqueuer(enqueue: (fingerprint: string) => void): void {
    this.#enqueueValidation = enqueue;
  }

  async run(): Promise<void> {
    const { profile, session, modelRouter } = this.#options;
    const dispatch = session.dispatch.bind(session);
    if (profile.authenticate)
      await this.target.runProfileSetup("authentication", () => profile.authenticate!(this.target));
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
      if (!this.coordinator.snapshot().debriefs.some((debrief) => debrief.agentId === id))
        this.coordinator.debrief(id, { summary, exhausted: true });
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
