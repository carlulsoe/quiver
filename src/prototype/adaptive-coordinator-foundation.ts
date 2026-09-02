import { actorIds, type ActorId } from "./sessions.ts";
import type { TestedRequest } from "./state.ts";
import type {
  AdaptiveCoordinatorOptions,
  Candidate,
  CoordinatorCoverage,
  CoordinatorHypothesis,
  CoordinatorSnapshot,
  HypothesisInput,
  MutableWorkerBudget,
  SpecialistPlan,
  ValidationQueueItem,
  WorkerBudget,
  WorkerDebrief,
} from "./adaptive-coordinator-types.ts";
import {
  cloneHypothesis,
  maximumSequence,
  operationKey,
  safeCoordinatorKey,
  safeNormalizeEndpoint,
  uniqueActorIds,
} from "./adaptive-coordinator-utils.ts";

export abstract class CoordinatorFoundation {
  protected readonly operations = new Map<string, { method: string; route: string }>();
  protected readonly tested = new Map<string, TestedRequest[]>();
  protected readonly claims = new Map<string, string>();
  protected readonly findings = new Set<string>();
  protected readonly hypotheses = new Map<string, CoordinatorHypothesis>();
  protected readonly debriefs = new Map<string, WorkerDebrief>();
  protected readonly allocations = new Map<string, MutableWorkerBudget>();
  protected readonly specialists = new Map<string, SpecialistPlan>();
  protected readonly validationQueue = new Map<string, ValidationQueueItem>();
  protected readonly actorIds: readonly ActorId[];
  protected readonly requestBudget?: number;
  protected readonly expectedWorkers: number;
  protected readonly onChange?: (snapshot: CoordinatorSnapshot) => void;
  protected requestsConsumed = 0;
  protected hypothesisSequence = 0;
  protected specialistSequence = 0;
  protected revision = 0;

  constructor(options: AdaptiveCoordinatorOptions = {}) {
    this.actorIds = uniqueActorIds(options.actorIds ?? [actorIds.anonymous, actorIds.ordinary]);
    if (
      options.requestBudget !== undefined &&
      (!Number.isInteger(options.requestBudget) || options.requestBudget < 0)
    ) {
      throw new Error("Coordinator request budget must be a non-negative integer");
    }
    this.requestBudget = options.requestBudget;
    this.expectedWorkers = Math.max(1, options.expectedWorkers ?? 1);
    this.onChange = options.onChange;
    if (options.restore) this.restore(options.restore);
  }

  protected restore(restore: NonNullable<AdaptiveCoordinatorOptions["restore"]>): void {
    const snapshot = structuredClone(restore.snapshot);
    this.revision = snapshot.revision;
    this.requestsConsumed = Math.max(snapshot.budget.consumed, restore.explorationRequests);
    for (const operation of restore.operations) {
      const route = safeCoordinatorKey(operation.path);
      if (!route) continue;
      const method = operation.method.toUpperCase();
      this.operations.set(operationKey(method, route), { method, route: operation.path });
    }
    for (const request of restore.testedRequests) {
      const operation = this.operationForRequest(request.method ?? "GET", request.path);
      if (!operation) continue;
      const requests = this.tested.get(operation) ?? [];
      requests.push({ ...request });
      this.tested.set(operation, requests);
    }
    for (const hypothesis of snapshot.hypotheses) {
      this.hypotheses.set(hypothesis.id, cloneHypothesis(hypothesis));
    }
    for (const debrief of snapshot.debriefs) {
      this.debriefs.set(debrief.agentId, {
        ...debrief,
        hypotheses: debrief.hypotheses.map((item) => ({ ...item })),
      });
    }
    for (const specialist of snapshot.specialists) {
      this.specialists.set(specialist.agentId, {
        ...specialist,
        hypothesisIds: [...specialist.hypothesisIds],
      });
    }
    for (const [agentId, budget] of Object.entries(snapshot.budget.workers)) {
      this.allocations.set(agentId, { allocated: budget.allocated, used: budget.used });
    }
    for (const item of snapshot.validationQueue) {
      this.validationQueue.set(item.fingerprint, { ...item });
    }
    for (const finding of restore.findings) {
      const route = safeNormalizeEndpoint(finding.endpoint);
      if (route) this.findings.add(operationKey(finding.method ?? "GET", route));
      if (!this.validationQueue.has(finding.fingerprint)) {
        this.validationQueue.set(finding.fingerprint, {
          fingerprint: finding.fingerprint,
          status: "queued",
        });
      }
    }
    for (const validation of restore.validations) {
      this.validationQueue.set(validation.fingerprint, {
        fingerprint: validation.fingerprint,
        status: "complete",
        outcome: validation.status,
      });
    }
    this.hypothesisSequence = maximumSequence(this.hypotheses.keys(), "hypothesis-");
    this.specialistSequence = maximumSequence(this.specialists.keys(), "specialist-");
  }

  protected abstract operationForRequest(method: string, path: string): string | undefined;
  protected abstract updateEvidenceHypothesis(operation: string, requests: TestedRequest[]): void;
  protected abstract evidenceHypothesis(operation: string): CoordinatorHypothesis | undefined;
  protected abstract recordHypothesis(agentId: string, input: HypothesisInput): void;
  protected abstract changed(): void;
  protected abstract candidates(): Candidate[];
  protected abstract allocate(agentId: string, hasWork: boolean): WorkerBudget;
  protected abstract availableBudget(): number;
  protected abstract coverage(): CoordinatorCoverage;
}
