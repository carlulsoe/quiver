import { CoordinatorCandidates } from "./adaptive-coordinator-candidates.ts";
import type {
  CoordinatorCoverage,
  CoordinatorHypothesis,
  HypothesisInput,
  WorkerBudget,
} from "./adaptive-coordinator-types.ts";
import {
  clampConfidence,
  operationKey,
  safeCoordinatorKey,
  workerBudget,
} from "./adaptive-coordinator-utils.ts";

export class CoordinatorBehavior extends CoordinatorCandidates {
  protected evidenceHypothesis(operation: string): CoordinatorHypothesis | undefined {
    return [...this.hypotheses.values()].find(
      (hypothesis) =>
        operationKey(hypothesis.method, hypothesis.route) === operation &&
        hypothesis.proposedBy === "coordinator" &&
        hypothesis.status !== "rejected",
    );
  }

  protected recordHypothesis(agentId: string, input: HypothesisInput): void {
    const canonicalRoute = safeCoordinatorKey(input.route);
    if (!canonicalRoute || !Number.isFinite(input.confidence)) return;
    const method = (input.method ?? "GET").toUpperCase();
    const duplicate = [...this.hypotheses.values()].find(
      (hypothesis) =>
        hypothesis.method === method &&
        safeCoordinatorKey(hypothesis.route) === canonicalRoute &&
        hypothesis.specialty === input.specialty &&
        hypothesis.title.toLowerCase() === input.title.toLowerCase(),
    );
    if (duplicate) {
      duplicate.confidence = Math.max(duplicate.confidence, clampConfidence(input.confidence));
      duplicate.rationale = input.rationale;
      duplicate.nextStep = input.nextStep;
      duplicate.evidenceSignals.push(`Reinforced by ${agentId}'s debrief.`);
      if (duplicate.status === "rejected") duplicate.status = "queued";
      return;
    }
    const hypothesis: CoordinatorHypothesis = {
      id: `hypothesis-${++this.hypothesisSequence}`,
      title: input.title,
      method,
      route: input.route,
      specialty: input.specialty,
      status: "queued",
      confidence: clampConfidence(input.confidence),
      rationale: input.rationale,
      nextStep: input.nextStep,
      proposedBy: agentId,
      evidenceSignals: [`Proposed during ${agentId}'s debrief.`],
    };
    this.hypotheses.set(hypothesis.id, hypothesis);
  }

  protected allocate(agentId: string, hasWork: boolean): WorkerBudget {
    const existing = this.allocations.get(agentId);
    if (existing) return workerBudget(existing);
    if (!hasWork) return { allocated: 0, used: 0, remaining: 0 };
    const available = this.availableBudget();
    const activeWorkers = [...this.allocations.values()].filter(
      ({ allocated, used }) => allocated > used,
    ).length;
    const slots = Math.max(1, this.expectedWorkers - activeWorkers);
    const allocated =
      this.requestBudget === undefined ? 3 : Math.max(0, Math.ceil(available / slots));
    const allocation = { allocated, used: 0 };
    this.allocations.set(agentId, allocation);
    return workerBudget(allocation);
  }

  protected availableBudget(): number {
    if (this.requestBudget === undefined) return Number.MAX_SAFE_INTEGER;
    const reserved = [...this.allocations.values()].reduce(
      (total, allocation) => total + Math.max(0, allocation.allocated - allocation.used),
      0,
    );
    return Math.max(0, this.requestBudget - this.requestsConsumed - reserved);
  }

  protected coverage(): CoordinatorCoverage {
    const testedOperations = [...this.operations].filter(([operation]) =>
      this.tested.has(operation),
    ).length;
    const testedAccessModes = [...this.operations].reduce((total, [operation]) => {
      const modes = new Set((this.tested.get(operation) ?? []).map(({ actorId }) => actorId));
      return total + modes.size;
    }, 0);
    const discoveredOperations = this.operations.size;
    const totalAccessModes = discoveredOperations * this.actorIds.length;
    return {
      discoveredOperations,
      testedOperations,
      operationCoverage: discoveredOperations === 0 ? 0 : testedOperations / discoveredOperations,
      testedAccessModes,
      totalAccessModes,
      accessModeCoverage: totalAccessModes === 0 ? 0 : testedAccessModes / totalAccessModes,
    };
  }

  protected changed(): void {
    this.revision += 1;
    this.onChange?.(this.snapshot());
  }
}
