import { CoordinatorCore } from "./adaptive-coordinator-core.ts";
import type {
  CoordinatorHypothesis,
  CoordinatorSnapshot,
  SpecialistKind,
  SpecialistPlan,
  WorkAssignment,
} from "./adaptive-coordinator-types.ts";
import { cloneHypothesis, workerBudget } from "./adaptive-coordinator-utils.ts";

export abstract class CoordinatorAssignment extends CoordinatorCore {
  assign(agentId: string, limit = 3): WorkAssignment {
    if (!Number.isInteger(limit) || limit < 1) throw new Error("Assignment limit must be positive");

    const candidates = this.candidates();
    const retained = candidates.filter((candidate) => this.claims.get(candidate.key) === agentId);
    const available = candidates.filter((candidate) => !this.claims.has(candidate.key));
    const selected = [...retained, ...available].slice(0, limit);
    for (const candidate of selected) {
      this.claims.set(candidate.key, agentId);
      if (candidate.hypothesisId) {
        const hypothesis = this.hypotheses.get(candidate.hypothesisId);
        if (hypothesis && hypothesis.status === "queued") {
          hypothesis.status = "testing";
          hypothesis.assignedAgentId = agentId;
        }
      }
    }

    const budget = this.allocate(agentId, selected.length > 0);
    const uncoveredRouteCount = [...this.operations].filter(
      ([operation]) => !this.tested.has(operation),
    ).length;
    const evidenceSignals = [...this.tested.entries()].flatMap(([operation, requests]) => {
      const modes = new Set(requests.map(({ actorId }) => actorId));
      if (modes.size >= this.actorIds.length) return [];
      const latest = requests.at(-1)!;
      const untested = this.actorIds.filter((actorId) => !modes.has(actorId));
      return [
        `${operation} returned ${latest.status} as ${latest.actorId}; ${untested.join(", ")} remain untested`,
      ];
    });
    const assignedHypotheses = [...this.hypotheses.values()].filter(
      ({ assignedAgentId }) => assignedAgentId === agentId,
    );
    const specialty = this.specialists.get(agentId)?.specialty;
    this.changed();

    const assignment: WorkAssignment = {
      agentId,
      tasks: selected.map(({ key: _key, priority: _priority, ...task }) => task),
      uncoveredRouteCount,
      evidenceSignals,
      hypotheses: assignedHypotheses.map(cloneHypothesis),
      budget,
    };
    if (specialty) assignment.specialty = specialty;
    return assignment;
  }

  planSpecialists(limit = 2): SpecialistPlan[] {
    if (!Number.isInteger(limit) || limit < 0)
      throw new Error("Specialist limit must be non-negative");
    if (limit === 0) return [];
    const queued = [...this.hypotheses.values()]
      .filter(({ status, confidence }) => status === "queued" && confidence >= 0.5)
      .sort((left, right) => right.confidence - left.confidence || left.id.localeCompare(right.id));
    const bySpecialty = new Map<SpecialistKind, CoordinatorHypothesis[]>();
    for (const hypothesis of queued) {
      const group = bySpecialty.get(hypothesis.specialty) ?? [];
      group.push(hypothesis);
      bySpecialty.set(hypothesis.specialty, group);
    }

    const plans: SpecialistPlan[] = [];
    for (const [specialty, hypotheses] of bySpecialty) {
      if (plans.length >= limit || this.availableBudget() <= 0) break;
      const agentId = `specialist-${++this.specialistSequence}`;
      const requestBudget = Math.max(
        1,
        Math.min(hypotheses.length * 2, Math.ceil(this.availableBudget() / (limit - plans.length))),
      );
      const plan: SpecialistPlan = {
        agentId,
        specialty,
        focus: `${specialty} hypotheses: ${hypotheses.map(({ title }) => title).join("; ")}`,
        hypothesisIds: hypotheses.map(({ id }) => id),
        requestBudget,
      };
      this.specialists.set(agentId, plan);
      this.allocations.set(agentId, { allocated: requestBudget, used: 0 });
      for (const hypothesis of hypotheses) {
        hypothesis.status = "testing";
        hypothesis.assignedAgentId = agentId;
      }
      plans.push(plan);
    }
    if (plans.length > 0) this.changed();
    return plans.map((plan) => ({ ...plan, hypothesisIds: [...plan.hypothesisIds] }));
  }

  focusFor(agentId: string): string | undefined {
    return this.specialists.get(agentId)?.focus;
  }

  snapshot(): CoordinatorSnapshot {
    const workers = Object.fromEntries(
      [...this.allocations].map(([agentId, allocation]) => [agentId, workerBudget(allocation)]),
    );
    const allocated = Object.values(workers).reduce((total, budget) => total + budget.remaining, 0);
    return {
      revision: this.revision,
      coverage: this.coverage(),
      hypotheses: [...this.hypotheses.values()].map(cloneHypothesis),
      debriefs: [...this.debriefs.values()].map((debrief) => ({
        ...debrief,
        hypotheses: debrief.hypotheses.map((item) => ({ ...item })),
      })),
      specialists: [...this.specialists.values()].map((plan) => ({
        ...plan,
        hypothesisIds: [...plan.hypothesisIds],
      })),
      validationQueue: [...this.validationQueue.values()].map((item) => ({ ...item })),
      budget: {
        total: this.requestBudget ?? null,
        consumed: this.requestsConsumed,
        allocated,
        available:
          this.requestBudget === undefined
            ? null
            : Math.max(0, this.requestBudget - this.requestsConsumed - allocated),
        workers,
      },
    };
  }
}
