import { actorIds } from "./sessions.ts";
import type { TestedRequest } from "./state.ts";
import { CoordinatorAssignment } from "./adaptive-coordinator-assignment.ts";
import type { Candidate, CoordinatorHypothesis } from "./adaptive-coordinator-types.ts";
import {
  operationKey,
  routeMatches,
  routeSpecificity,
  safeCoordinatorKey,
  taskKey,
} from "./adaptive-coordinator-utils.ts";

export abstract class CoordinatorCandidates extends CoordinatorAssignment {
  protected candidates(): Candidate[] {
    const candidates: Candidate[] = [];
    for (const [operation, { method, route }] of this.operations) {
      const requests = this.tested.get(operation) ?? [];
      const testedModes = new Set(requests.map(({ actorId }) => actorId));
      if (requests.length === 0) {
        const actorId =
          this.actorIds.find((candidate) => candidate !== actorIds.anonymous) ?? actorIds.anonymous;
        candidates.push({
          key: taskKey(operation, actorId),
          route,
          method,
          actorId,
          source: "uncovered-surface",
          priority: 80,
          reason: "No explorer has tested this discovered operation yet.",
        });
        continue;
      }

      if (testedModes.size < this.actorIds.length) {
        const latest = requests.at(-1)!;
        const actorId = this.actorIds.find((candidate) => !testedModes.has(candidate));
        if (!actorId) continue;
        const success = latest.status >= 200 && latest.status < 300;
        const hypothesis = this.evidenceHypothesis(operation);
        const candidate: Candidate = {
          key: taskKey(operation, actorId),
          route,
          method,
          actorId,
          source: "incoming-evidence",
          priority: success ? 100 : 90,
          reason: success
            ? `${latest.actorId} access succeeded; test the ${actorId} boundary.`
            : `${latest.actorId} access returned ${latest.status}; test ${actorId} to map the boundary.`,
        };
        if (hypothesis) candidate.hypothesisId = hypothesis.id;
        candidates.push(candidate);
      }
    }

    return candidates.sort((left, right) => {
      const leftFinding = this.findings.has(operationKey(left.method, left.route)) ? 1 : 0;
      const rightFinding = this.findings.has(operationKey(right.method, right.route)) ? 1 : 0;
      return (
        leftFinding - rightFinding ||
        right.priority - left.priority ||
        left.route.localeCompare(right.route)
      );
    });
  }

  protected operationForRequest(method: string, path: string): string | undefined {
    const normalized = safeCoordinatorKey(path);
    if (!normalized) return undefined;
    const normalizedMethod = method.toUpperCase();
    const exact = operationKey(normalizedMethod, normalized);
    if (this.operations.has(exact)) return exact;

    const matching = [...this.operations].filter(([, candidate]) => {
      const template = safeCoordinatorKey(candidate.route);
      return (
        candidate.method === normalizedMethod && template && routeMatches(template, normalized)
      );
    });
    matching.sort(
      ([, left], [, right]) => routeSpecificity(right.route) - routeSpecificity(left.route),
    );
    return matching[0]?.[0] ?? exact;
  }

  protected updateEvidenceHypothesis(operation: string, requests: TestedRequest[]): void {
    const testedModes = new Set(requests.map(({ actorId }) => actorId));
    const existing = this.evidenceHypothesis(operation);
    if (testedModes.size > 1) {
      if (existing && existing.status !== "supported") {
        existing.status = "rejected";
        existing.evidenceSignals.push("Both access modes have now been tested.");
      }
      return;
    }
    if (existing) return;
    const candidate = this.operations.get(operation);
    if (!candidate || this.actorIds.length < 2) return;
    const latest = requests.at(-1)!;
    const nextActorId = this.actorIds.find((actorId) => !testedModes.has(actorId));
    if (!nextActorId) return;
    const hypothesis: CoordinatorHypothesis = {
      id: `hypothesis-${++this.hypothesisSequence}`,
      title: `Test the opposite access boundary for ${operation}`,
      method: candidate.method,
      route: candidate.route,
      specialty: latest.actorId === actorIds.anonymous ? "authorization" : "authentication",
      status: "queued",
      confidence: latest.status >= 200 && latest.status < 300 ? 0.75 : 0.6,
      rationale: `${latest.actorId} access returned ${latest.status}, while ${nextActorId} remains unknown.`,
      nextStep: `Repeat ${operation} as ${nextActorId}.`,
      proposedBy: "coordinator",
      evidenceSignals: [`${latest.status} observed by ${latest.agentId}`],
    };
    this.hypotheses.set(hypothesis.id, hypothesis);
  }
}
