import { fingerprintFinding, type FindingInput, type TestedRequest } from "./state.ts";
import { CoordinatorFoundation } from "./adaptive-coordinator-foundation.ts";
import type { WorkerDebrief, WorkerDebriefInput } from "./adaptive-coordinator-types.ts";
import {
  operationKey,
  routeMatches,
  safeCoordinatorKey,
  safeNormalizeEndpoint,
  taskKey,
} from "./adaptive-coordinator-utils.ts";

export abstract class CoordinatorCore extends CoordinatorFoundation {
  discoverRoutes(routes: readonly string[]): void {
    this.discoverOperations(routes.map((path) => ({ method: "GET", path })));
  }

  discoverOperations(operations: readonly { method: string; path: string }[]): void {
    let changed = false;
    for (const { method, path: route } of operations) {
      const normalized = safeCoordinatorKey(route);
      if (!normalized) continue;
      const normalizedMethod = method.toUpperCase();
      const key = operationKey(normalizedMethod, normalized);
      if (this.operations.has(key)) continue;
      this.operations.set(key, { method: normalizedMethod, route });
      changed = true;
    }
    if (changed) this.changed();
  }

  /** Records a real target request, including browser mapping requests. */
  observeBudgetUse(count = 1): void {
    if (!Number.isInteger(count) || count < 1) throw new Error("Budget use must be positive");
    this.requestsConsumed += count;
    this.changed();
  }

  canRequest(agentId: string): boolean {
    if (this.requestBudget !== undefined && this.requestsConsumed >= this.requestBudget) {
      return false;
    }
    const allocation = this.allocations.get(agentId);
    return allocation === undefined || allocation.used < allocation.allocated;
  }

  observeRequest(request: TestedRequest): void {
    const operation = this.operationForRequest(request.method ?? "GET", request.path);
    if (!operation) return;
    const requests = this.tested.get(operation) ?? [];
    requests.push({ ...request });
    this.tested.set(operation, requests);
    this.claims.delete(taskKey(operation, request.actorId));
    const allocation = this.allocations.get(request.agentId);
    if (allocation && allocation.used < allocation.allocated) allocation.used += 1;
    this.updateEvidenceHypothesis(operation, requests);
    this.changed();
  }

  observeFinding(finding: FindingInput): string {
    const route = safeNormalizeEndpoint(finding.endpoint);
    if (route) this.findings.add(operationKey(finding.method ?? "GET", route));
    const fingerprint = fingerprintFinding(finding);
    if (!this.validationQueue.has(fingerprint)) {
      this.validationQueue.set(fingerprint, { fingerprint, status: "queued" });
    }
    for (const hypothesis of this.hypotheses.values()) {
      if (
        hypothesis.status !== "rejected" &&
        route &&
        hypothesis.method === (finding.method ?? "GET") &&
        routeMatches(hypothesis.route, route)
      ) {
        hypothesis.status = "supported";
        hypothesis.evidenceSignals.push(`Finding ${fingerprint} supplies deterministic proof.`);
      }
    }
    this.changed();
    return fingerprint;
  }

  recordValidation(
    fingerprint: string,
    outcome: "confirmed" | "rejected",
    validatorId = "validator",
  ): void {
    const item = this.validationQueue.get(fingerprint);
    if (!item) return;
    this.validationQueue.set(fingerprint, {
      fingerprint,
      status: "complete",
      validatorId,
      outcome,
    });
    this.changed();
  }

  claimValidation(validatorId = "validator", fingerprint?: string): string | undefined {
    const item = fingerprint
      ? this.validationQueue.get(fingerprint)
      : [...this.validationQueue.values()].find(({ status }) => status === "queued");
    if (item?.status !== "queued") return undefined;
    this.validationQueue.set(item.fingerprint, {
      ...item,
      status: "validating",
      validatorId,
    });
    this.changed();
    return item.fingerprint;
  }

  releaseValidation(fingerprint: string): void {
    const item = this.validationQueue.get(fingerprint);
    if (!item || item.status === "complete") return;
    this.validationQueue.set(fingerprint, { fingerprint, status: "queued" });
    this.changed();
  }

  debrief(agentId: string, input: WorkerDebriefInput): WorkerDebrief {
    const debrief: WorkerDebrief = {
      agentId,
      summary: input.summary,
      exhausted: input.exhausted,
      hypotheses: (input.hypotheses ?? []).map((hypothesis) => ({ ...hypothesis })),
    };
    this.debriefs.set(agentId, debrief);
    for (const hypothesis of debrief.hypotheses) this.recordHypothesis(agentId, hypothesis);
    if (input.exhausted) {
      for (const hypothesis of this.hypotheses.values()) {
        if (hypothesis.assignedAgentId === agentId && hypothesis.status === "testing") {
          hypothesis.status = "rejected";
          delete hypothesis.assignedAgentId;
          hypothesis.evidenceSignals.push(`${agentId} exhausted this lead during its mission.`);
        }
      }
    }
    this.changed();
    return { ...debrief, hypotheses: debrief.hypotheses.map((item) => ({ ...item })) };
  }

  release(agentId: string): void {
    let changed = false;
    for (const [key, owner] of this.claims) {
      if (owner === agentId) {
        this.claims.delete(key);
        changed = true;
      }
    }
    for (const hypothesis of this.hypotheses.values()) {
      if (hypothesis.assignedAgentId === agentId && hypothesis.status === "testing") {
        hypothesis.status = "queued";
        delete hypothesis.assignedAgentId;
        changed = true;
      }
    }
    if (this.allocations.delete(agentId)) changed = true;
    if (changed) this.changed();
  }
}
