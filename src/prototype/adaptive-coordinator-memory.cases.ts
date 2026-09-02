import { describe, expect, it } from "vitest";
import { AdaptiveCoordinator } from "./adaptive-coordinator.ts";

describe("adaptive coordinator memory", () => {
  it("persists coverage, hypotheses, and worker debriefs across short-lived workers", () => {
    const coordinator = new AdaptiveCoordinator({ requestBudget: 12, expectedWorkers: 2 });
    coordinator.discoverOperations([
      { method: "GET", path: "/api/accounts/{id}" },
      { method: "GET", path: "/api/profile" },
    ]);
    const assignment = coordinator.assign("explorer-1", 1);
    coordinator.observeBudgetUse();
    coordinator.observeRequest({
      agentId: "explorer-1",
      method: "GET",
      path: assignment.tasks[0]!.route,
      actorId: "ordinary-user",
      status: 200,
    });
    coordinator.debrief("explorer-1", {
      summary: "The account detail response exposed an owner identifier.",
      exhausted: false,
      hypotheses: [
        {
          title: "Account IDs may cross tenant boundaries",
          method: "GET",
          route: "/api/accounts/{id}",
          specialty: "authorization",
          confidence: 0.8,
          rationale: "The response exposes a stable owner ID.",
          nextStep: "Replace the ID with one learned from another response.",
        },
      ],
    });
    coordinator.release("explorer-1");

    const snapshot = coordinator.snapshot();
    expect(snapshot.coverage).toMatchObject({
      discoveredOperations: 2,
      testedOperations: 1,
      testedAccessModes: 1,
      totalAccessModes: 4,
    });
    expect(snapshot.debriefs).toEqual([
      expect.objectContaining({ agentId: "explorer-1", exhausted: false }),
    ]);
    expect(snapshot.hypotheses).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          title: "Account IDs may cross tenant boundaries",
          specialty: "authorization",
        }),
      ]),
    );
    expect(snapshot.budget).toMatchObject({ total: 12, consumed: 1 });
  });

  it("returns unused worker allocations and uses them to spawn focused specialists", () => {
    const coordinator = new AdaptiveCoordinator({ requestBudget: 8, expectedWorkers: 2 });
    coordinator.discoverRoutes(["/api/accounts/{id}", "/api/me"]);
    expect(coordinator.assign("explorer-1", 1).budget.allocated).toBe(4);
    expect(coordinator.assign("explorer-2", 1).budget.allocated).toBe(4);
    coordinator.debrief("explorer-1", {
      summary: "A cross-account lead remains.",
      exhausted: false,
      hypotheses: [
        {
          title: "Cross-account lookup",
          route: "/api/accounts/{id}",
          specialty: "authorization",
          confidence: 0.9,
          rationale: "Account IDs are enumerable.",
          nextStep: "Try a non-owned account ID.",
        },
      ],
    });
    coordinator.release("explorer-1");
    coordinator.release("explorer-2");

    expect(coordinator.planSpecialists(1)).toEqual([
      expect.objectContaining({
        agentId: "specialist-1",
        specialty: "authorization",
        requestBudget: 2,
        hypothesisIds: [expect.any(String)],
      }),
    ]);
    expect(coordinator.snapshot().budget.workers["specialist-1"]).toMatchObject({
      allocated: 2,
      remaining: 2,
    });
  });

  it("queues findings for incremental independent validation", () => {
    const coordinator = new AdaptiveCoordinator();
    const fingerprint = coordinator.observeFinding({
      agentId: "explorer-1",
      title: "Anonymous profile exposure",
      category: "broken-function-authorization",
      severity: "high",
      cwe: "CWE-306",
      endpoint: "/api/profile",
      resource: "profile",
      rationale: "Anonymous access returned the profile.",
      impact: "Private profile data is public.",
      mitigation: "Require authentication.",
      reproduction: [{ path: "/api/profile", actorId: "anonymous" }],
      proof: {
        type: "unauthenticated-success",
        requestIndex: 0,
        evidencePointers: ["/email"],
      },
    });

    expect(coordinator.claimValidation("validator-1")).toBe(fingerprint);
    coordinator.recordValidation(fingerprint, "confirmed", "validator-1");
    expect(coordinator.snapshot().validationQueue).toEqual([
      { fingerprint, status: "complete", validatorId: "validator-1", outcome: "confirmed" },
    ]);
  });

  it("deterministically restores coordinator memory from a campaign checkpoint", () => {
    const operations = [{ method: "GET", path: "/api/accounts/{id}" }];
    const testedRequests = [
      {
        agentId: "explorer-1",
        method: "GET" as const,
        path: "/api/accounts/42",
        actorId: "ordinary-user" as const,
        status: 200,
      },
    ];
    const coordinator = new AdaptiveCoordinator({ requestBudget: 8, expectedWorkers: 1 });
    coordinator.discoverOperations(operations);
    coordinator.observeBudgetUse();
    coordinator.observeRequest(testedRequests[0]!);
    coordinator.debrief("explorer-1", {
      summary: "Retain the account authorization lead.",
      exhausted: false,
      hypotheses: [
        {
          title: "Cross-account lookup",
          route: "/api/accounts/{id}",
          specialty: "authorization",
          confidence: 0.9,
          rationale: "A concrete account identifier was observed.",
          nextStep: "Try the identifier as another actor.",
        },
      ],
    });
    coordinator.release("explorer-1");
    const snapshot = coordinator.snapshot();

    const restored = new AdaptiveCoordinator({
      requestBudget: 8,
      expectedWorkers: 1,
      restore: {
        snapshot,
        operations,
        testedRequests,
        findings: [],
        validations: [],
        explorationRequests: 1,
      },
    });

    expect(restored.snapshot()).toEqual(snapshot);
  });
});
