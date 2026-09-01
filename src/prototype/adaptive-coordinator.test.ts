import { describe, expect, it } from "vitest";
import { AdaptiveCoordinator } from "./adaptive-coordinator.ts";

describe("adaptive coordinator", () => {
  it("assigns distinct uncovered routes to concurrent explorers", () => {
    const coordinator = new AdaptiveCoordinator();
    coordinator.discoverRoutes(["/api/items", "/api/users", "/api/orders"]);

    const first = coordinator.assign("explorer-1", 2);
    const second = coordinator.assign("explorer-2", 2);

    expect(first.tasks).toHaveLength(2);
    expect(second.tasks).toHaveLength(1);
    expect(second.tasks[0]!.route).not.toBe(first.tasks[0]!.route);
    expect(
      [...first.tasks, ...second.tasks].every(
        (task) => task.source === "uncovered-surface" && task.actorId === "ordinary-user",
      ),
    ).toBe(true);
  });

  it("turns evidence from a concrete string identifier into a template follow-up", () => {
    const coordinator = new AdaptiveCoordinator();
    coordinator.discoverRoutes(["/api/users/{username}"]);
    coordinator.observeRequest({
      agentId: "explorer-1",
      path: "/api/users/alice",
      actorId: "ordinary-user",
      status: 200,
    });

    expect(coordinator.assign("explorer-2")).toMatchObject({
      uncoveredRouteCount: 0,
      tasks: [
        {
          route: "/api/users/{username}",
          actorId: "anonymous",
          source: "incoming-evidence",
        },
      ],
    });
  });

  it("prefers an exact static route over an overlapping template", () => {
    const coordinator = new AdaptiveCoordinator();
    coordinator.discoverRoutes(["/api/users/{username}", "/api/users/me"]);
    coordinator.observeRequest({
      agentId: "explorer-1",
      path: "/api/users/me",
      actorId: "ordinary-user",
      status: 200,
    });

    const assignment = coordinator.assign("explorer-2", 2);
    expect(assignment.tasks).toContainEqual(
      expect.objectContaining({ route: "/api/users/me", actorId: "anonymous" }),
    );
    expect(assignment.tasks).toContainEqual(
      expect.objectContaining({ route: "/api/users/{username}", actorId: "ordinary-user" }),
    );
  });

  it("retires completed claims and reports no work after both modes are covered", () => {
    const coordinator = new AdaptiveCoordinator();
    coordinator.discoverRoutes(["/api/me"]);
    coordinator.assign("explorer-1");
    coordinator.observeRequest({
      agentId: "explorer-1",
      path: "/api/me",
      actorId: "ordinary-user",
      status: 200,
    });
    coordinator.observeRequest({
      agentId: "explorer-2",
      path: "/api/me",
      actorId: "anonymous",
      status: 401,
    });

    expect(coordinator.assign("explorer-3").tasks).toEqual([]);
  });

  it("returns unfinished work to the pool when an explorer exits", () => {
    const coordinator = new AdaptiveCoordinator();
    coordinator.discoverRoutes(["/api/items"]);
    coordinator.assign("explorer-1");

    expect(coordinator.assign("explorer-2").tasks).toEqual([]);
    coordinator.release("explorer-1");
    expect(coordinator.assign("explorer-2").tasks).toHaveLength(1);
  });

  it("assigns only anonymous work when the target has no authentication", () => {
    const coordinator = new AdaptiveCoordinator({ actorIds: ["anonymous"] });
    coordinator.discoverRoutes(["/public/catalog"]);

    const [task] = coordinator.assign("explorer-1").tasks;
    expect(task).toMatchObject({ route: "/public/catalog", actorId: "anonymous" });

    coordinator.observeRequest({
      agentId: "explorer-1",
      path: "/public/catalog",
      actorId: "anonymous",
      status: 200,
    });
    expect(coordinator.assign("explorer-1").tasks).toEqual([]);
  });

  it("ignores malformed percent escapes in discovered routes", () => {
    const coordinator = new AdaptiveCoordinator();

    expect(() => coordinator.discoverRoutes(["/api/%zz", "/api/valid"])).not.toThrow();
    expect(coordinator.assign("explorer-1").tasks).toEqual([
      expect.objectContaining({ route: "/api/valid" }),
    ]);
  });

  it("coordinates query variants as distinct surface", () => {
    const coordinator = new AdaptiveCoordinator();
    coordinator.discoverRoutes(["/api/items?owner=me", "/api/items?owner=all"]);
    coordinator.observeRequest({
      agentId: "explorer-1",
      path: "/api/items?owner=me",
      actorId: "ordinary-user",
      status: 200,
    });

    expect(coordinator.assign("explorer-2").tasks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ route: "/api/items?owner=me", actorId: "anonymous" }),
        expect.objectContaining({ route: "/api/items?owner=all", actorId: "ordinary-user" }),
      ]),
    );
  });

  it("coordinates methods on the same route as distinct operations", () => {
    const coordinator = new AdaptiveCoordinator();
    coordinator.discoverOperations([
      { method: "GET", path: "/api/items/{id}" },
      { method: "PATCH", path: "/api/items/{id}" },
    ]);
    coordinator.observeRequest({
      agentId: "explorer-1",
      method: "PATCH",
      path: "/api/items/42",
      actorId: "ordinary-user",
      status: 200,
    });

    expect(coordinator.assign("explorer-2").tasks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ method: "GET", actorId: "ordinary-user" }),
        expect.objectContaining({ method: "PATCH", actorId: "anonymous" }),
      ]),
    );
  });

  it("matches templated query values to concrete evidence", () => {
    const coordinator = new AdaptiveCoordinator();
    coordinator.discoverRoutes(["/api/items?owner={username}"]);
    coordinator.observeRequest({
      agentId: "explorer-1",
      path: "/api/items?owner=alice",
      actorId: "ordinary-user",
      status: 200,
    });

    expect(coordinator.assign("explorer-2").tasks).toEqual([
      expect.objectContaining({ route: "/api/items?owner={username}", actorId: "anonymous" }),
    ]);
  });

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
});
