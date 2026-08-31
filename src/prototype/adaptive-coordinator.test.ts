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
        (task) => task.source === "uncovered-surface" && task.authenticated,
      ),
    ).toBe(true);
  });

  it("turns evidence from a concrete string identifier into a template follow-up", () => {
    const coordinator = new AdaptiveCoordinator();
    coordinator.discoverRoutes(["/api/users/{username}"]);
    coordinator.observeRequest({
      agentId: "explorer-1",
      path: "/api/users/alice",
      authenticated: true,
      status: 200,
    });

    expect(coordinator.assign("explorer-2")).toMatchObject({
      uncoveredRouteCount: 0,
      tasks: [
        {
          route: "/api/users/{username}",
          authenticated: false,
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
      authenticated: true,
      status: 200,
    });

    const assignment = coordinator.assign("explorer-2", 2);
    expect(assignment.tasks).toContainEqual(
      expect.objectContaining({ route: "/api/users/me", authenticated: false }),
    );
    expect(assignment.tasks).toContainEqual(
      expect.objectContaining({ route: "/api/users/{username}", authenticated: true }),
    );
  });

  it("retires completed claims and reports no work after both modes are covered", () => {
    const coordinator = new AdaptiveCoordinator();
    coordinator.discoverRoutes(["/api/me"]);
    coordinator.assign("explorer-1");
    coordinator.observeRequest({
      agentId: "explorer-1",
      path: "/api/me",
      authenticated: true,
      status: 200,
    });
    coordinator.observeRequest({
      agentId: "explorer-2",
      path: "/api/me",
      authenticated: false,
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
    const coordinator = new AdaptiveCoordinator({ supportsAuthentication: false });
    coordinator.discoverRoutes(["/public/catalog"]);

    const [task] = coordinator.assign("explorer-1").tasks;
    expect(task).toMatchObject({ route: "/public/catalog", authenticated: false });

    coordinator.observeRequest({
      agentId: "explorer-1",
      path: "/public/catalog",
      authenticated: false,
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
      authenticated: true,
      status: 200,
    });

    expect(coordinator.assign("explorer-2").tasks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ route: "/api/items?owner=me", authenticated: false }),
        expect.objectContaining({ route: "/api/items?owner=all", authenticated: true }),
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
      authenticated: true,
      status: 200,
    });

    expect(coordinator.assign("explorer-2").tasks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ method: "GET", authenticated: true }),
        expect.objectContaining({ method: "PATCH", authenticated: false }),
      ]),
    );
  });

  it("matches templated query values to concrete evidence", () => {
    const coordinator = new AdaptiveCoordinator();
    coordinator.discoverRoutes(["/api/items?owner={username}"]);
    coordinator.observeRequest({
      agentId: "explorer-1",
      path: "/api/items?owner=alice",
      authenticated: true,
      status: 200,
    });

    expect(coordinator.assign("explorer-2").tasks).toEqual([
      expect.objectContaining({ route: "/api/items?owner={username}", authenticated: false }),
    ]);
  });
});
