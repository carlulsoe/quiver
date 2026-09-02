import { describe, expect, it } from "vitest";
import { RequestBudgetExceededError, ScopedTarget } from "./scoped-target.ts";
import { response } from "./scoped-target-test-support.ts";

describe("scoped target", () => {
  it("charges browser proof requests to both the collector cap and campaign budget", async () => {
    const requested: string[] = [];
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 3,
      onRequest: ({ method, path }) => requested.push(`${method} ${path}`),
      browserEffectCollector: async (probe) => {
        expect(probe.decideRequest("GET", "/proof")).toBe(true);
        expect(probe.decideRequest("GET", "/asset.js")).toBe(true);
        expect(probe.decideRequest("GET", "/extra.js")).toBe(false);
        expect(probe.decideRequest("POST", "/submit")).toBe(false);
        return undefined;
      },
    });

    await target.observeBrowserEffect({
      probeId: "probe-1",
      path: "/proof",
      marker: "QUIVER-BROWSER-1",
      kind: "dialog",
      actorId: "anonymous",
      requestBudget: 2,
    });

    expect(requested).toEqual(["GET /proof", "GET /asset.js"]);
    expect(target.remainingRequests).toBe(1);
  });

  it("rejects an authenticated browser proof without configured browser credentials", async () => {
    let browserCollections = 0;
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 1,
      browserEffectCollector: async () => {
        browserCollections += 1;
        return undefined;
      },
    });

    await expect(
      target.observeBrowserEffect({
        probeId: "probe-1",
        path: "/proof",
        marker: "QUIVER-BROWSER-1",
        kind: "dialog",
        actorId: "ordinary-user",
        requestBudget: 1,
      }),
    ).rejects.toThrow("no browser session for actor ordinary-user");
    expect(browserCollections).toBe(0);
    expect(target.remainingRequests).toBe(1);
  });

  it("delegates to a budgeted REST attack-surface mapper", async () => {
    const requested: string[] = [];
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888/start"),
      requestBudget: 5,
      onRequest: ({ method, path }) => requested.push(`${method} ${path}`),
      attackSurfaceMapper: async (options) => {
        expect(options.decideRequest("GET", "/start").allowed).toBe(true);
        expect(options.decideRequest("GET", "/assets/app.js", { budgeted: true }).allowed).toBe(
          true,
        );
        expect(options.decideRequest("POST", "/api/search").allowed).toBe(false);
        return {
          startPath: options.startPath,
          documents: [],
          routes: ["/api/search"],
          routeDetails: [
            {
              path: "/api/search",
              methods: ["POST"],
              sources: ["browser:fetch:/start"],
              examples: ["/api/search"],
              callSites: [{ documentPath: "/start", method: "POST", authentication: "unknown" }],
              getCallSites: [],
              identifierSources: [],
            },
          ],
        };
      },
    });

    const map = await target.mapAttackSurface({ maxDocuments: 3 });

    expect(requested).toEqual(["GET /start", "GET /assets/app.js"]);
    expect(map.routeDetails[0]).toMatchObject({ path: "/api/search", methods: ["POST"] });
  });

  it("enforces one request budget across mapping and direct requests", async () => {
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 1,
      transport: async () => response("ok", "text/plain"),
    });

    await target.request({ path: "/first" });

    await expect(target.request({ path: "/second" })).rejects.toBeInstanceOf(
      RequestBudgetExceededError,
    );
  });

  it("allows state-changing operations only after profile or mapper authorization", async () => {
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 2,
      attackSurfaceMapper: async (options) => {
        options.onOperationDiscovered?.("PATCH", "/api/items/{id}", "openapi");
        return {
          startPath: "/",
          documents: [],
          routes: ["/api/items/{id}"],
          routeDetails: [
            {
              path: "/api/items/{id}",
              methods: ["PATCH"],
              sources: ["openapi"],
              examples: [],
              callSites: [],
              getCallSites: [],
              identifierSources: [],
            },
          ],
        };
      },
      transport: async () => response('{"updated":true}', "application/json"),
    });

    await expect(
      target.request({ path: "/api/items/42", method: "PATCH", body: "{}" }),
    ).rejects.toThrow("was not supplied by the profile or attack-surface map");
    await target.mapAttackSurface();
    await expect(
      target.request({ path: "/api/items/42", method: "PATCH", body: "{}" }),
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      target.request({ path: "/api/items/widget-blue", method: "PATCH", body: "{}" }),
    ).resolves.toMatchObject({ status: 200 });
    await expect(target.request({ path: "/api/admin", method: "DELETE" })).rejects.toThrow(
      "DELETE is never allowed for proof demonstration",
    );
  });

  it("allows safe form reads without authorizing rejected browser mutations", async () => {
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 2,
      attackSurfaceMapper: async (options) => {
        options.onOperationDiscovered?.("DELETE", "/api/items/42", "browser", {
          automaticInteraction: true,
        });
        expect(
          options.decideRequest("DELETE", "/api/items/42", {
            budgeted: true,
            automaticInteraction: true,
          }).allowed,
        ).toBe(false);
        expect(
          options.decideRequest("GET", "/logout", {
            budgeted: true,
            automaticInteraction: true,
          }).allowed,
        ).toBe(true);
        return {
          startPath: "/",
          documents: [],
          routes: ["/api/items/42"],
          routeDetails: [
            {
              path: "/api/items/42",
              methods: ["DELETE"],
              sources: ["browser:fetch:/"],
              examples: ["/api/items/42"],
              callSites: [],
              getCallSites: [],
              identifierSources: [],
            },
          ],
        };
      },
      transport: async () => response("unexpected", "text/plain"),
    });

    const map = await target.mapAttackSurface();

    expect(map.routes).toContain("/api/items/42");
    await expect(target.request({ path: "/api/items/42", method: "DELETE" })).rejects.toThrow(
      "DELETE is never allowed for proof demonstration",
    );
  });
});
