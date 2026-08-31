import { describe, expect, it } from "vitest";
import { RequestBudgetExceededError, ScopedTarget, TargetScopeError } from "./scoped-target.ts";

function response(body: string, contentType: string): Response {
  return new Response(body, { status: 200, headers: { "content-type": contentType } });
}

describe("scoped target", () => {
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
      "was not supplied by the profile or attack-surface map",
    );
  });

  it("does not authorize rejected browser observations for direct requests", async () => {
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
        ).toBe(false);
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
      "was not supplied by the profile or attack-surface map",
    );
  });

  it("authorizes passively observed browser operations", async () => {
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 2,
      attackSurfaceMapper: async (options) => {
        expect(options.decideRequest("POST", "/api/runtime-operation").allowed).toBe(false);
        options.onOperationDiscovered?.("POST", "/api/runtime-operation", "browser", {
          automaticInteraction: false,
        });
        return { startPath: "/", documents: [], routes: [], routeDetails: [] };
      },
      transport: async () => response('{"created":true}', "application/json"),
    });

    await target.mapAttackSurface();

    await expect(
      target.request({ path: "/api/runtime-operation", method: "POST", body: "{}" }),
    ).resolves.toMatchObject({ status: 200, body: { created: true } });
  });

  it("rejects credential-capable headers on anonymous requests", async () => {
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 1,
      transport: async () => response("ok", "text/plain"),
    });

    await expect(
      target.request({ path: "/api/items", headers: { "x-api-key": "secret" } }),
    ).rejects.toThrow("Anonymous requests may only use standard");
    await expect(
      target.request({
        path: "/api/items",
        headers: { "x-http-method-override": "DELETE" },
      }),
    ).rejects.toThrow("may not override the scoped method or target path");
    await expect(
      target.request({
        path: "/api/items",
        headers: { accept: "application/json", "x-tenant-id": "tenant-42" },
      }),
    ).resolves.toMatchObject({ status: 200 });
  });

  it("rejects caller credentials that could replace the authenticated identity", async () => {
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 1,
      transport: async () => response("ok", "text/plain"),
    });
    target.setAuthentication({ authorization: "Bearer profile-token" });

    await expect(
      target.request({
        path: "/api/me",
        authenticated: true,
        headers: { authorization: "Bearer other-token" },
      }),
    ).rejects.toThrow("may not override the target profile's credential headers");
    await expect(
      target.request({
        path: "/api/me",
        authenticated: true,
        headers: { cookie: "session=other" },
      }),
    ).rejects.toThrow("may not override the target profile's credential headers");
    await expect(
      target.request({
        path: "/api/me",
        authenticated: true,
        headers: { "idempotency-key": "request-1", prefer: "return=minimal" },
      }),
    ).resolves.toMatchObject({ status: 200 });
  });

  it("sends scoped REST methods, headers, and bodies", async () => {
    const seen: Array<{ method?: string; body?: BodyInit | null; header?: string | null }> = [];
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 1,
      allowedRequests: [{ method: "PATCH", path: "/items/42" }],
      transport: async (_input, init) => {
        const headers = new Headers(init?.headers);
        seen.push({ method: init?.method, body: init?.body, header: headers.get("content-type") });
        return response('{"updated":true}', "application/json");
      },
    });

    await expect(
      target.request({
        path: "/items/42",
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: '{"name":"updated"}',
      }),
    ).resolves.toMatchObject({ method: "PATCH", body: { updated: true } });
    expect(seen).toEqual([
      { method: "PATCH", body: '{"name":"updated"}', header: "application/json" },
    ]);
    await expect(
      target.request({ path: "/items/widget-blue", method: "PATCH", body: "{}" }),
    ).rejects.toThrow("was not supplied by the profile or attack-surface map");
  });

  it("shares one crawl map across concurrent explorers", async () => {
    let requests = 0;
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      attackSurfaceMapper: async (options) => {
        requests += 1;
        options.decideRequest("GET", "/");
        return { startPath: "/", documents: [], routes: [], routeDetails: [] };
      },
    });

    const [first, second] = await Promise.all([
      target.mapAttackSurface(),
      target.mapAttackSurface(),
    ]);

    expect(requests).toBe(1);
    expect(second).toBe(first);
  });

  it("rejects non-loopback targets and cross-origin request paths", async () => {
    expect(
      () =>
        new ScopedTarget({
          target: new URL("https://example.com"),
          requestBudget: 1,
        }),
    ).toThrow(TargetScopeError);

    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
    });
    await expect(target.request({ path: "//example.com/escape" })).rejects.toBeInstanceOf(
      TargetScopeError,
    );
  });

  it("blocks profile-denied GET routes before transport or budget use", async () => {
    let requests = 0;
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
      deniedRequests: [{ method: "GET", path: "/api/state-changing-read" }],
      transport: async () => {
        requests += 1;
        return response("unexpected", "text/plain");
      },
    });

    await expect(target.request({ path: "/api/state-changing-read?value=1" })).rejects.toThrow(
      "GET /api/state-changing-read is denied by the target profile",
    );
    expect(requests).toBe(0);
    await expect(target.request({ path: "/safe" })).resolves.toMatchObject({ status: 200 });
  });

  it("excludes profile-denied operations from browser traffic", async () => {
    const requested: string[] = [];
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      allowedRequests: [{ method: "POST", path: "/api/runtime-operation" }],
      deniedRequests: [{ method: "GET", path: "/api/state-changing-read" }],
      attackSurfaceMapper: async (options) => {
        expect(options.decideRequest("GET", "/api/state-changing-read").allowed).toBe(false);
        expect(options.decideRequest("POST", "/api/runtime-operation").allowed).toBe(true);
        requested.push("POST /api/runtime-operation");
        return {
          startPath: "/",
          documents: [],
          routes: ["/api/state-changing-read"],
          routeDetails: [],
        };
      },
    });

    const map = await target.mapAttackSurface();

    expect(map.routes).toContain("/api/state-changing-read");
    expect(requested).toEqual(["POST /api/runtime-operation"]);
  });

  it("caps response bodies before exposing them", async () => {
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
      maxResponseChars: 5,
      transport: async () => response("abcdefgh", "text/plain"),
    });

    await expect(target.request({ path: "/large" })).resolves.toMatchObject({
      body: "abcde",
      truncated: true,
    });
  });
});
