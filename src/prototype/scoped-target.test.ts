import { describe, expect, it } from "vitest";
import { RequestBudgetExceededError, ScopedTarget, TargetScopeError } from "./scoped-target.ts";

function response(body: string, contentType: string): Response {
  return new Response(body, { status: 200, headers: { "content-type": contentType } });
}

describe("scoped target", () => {
  it("captures an exact Location header without following the redirect", async () => {
    let redirectMode: RequestRedirect | undefined;
    const destination = "https://redirect-proof.invalid/landing";
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
      transport: async (_input, init) => {
        redirectMode = init?.redirect;
        return new Response("redirecting", {
          status: 302,
          headers: { location: destination },
        });
      },
    });

    await expect(target.request({ path: "/leave?next=external" })).resolves.toMatchObject({
      status: 302,
      redirectLocation: destination,
      redirected: false,
    });
    expect(redirectMode).toBe("manual");
  });

  it("requires CSRF browser proof cookies to belong to the primary target", async () => {
    let collections = 0;
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      allowedRequests: [{ method: "POST", path: "/account/email" }],
      attackSurfaceOrigins: [{ origin: "http://127.0.0.1:9999", scope: "visit-only" }],
      browserStateTransitionCollector: async () => {
        collections += 1;
        return undefined;
      },
    });
    target.setSession("ordinary-user", {
      browserState: {
        cookies: [{ name: "session", value: "wrong", url: "http://127.0.0.1:9999" }],
      },
    });

    await expect(
      target.observeBrowserStateTransition({
        policyId: "email-csrf",
        sourceOrigin: "http://127.0.0.1:9999",
        sourcePath: "/csrf/email",
        targetPath: "/account/email",
        method: "POST",
        actorId: "ordinary-user",
        requestBudget: 2,
      }),
    ).rejects.toThrow("target-scoped cookies");
    expect(collections).toBe(0);
    expect(target.requestsUsed).toBe(0);
  });

  it("extends a persistent validation session and admits new reproduction operations", async () => {
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
      transport: async () => new Response("{}", { status: 200 }),
    });
    target.allowRequests([{ method: "POST", path: "/api/replay" }]);

    await target.request({ path: "/api/replay", method: "POST", body: "{}" });
    await expect(
      target.request({ path: "/api/replay", method: "POST", body: "{}" }),
    ).rejects.toThrow("Request budget exhausted");
    target.extendRequestBudget(1);
    await expect(
      target.request({ path: "/api/replay", method: "POST", body: '{"retry":true}' }),
    ).resolves.toMatchObject({ status: 200 });
    expect(target.requestsUsed).toBe(2);
    expect(target.requestBudget).toBe(2);
  });

  it("allows profile-only setup requests to read authentication response headers", async () => {
    let setupAuthorization: string | null = null;
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 2,
      allowedRequests: [{ method: "POST", path: "/login" }],
      deniedRequests: [{ method: "POST", path: "/login" }],
      transport: async (_input, init) => {
        setupAuthorization = new Headers(init?.headers).get("authorization");
        return new Response("{}", {
          status: 200,
          headers: { authorization: "Bearer setup-token" },
        });
      },
    });

    await expect(target.request({ path: "/login", method: "POST" })).rejects.toThrow(
      "denied by the target profile",
    );
    await expect(
      target.setupRequest({
        path: "/login",
        method: "POST",
        headers: { authorization: "Refresh profile-token" },
      }),
    ).resolves.toMatchObject({
      status: 200,
      headers: { authorization: "Bearer setup-token" },
    });
    expect(setupAuthorization).toBe("Refresh profile-token");
    await expect(target.setupRequest({ path: "/other" })).rejects.toThrow(
      "is not an allowed profile setup request",
    );
  });

  it("enforces the impact ceiling before target or browser network activity", async () => {
    let targetRequests = 0;
    let browserCollections = 0;
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 2,
      maximumImpactLevel: "observation",
      allowedRequests: [{ method: "POST", path: "/profile/setup" }],
      transport: async () => {
        targetRequests += 1;
        return response("ok", "text/plain");
      },
      browserEffectCollector: async () => {
        browserCollections += 1;
        return undefined;
      },
    });

    await expect(
      target.request({ path: "/profile/setup", method: "POST", body: "{}" }),
    ).rejects.toThrow("state-change impact exceeds");
    await expect(
      target.observeBrowserEffect({
        probeId: "probe-1",
        path: "/proof",
        marker: "QUIVER-BROWSER-1",
        kind: "dialog",
        actorId: "anonymous",
        requestBudget: 1,
      }),
    ).rejects.toThrow("bounded impact exceeds");
    await expect(target.request({ path: "/anything", method: "DELETE" })).rejects.toThrow(
      "DELETE is never allowed",
    );
    expect(targetRequests).toBe(0);
    expect(browserCollections).toBe(0);
    expect(target.remainingRequests).toBe(2);
  });

  it("limits profile setup bypasses to predeclared setup operations", async () => {
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 3,
      maximumImpactLevel: "observation",
      allowedRequests: [
        { method: "POST", path: "/login" },
        { method: "DELETE", path: "/synthetic-session" },
      ],
      transport: async () => response("ok", "text/plain"),
    });

    await expect(
      target.runProfileSetup(() => target.request({ path: "/login", method: "POST" })),
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      target.runProfileSetup(() => target.request({ path: "/other", method: "POST" })),
    ).rejects.toThrow("not a profile setup operation");
    await expect(
      target.runProfileSetup(() =>
        target.request({ path: "/synthetic-session", method: "DELETE" }),
      ),
    ).resolves.toMatchObject({ status: 200 });
  });

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

  it("does not authorize browser operations rejected by discovery policy", async () => {
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 2,
      attackSurfaceMapper: async (options) => {
        options.onOperationDiscovered?.("POST", "/api/rejected", "browser", {
          automaticInteraction: false,
          allowed: false,
          blockedReason: "state-changing operation is not preauthorized",
        });
        return { startPath: "/", documents: [], routes: [], routeDetails: [] };
      },
      transport: async () => response("unexpected", "text/plain"),
    });

    await target.mapAttackSurface();
    await expect(
      target.request({ path: "/api/rejected", method: "POST", body: "{}" }),
    ).rejects.toThrow("was not supplied by the profile or attack-surface map");
  });

  it("attacks configured secondary origins while keeping visit-only origins browser-only", async () => {
    const requested: Array<{ url: string; authorization: string | null }> = [];
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      attackSurfaceOrigins: [
        { origin: "http://127.0.0.1:8889", scope: "attackable" },
        { origin: "http://127.0.0.1:8890", scope: "visit-only" },
      ],
      attackSurfaceMapper: async (options) => {
        expect(options.origins).toEqual([
          { origin: "http://127.0.0.1:8889", scope: "attackable" },
          { origin: "http://127.0.0.1:8890", scope: "visit-only" },
        ]);
        options.onOperationDiscovered?.("POST", "/api/items/{id}", "openapi", {
          automaticInteraction: false,
          origin: "http://127.0.0.1:8889",
          scope: "attackable",
        });
        return { startPath: "/", documents: [], routes: [], routeDetails: [] };
      },
      transport: async (input, init) => {
        requested.push({
          url: String(input),
          authorization: new Headers(init?.headers).get("authorization"),
        });
        return response('{"updated":true}', "application/json");
      },
    });
    target.setSession("ordinary-user", {
      headers: { authorization: "Bearer primary-session" },
    });

    await target.mapAttackSurface();
    await expect(
      target.request({
        path: "http://127.0.0.1:8889/api/items/42",
        method: "POST",
        body: "{}",
        actorId: "ordinary-user",
      }),
    ).resolves.toMatchObject({
      path: "http://127.0.0.1:8889/api/items/42",
      body: { updated: true },
    });
    await expect(target.request({ path: "http://127.0.0.1:8890/documentation" })).rejects.toThrow(
      "visit-only origin blocked",
    );
    expect(requested).toEqual([{ url: "http://127.0.0.1:8889/api/items/42", authorization: null }]);
  });

  it("reserves auth-only origins for setup and never contacts blocked origins", async () => {
    const requested: string[] = [];
    const authenticationPath = "http://127.0.0.1:8891/token";
    const blockedPath = "http://127.0.0.1:8892/admin";
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      attackSurfaceOrigins: [
        { origin: "http://127.0.0.1:8891", scope: "auth-only" },
        { origin: "http://127.0.0.1:8892", scope: "blocked" },
      ],
      setupRequests: [{ method: "POST", path: authenticationPath }],
      transport: async (input) => {
        requested.push(String(input));
        return response('{"token":"session"}', "application/json");
      },
    });

    await expect(target.request({ path: authenticationPath })).rejects.toThrow(
      "reserved for profile setup",
    );
    await expect(
      target.setupRequest({ path: authenticationPath, method: "POST", body: "grant=test" }),
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      target.setupRequest({ path: blockedPath, method: "POST", body: "{}" }),
    ).rejects.toThrow("blocked");

    expect(requested).toEqual([authenticationPath]);
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
    target.setSession("ordinary-user", { headers: { authorization: "Bearer profile-token" } });

    await expect(
      target.request({
        path: "/api/me",
        actorId: "ordinary-user",
        headers: { authorization: "Bearer other-token" },
      }),
    ).rejects.toThrow("may not override the session adapter's credential headers");
    await expect(
      target.request({
        path: "/api/me",
        actorId: "ordinary-user",
        headers: { cookie: "session=other" },
      }),
    ).rejects.toThrow("may not override the session adapter's credential headers");
    await expect(
      target.request({
        path: "/api/me",
        actorId: "ordinary-user",
        headers: { xApiKey: "other-key" },
      }),
    ).rejects.toThrow("may not override the session adapter's credential headers");
    await expect(
      target.request({
        path: "/api/me",
        headers: { xAccessToken: "anonymous-override" },
      }),
    ).rejects.toThrow("Anonymous requests may only use standard");
    await expect(
      target.request({
        path: "/api/me",
        actorId: "ordinary-user",
        headers: {
          "idempotency-key": "request-1",
          prefer: "return=minimal",
          "x-author": "Ada",
        },
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
    expect(
      () =>
        new ScopedTarget({
          target: new URL("http://127.0.0.1:8888"),
          requestBudget: 1,
          attackSurfaceOrigins: [{ origin: "https://example.com", scope: "visit-only" }],
        }),
    ).toThrow("Discovery origins must be exact loopback");
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
