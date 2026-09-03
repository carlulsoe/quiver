import { describe, expect, it } from "vitest";
import { ScopedTarget, TargetScopeError } from "./scoped-target.ts";
import { response } from "./scoped-target-test-support.ts";

describe("scoped target", () => {
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
    await expect(target.request({ path: "/api/%ZZ" })).rejects.toThrow(
      "contains malformed encoding",
    );
    await expect(target.request({ path: "/api/%252Fadmin" })).rejects.toThrow(
      "contains ambiguous encoding",
    );
    await expect(target.request({ path: "/api/%2e%2e/admin" })).rejects.toThrow(
      "contains ambiguous encoding",
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
        expect(options.decideRequest("GET", "/api/state%2Dchanging%2Dread/").allowed).toBe(false);
        expect(options.decideRequest("GET", "/api/%2Fstate-changing-read")).toMatchObject({
          allowed: false,
          reason: "Target operation path contains ambiguous encoding",
        });
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
});
