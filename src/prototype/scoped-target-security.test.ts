import { describe, expect, it } from "vitest";
import { ScopedTarget } from "./scoped-target.ts";
import { response } from "./scoped-target-test-support.ts";

describe("scoped target", () => {
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
});
