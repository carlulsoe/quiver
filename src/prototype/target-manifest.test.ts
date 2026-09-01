import { afterEach, describe, expect, it, vi } from "vitest";
import { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import {
  assertValidTargetManifest,
  authenticateTargetManifest,
  type TargetManifest,
} from "./target-manifest.ts";

afterEach(() => vi.unstubAllEnvs());

function multiPrincipalManifest(): TargetManifest {
  return {
    schemaVersion: 1,
    id: "multi-principal",
    displayName: "Multi-principal fixture",
    objective: "Exercise declarative authentication adapters.",
    scope: {
      setupOperations: [
        { method: "POST", path: "/login/a" },
        { method: "POST", path: "/refresh/a" },
        { method: "POST", path: "/login/b" },
        { method: "POST", path: "/login/admin" },
      ],
      protectedOperations: [
        {
          method: "GET",
          path: "/admin",
          authorizedActors: [actorIds.administrator],
        },
      ],
    },
    identities: [
      { id: actorIds.anonymous, label: "Anonymous", role: "anonymous" },
      {
        id: actorIds.userA,
        label: "User A",
        role: "user",
        authentication: {
          kind: "header-token",
          login: {
            request: { method: "POST", path: "/login/a", body: { password: "a" } },
            credential: { location: "body", pointer: "/access" },
            refreshCredential: { location: "body", pointer: "/refresh" },
            expectedStatuses: [200],
            expiresAfterMs: 100,
          },
          refresh: {
            request: {
              method: "POST",
              path: "/refresh/a",
              body: { refresh: "{{refreshCredential}}" },
            },
            credential: { location: "body", pointer: "/access" },
            expectedStatuses: [200],
            expiresAfterMs: 100,
          },
        },
      },
      {
        id: actorIds.userB,
        label: "User B",
        role: "user",
        authentication: {
          kind: "cookie",
          login: {
            request: { method: "POST", path: "/login/b" },
            credential: { location: "cookie", name: "session" },
          },
          cookie: { name: "session", path: "/app" },
        },
      },
      {
        id: actorIds.administrator,
        label: "Administrator",
        role: "administrator",
        authentication: {
          kind: "browser-login",
          login: {
            request: { method: "POST", path: "/login/admin" },
            credential: { location: "header", name: "authorization" },
          },
          session: {
            localStorage: {
              role: "administrator",
              token: "{{credential}}",
              email: "{{env:QUIVER_MANIFEST_TEST_EMAIL|default@example.test}}",
            },
            cookies: [{ name: "admin_session", value: "{{credential}}", path: "/admin" }],
          },
        },
      },
    ],
  };
}

describe("declarative target onboarding", () => {
  it("materializes header-token, cookie, and browser-login sessions for four actor roles", async () => {
    const manifest = multiPrincipalManifest();
    vi.stubEnv("QUIVER_MANIFEST_TEST_EMAIL", "configured@example.test");
    let now = 0;
    const requests: Array<{ path: string; headers: Headers; body: string }> = [];
    const transport = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const path = new URL(String(input)).pathname;
      requests.push({
        path,
        headers: new Headers(init?.headers),
        body: String(init?.body ?? ""),
      });
      if (path === "/login/a") return Response.json({ access: "a-1", refresh: "refresh-a" });
      if (path === "/refresh/a") return Response.json({ access: "a-2" });
      if (path === "/login/b") {
        return new Response("{}", {
          headers: { "set-cookie": "session=b-cookie; Path=/; HttpOnly" },
        });
      }
      if (path === "/login/admin") {
        return new Response("{}", { headers: { authorization: "Admin admin-token" } });
      }
      return Response.json({ ok: true });
    });
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8080"),
      requestBudget: 12,
      allowedRequests: [...(manifest.scope.setupOperations ?? [])],
      transport,
    });

    await expect(authenticateTargetManifest(target, manifest, { now: () => now })).resolves.toEqual(
      {
        authContext: `${actorIds.userA},${actorIds.userB},${actorIds.administrator}`,
      },
    );
    await target.request({ path: "/resource", actorId: actorIds.userA });
    await target.request({ path: "/app/resource", actorId: actorIds.userB });
    await expect(target.sessions.browserState(actorIds.userB)).resolves.toMatchObject({
      cookies: [
        {
          name: "session",
          value: "b-cookie",
          domain: "127.0.0.1",
          path: "/app",
        },
      ],
    });
    await expect(target.sessions.browserState(actorIds.administrator)).resolves.toMatchObject({
      localStorage: {
        role: "administrator",
        token: "Admin admin-token",
        email: "configured@example.test",
      },
    });
    expect(requests.at(-2)?.headers.get("authorization")).toBe("Bearer a-1");
    expect(requests.at(-1)?.headers.get("cookie")).toBe("session=b-cookie");

    await target.request({ path: "/application", actorId: actorIds.userB });
    expect(requests.at(-1)?.headers.get("cookie")).toBeNull();
    await target.request({ path: "/admin/resource", actorId: actorIds.administrator });
    expect(requests.at(-1)?.headers.get("cookie")).toBe("admin_session=Admin admin-token");

    now = 100;
    await target.request({ path: "/resource", actorId: actorIds.userA });
    expect(requests.find(({ path }) => path === "/refresh/a")?.body).toBe(
      JSON.stringify({ refresh: "refresh-a" }),
    );
    expect(requests.at(-1)?.headers.get("authorization")).toBe("Bearer a-2");
  });

  it("creates independent credentials when exploration and validation onboard separately", async () => {
    const manifest = multiPrincipalManifest();
    let loginSequence = 0;
    const makeTarget = () =>
      new ScopedTarget({
        target: new URL("http://127.0.0.1:8080"),
        requestBudget: 8,
        allowedRequests: [...(manifest.scope.setupOperations ?? [])],
        transport: async (input) => {
          const path = new URL(String(input)).pathname;
          if (path === "/login/a") {
            loginSequence += 1;
            return Response.json({ access: `a-${loginSequence}`, refresh: `r-${loginSequence}` });
          }
          if (path === "/login/b") {
            return new Response("{}", {
              headers: { "set-cookie": `session=b-${loginSequence}; Path=/` },
            });
          }
          if (path === "/login/admin") {
            return new Response("{}", { headers: { authorization: `Admin ${loginSequence}` } });
          }
          return Response.json({ access: "refreshed" });
        },
      });
    const exploration = makeTarget();
    const validation = makeTarget();

    await authenticateTargetManifest(exploration, manifest);
    await authenticateTargetManifest(validation, manifest, { actorIds: [actorIds.userA] });

    await expect(exploration.sessions.acquire(actorIds.userA)).resolves.toMatchObject({
      headers: { authorization: "Bearer a-1" },
    });
    await expect(validation.sessions.acquire(actorIds.userA)).resolves.toMatchObject({
      headers: { authorization: "Bearer a-2" },
    });
    await expect(validation.sessions.acquire(actorIds.userB)).rejects.toThrow(
      "no session for actor second-user",
    );
  });

  it("rejects undeclared authentication and protected-operation actors", () => {
    const manifest = multiPrincipalManifest();
    manifest.scope.setupOperations = manifest.scope.setupOperations?.filter(
      ({ path }) => path !== "/refresh/a",
    );
    manifest.scope.protectedOperations = [
      { method: "GET", path: "/root", authorizedActors: ["missing-actor"] },
    ];

    expect(() => assertValidTargetManifest(manifest)).toThrow("references unknown actor");
    manifest.scope.protectedOperations = [];
    expect(() => assertValidTargetManifest(manifest)).toThrow(
      "Authentication operation POST /refresh/a must be declared",
    );
  });
});
