import { describe, expect, it, vi } from "vitest";
import { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import { assertValidTargetManifest, authenticateTargetManifest } from "./target-manifest.ts";

import { multiPrincipalManifest } from "./target-manifest-test-helpers.ts";

describe("declarative target onboarding sessions", () => {
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
    expect(requests.find(({ path }) => path === "/refresh/a")?.headers.get("authorization")).toBe(
      "Refresh refresh-a",
    );
    expect(requests.at(-1)?.headers.get("authorization")).toBe("Bearer a-2");
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

    const unsafePath = multiPrincipalManifest();
    const userA = unsafePath.identities.find(({ id }) => id === actorIds.userA);
    if (!userA?.authentication?.refresh) throw new Error("Expected user A refresh fixture");
    userA.authentication.refresh.request.path = "/refresh/a?token={{refreshCredential}}";
    unsafePath.scope.setupOperations = [
      ...(unsafePath.scope.setupOperations ?? []),
      { method: "POST", path: userA.authentication.refresh.request.path },
    ];
    expect(() => assertValidTargetManifest(unsafePath)).toThrow(
      "authentication request paths must be static",
    );
  });
});
