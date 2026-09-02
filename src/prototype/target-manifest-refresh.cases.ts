import { describe, expect, it, vi } from "vitest";
import { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import { authenticateTargetManifest, type TargetManifest } from "./target-manifest.ts";

import { multiPrincipalManifest } from "./target-manifest-test-helpers.ts";

describe("declarative target onboarding refresh", () => {
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

  it("refreshes principals independently and coalesces concurrent refreshes per actor", async () => {
    const refreshable = (actor: "a" | "b") => ({
      kind: "header-token" as const,
      login: {
        request: { method: "POST" as const, path: `/login/${actor}` },
        credential: { location: "body" as const, pointer: "/access" },
        refreshCredential: { location: "body" as const, pointer: "/refresh" },
        expiresAfterMs: 100,
      },
      refresh: {
        request: {
          method: "POST" as const,
          path: `/refresh/${actor}`,
          headers: { authorization: "Refresh {{refreshCredential}}" },
        },
        credential: { location: "body" as const, pointer: "/access" },
        expiresAfterMs: 100,
      },
    });
    const manifest: TargetManifest = {
      schemaVersion: 1,
      id: "independent-refresh",
      displayName: "Independent refresh",
      objective: "Keep each principal's refresh state isolated.",
      scope: {
        setupOperations: [
          { method: "POST", path: "/login/a" },
          { method: "POST", path: "/refresh/a" },
          { method: "POST", path: "/login/b" },
          { method: "POST", path: "/refresh/b" },
        ],
      },
      identities: [
        { id: actorIds.anonymous, label: "Anonymous", role: "anonymous" },
        {
          id: actorIds.userA,
          label: "User A",
          role: "user",
          authentication: refreshable("a"),
        },
        {
          id: actorIds.userB,
          label: "User B",
          role: "user",
          authentication: refreshable("b"),
        },
      ],
    };
    let now = 0;
    const requests: Array<{ path: string; authorization: string | null }> = [];
    const transport = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const path = new URL(String(input)).pathname;
      const authorization = new Headers(init?.headers).get("authorization");
      requests.push({ path, authorization });
      if (path === "/login/a") return Response.json({ access: "a-1", refresh: "refresh-a" });
      if (path === "/login/b") return Response.json({ access: "b-1", refresh: "refresh-b" });
      if (path === "/refresh/a") return Response.json({ access: "a-2" });
      if (path === "/refresh/b") return Response.json({ access: "b-2" });
      return Response.json({ ok: true });
    });
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8080"),
      requestBudget: 10,
      allowedRequests: [...(manifest.scope.setupOperations ?? [])],
      transport,
    });
    await authenticateTargetManifest(target, manifest, { now: () => now });

    now = 100;
    await Promise.all([
      target.request({ path: "/resource/a/1", actorId: actorIds.userA }),
      target.request({ path: "/resource/a/2", actorId: actorIds.userA }),
      target.request({ path: "/resource/b/1", actorId: actorIds.userB }),
      target.request({ path: "/resource/b/2", actorId: actorIds.userB }),
    ]);

    expect(requests.filter(({ path }) => path === "/refresh/a")).toEqual([
      { path: "/refresh/a", authorization: "Refresh refresh-a" },
    ]);
    expect(requests.filter(({ path }) => path === "/refresh/b")).toEqual([
      { path: "/refresh/b", authorization: "Refresh refresh-b" },
    ]);
    expect(requests.filter(({ path }) => path.startsWith("/resource/a/"))).toEqual([
      { path: "/resource/a/1", authorization: "Bearer a-2" },
      { path: "/resource/a/2", authorization: "Bearer a-2" },
    ]);
    expect(requests.filter(({ path }) => path.startsWith("/resource/b/"))).toEqual([
      { path: "/resource/b/1", authorization: "Bearer b-2" },
      { path: "/resource/b/2", authorization: "Bearer b-2" },
    ]);
  });
});
