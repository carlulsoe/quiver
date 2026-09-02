import { afterEach, vi } from "vitest";
import { actorIds } from "./sessions.ts";
import type { TargetManifest } from "./target-manifest.ts";

afterEach(() => vi.unstubAllEnvs());

export function multiPrincipalManifest(): TargetManifest {
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
              headers: { authorization: "Refresh {{refreshCredential}}" },
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
