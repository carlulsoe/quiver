import { afterEach, describe, expect, it } from "vitest";
import { BrowserAttackSurfaceMapper } from "./attack-surface.ts";
import { createBrowserFixture } from "./attack-surface-browser-fixture.ts";

const servers: Bun.Server<unknown>[] = [];

afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
});
describe("browser stateful discovery", () => {
  it("fills safe workflows, observes APIs and sockets, and keeps visit-only origins passive", async () => {
    const { primary, secondary, state } = createBrowserFixture(servers);

    const decisions: Array<{ method: string; path: string; scope?: string; automatic?: boolean }> =
      [];
    const origin = `http://127.0.0.1:${primary.port}`;
    state.primaryOrigin = origin;
    const map = await new BrowserAttackSurfaceMapper({
      origin,
      startPath: "/",
      maxDocuments: 2,
      timeoutMs: 3_000,
      authenticationHeaders: {
        authorization: "Bearer primary-session",
        xApiKey: "primary-api-key",
      },
      localStorage: { "primary-secret": "must-not-cross-origins" },
      cookies: [{ name: "session", value: "primary-cookie", url: origin }],
      origins: [{ origin: `http://127.0.0.1:${secondary.port}`, scope: "visit-only" }],
      decideRequest(method, path, metadata) {
        decisions.push({
          method,
          path,
          scope: metadata?.scope,
          automatic: metadata?.automaticInteraction,
        });
        return path === "/blocked-workflow"
          ? { allowed: false, reason: "not preauthorized" }
          : { allowed: true };
      },
    }).map();

    expect(state.graphqlRequests).toBe(1);
    expect(state.blockedWorkflowRequests).toBe(0);
    expect(state.blockedVisitOnlyPosts).toBe(0);
    expect(state.primaryAuthorization).toBe("Bearer primary-session");
    expect(state.primaryApiKey).toBe("primary-api-key");
    expect(state.primarySocketAuthorization).toBe("Bearer primary-session");
    expect(state.primaryCookie).toBe("session=primary-cookie");
    expect(state.secondaryAuthorization).toBeNull();
    expect(state.secondaryApiKey).toBeNull();
    expect(state.secondaryCookie ?? "").not.toContain("primary-cookie");
    expect(state.secondaryStoredValue).toBe("null");
    expect(state.secondaryVisibleCookie).toBe("");
    expect(state.secondarySocketConnections).toBe(0);
    expect(state.primaryLogoutRequests).toBe(0);
    expect(state.destructiveWorkflowRequests).toBe(0);
    expect(state.activeVisitOnlyGets).toBe(0);
    expect(state.wrongSearchActions).toBe(0);
    expect(state.searchSubmitterValue).toBe("inventory-search");
    expect(decisions).toContainEqual(
      expect.objectContaining({ method: "POST", path: "/graphql", automatic: true }),
    );
    expect(map.forms).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          intent: expect.stringContaining("Search inventory"),
          submitted: true,
        }),
        expect.objectContaining({
          action: `${origin}/upload`,
          fileFields: ["attachment"],
          submitted: false,
        }),
        expect.objectContaining({
          intent: expect.stringContaining("Delete account"),
          submitted: false,
        }),
        expect.objectContaining({ action: `${origin}/logout`, submitted: false }),
        expect.objectContaining({ action: `${origin}/workflow/one`, submitted: false }),
        expect.objectContaining({ action: `${origin}/workflow/two`, submitted: false }),
        expect.objectContaining({ action: `${origin}/workflow/three`, submitted: false }),
        expect.objectContaining({ action: `${origin}/workflow/four`, submitted: false }),
        expect.objectContaining({ action: `${origin}/workflow/five`, submitted: false }),
        expect.objectContaining({ action: `${origin}/workflow/six`, submitted: false }),
        expect.objectContaining({ action: `${origin}/workflow/seven`, submitted: false }),
        expect.objectContaining({
          action: `${origin}/blocked-workflow`,
          attempted: true,
          submitted: false,
        }),
        expect.objectContaining({
          action: `http://127.0.0.1:${secondary.port}/interact`,
          submitted: false,
        }),
      ]),
    );
    expect(map.forms?.filter((form) => form.action === `${origin}/upload`)).toHaveLength(2);
    expect(map.routeDetails).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: "/graphql",
          methods: ["POST"],
          requestBodies: [
            expect.objectContaining({
              contentType: "application/x-www-form-urlencoded",
              fields: ["query"],
            }),
          ],
          graphqlOperations: [{ type: "mutation", name: "SaveItem", rootFields: ["saveItem"] }],
        }),
        expect.objectContaining({
          path: "/upload",
          requestBodies: expect.arrayContaining([
            expect.objectContaining({
              contentType: "multipart/form-data",
              fields: ["description"],
              files: [{ field: "attachment" }],
            }),
            expect.objectContaining({
              contentType: "multipart/form-data",
              fields: ["note"],
              files: [{ field: "screenshot" }],
            }),
          ]),
        }),
        expect.objectContaining({
          path: `http://127.0.0.1:${secondary.port}/blocked`,
          scope: "visit-only",
          callSites: [expect.objectContaining({ allowed: false })],
        }),
        expect.objectContaining({
          path: `http://127.0.0.1:${secondary.port}/active-get`,
          callSites: [expect.objectContaining({ allowed: false })],
        }),
        expect.objectContaining({
          path: "/logout",
          callSites: [
            expect.objectContaining({
              allowed: false,
              blockedReason: "blocked by discovery origin scope",
            }),
          ],
        }),
      ]),
    );
    const primarySockets = map.webSockets?.filter((socket) => socket.origin === origin) ?? [];
    expect(primarySockets).toHaveLength(2);
    expect(primarySockets).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: "/socket", scope: "attackable", sentFrames: 1 }),
        expect.objectContaining({ path: "/socket", scope: "attackable", sentFrames: 0 }),
      ]),
    );
    expect(
      primarySockets.reduce((total, socket) => total + socket.receivedFrames, 0),
    ).toBeGreaterThanOrEqual(2);
    expect(map.webSockets).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          origin: `http://127.0.0.1:${secondary.port}`,
          path: "/socket",
          scope: "visit-only",
          sentFrames: 0,
          receivedFrames: 0,
        }),
      ]),
    );
  }, 40_000);
});
