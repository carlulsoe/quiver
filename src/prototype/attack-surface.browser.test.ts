import { afterEach, describe, expect, it } from "vitest";
import { BrowserAttackSurfaceMapper } from "./attack-surface.ts";

const servers: Bun.Server<unknown>[] = [];

afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
});

describe("browser stateful discovery", () => {
  it("fills safe workflows, observes APIs and sockets, and keeps visit-only origins passive", async () => {
    let graphqlRequests = 0;
    let blockedWorkflowRequests = 0;
    let blockedVisitOnlyPosts = 0;
    let primaryAuthorization: string | null = null;
    let primarySocketAuthorization: string | null = null;
    let primaryCookie: string | null = null;
    let secondaryAuthorization: string | null = null;
    let secondaryCookie: string | null = null;
    let secondaryStoredValue: string | null = null;
    let secondaryVisibleCookie: string | null = null;
    let secondarySocketConnections = 0;
    let primaryLogoutRequests = 0;
    let destructiveWorkflowRequests = 0;
    let activeVisitOnlyGets = 0;
    let wrongSearchActions = 0;
    let searchSubmitterValue: string | null = null;
    let primaryOrigin = "";
    const secondary = Bun.serve({
      port: 0,
      websocket: {
        open() {
          secondarySocketConnections += 1;
        },
        message() {},
      },
      fetch(request, server) {
        const url = new URL(request.url);
        if (url.pathname === "/socket" && server.upgrade(request)) return;
        if (url.pathname === "/blocked") blockedVisitOnlyPosts += 1;
        if (url.pathname === "/active-get") activeVisitOnlyGets += 1;
        if (url.pathname === "/passive") {
          secondaryStoredValue = url.searchParams.get("stored");
          secondaryVisibleCookie = url.searchParams.get("cookie");
        }
        if (url.pathname === "/visitor") {
          secondaryAuthorization = request.headers.get("authorization");
          secondaryCookie = request.headers.get("cookie");
          return html(`
            <script>
              new WebSocket('ws://' + location.host + '/socket');
              const pixel = new Image();
              pixel.src = '/passive?stored=' + localStorage.getItem('primary-secret') + '&cookie=' + encodeURIComponent(document.cookie);
              fetch('/blocked', { method: 'POST', body: 'must-not-arrive' }).catch(() => {});
              fetch('${primaryOrigin}/logout').catch(() => {});
            </script>
            <form aria-label="Visitor lookup" action="/interact" method="get">
              <input name="query" placeholder="lookup">
              <button type="submit">Continue</button>
            </form>
          `);
        }
        return new Response("ok");
      },
    });
    servers.push(secondary);

    const primary = Bun.serve({
      port: 0,
      websocket: {
        open(socket) {
          socket.send("welcome");
        },
        message(socket, message) {
          socket.send(message);
        },
      },
      async fetch(request, server) {
        const url = new URL(request.url);
        if (url.pathname === "/socket") {
          primarySocketAuthorization = request.headers.get("authorization");
          if (server.upgrade(request)) return;
        }
        if (url.pathname === "/") {
          primaryAuthorization = request.headers.get("authorization");
          primaryCookie = request.headers.get("cookie");
          return html(`
            <script>
              const socket = new WebSocket('ws://' + location.host + '/socket');
              socket.addEventListener('open', () => socket.send('observe-only'));
              new WebSocket('ws://' + location.host + '/socket');
              fetch('http://127.0.0.1:${secondary.port}/active-get').catch(() => {});
            </script>
            <a href="http://127.0.0.1:${secondary.port}/visitor">Documentation</a>
            <form aria-label="Lookup remote documentation" action="http://127.0.0.1:${secondary.port}/interact" method="get">
              <input name="query">
              <button type="submit">Lookup</button>
            </form>
            <form aria-label="Search inventory" action="/wrong-search-action" method="post">
              <input name="query" placeholder="Search term">
              <button type="submit" name="workflow" value="inventory-search" formaction="/step" formmethod="get">Search</button>
            </form>
            <form aria-label="Upload evidence" action="/upload" method="post" enctype="multipart/form-data">
              <input name="description">
              <input name="attachment" type="file">
              <button type="submit">Upload</button>
            </form>
            <form aria-label="Upload alternate evidence" action="/upload" method="post" enctype="multipart/form-data">
              <input name="note">
              <input name="screenshot" type="file">
              <button type="submit">Upload alternate</button>
            </form>
          `);
        }
        if (url.pathname === "/step") {
          searchSubmitterValue = url.searchParams.get("workflow");
          return html(`
            <form aria-label="Delete account" action="/delete" method="post">
              <input name="confirm">
              <button type="submit">Delete</button>
            </form>
            <form aria-label="Continue account cancellation" action="/workflow/one" method="post">
              <input name="confirm">
              <button type="submit">Continue</button>
            </form>
            <form aria-label="Verify workspace closure" action="/workflow/two" method="post">
              <input name="confirm">
              <button type="submit">Verify</button>
            </form>
            <form aria-label="Continue profile deactivation" action="/workflow/three" method="post">
              <input name="confirm">
              <button type="submit">Continue</button>
            </form>
            <form aria-label="Verify subscription termination" action="/workflow/four" method="post">
              <input name="confirm">
              <button type="submit">Verify</button>
            </form>
            <form aria-label="Continue account deletion" action="/workflow/five" method="post">
              <input name="confirm">
              <button type="submit">Continue</button>
            </form>
            <form aria-label="Verify service suspension" action="/workflow/six" method="post">
              <input name="confirm">
              <button type="submit">Verify</button>
            </form>
            <form aria-label="Continue data archival" action="/workflow/seven" method="post">
              <input name="confirm">
              <button type="submit">Continue</button>
            </form>
            <form action="/logout" method="get">
              <input name="confirm">
              <button type="submit">Submit</button>
            </form>
            <form aria-label="Verify blocked workflow" action="/blocked-workflow" method="post">
              <input name="code">
              <button type="submit">Verify</button>
            </form>
            <form aria-label="Continue GraphQL workflow" action="/graphql" method="post">
              <textarea name="query">mutation SaveItem { saveItem(input: { name: "sample" }) { id } }</textarea>
              <button type="submit">Continue</button>
            </form>
          `);
        }
        if (url.pathname === "/graphql") {
          if (request.method === "POST") graphqlRequests += 1;
          return Response.json({ data: { saveItem: { id: "1" } } });
        }
        if (url.pathname === "/blocked-workflow") blockedWorkflowRequests += 1;
        if (url.pathname === "/wrong-search-action") wrongSearchActions += 1;
        if (url.pathname === "/logout") primaryLogoutRequests += 1;
        if (
          [
            "/workflow/one",
            "/workflow/two",
            "/workflow/three",
            "/workflow/four",
            "/workflow/five",
            "/workflow/six",
            "/workflow/seven",
          ].includes(url.pathname)
        )
          destructiveWorkflowRequests += 1;
        return new Response("ok");
      },
    });
    servers.push(primary);

    const decisions: Array<{ method: string; path: string; scope?: string; automatic?: boolean }> =
      [];
    const origin = `http://127.0.0.1:${primary.port}`;
    primaryOrigin = origin;
    const map = await new BrowserAttackSurfaceMapper({
      origin,
      startPath: "/",
      maxDocuments: 2,
      timeoutMs: 3_000,
      authenticationHeaders: { authorization: "Bearer primary-session" },
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

    expect(graphqlRequests).toBe(1);
    expect(blockedWorkflowRequests).toBe(0);
    expect(blockedVisitOnlyPosts).toBe(0);
    expect(primaryAuthorization).toBe("Bearer primary-session");
    expect(primarySocketAuthorization).toBe("Bearer primary-session");
    expect(primaryCookie).toBe("session=primary-cookie");
    expect(secondaryAuthorization).toBeNull();
    expect(secondaryCookie ?? "").not.toContain("primary-cookie");
    expect(secondaryStoredValue).toBe("null");
    expect(secondaryVisibleCookie).toBe("");
    expect(secondarySocketConnections).toBe(0);
    expect(primaryLogoutRequests).toBe(0);
    expect(destructiveWorkflowRequests).toBe(0);
    expect(activeVisitOnlyGets).toBe(0);
    expect(wrongSearchActions).toBe(0);
    expect(searchSubmitterValue).toBe("inventory-search");
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

function html(body: string): Response {
  return new Response(`<!doctype html><html><body>${body}</body></html>`, {
    headers: { "content-type": "text/html" },
  });
}
