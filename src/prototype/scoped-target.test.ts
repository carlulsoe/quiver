import { describe, expect, it } from "vitest";
import { ScopedTarget } from "./scoped-target.ts";
import { response } from "./scoped-target-test-support.ts";

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
      target.runProfileSetup("authentication", () =>
        target.request({ path: "/login", method: "POST" }),
      ),
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      target.runProfileSetup("authentication", () =>
        target.request({ path: "/other", method: "POST" }),
      ),
    ).rejects.toThrow("not a profile setup operation");
    await expect(
      target.runProfileSetup("authentication", () =>
        target.request({ path: "/synthetic-session", method: "DELETE" }),
      ),
    ).resolves.toMatchObject({ status: 200 });
  });
});
