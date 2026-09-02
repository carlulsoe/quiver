import { describe, expect, it } from "vitest";
import { replayFinding } from "./replay.ts";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { ScopedTarget } from "./scoped-target.ts";
import type { Finding } from "./state.ts";

describe("finding replay", () => {
  it("places a policy-owned cross-origin browser transition between exact state reads", async () => {
    await using artifacts = new ProofArtifactStore();
    let email = "before@example.test";
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 4,
      allowedRequests: [{ method: "POST", path: "/account/email" }],
      attackSurfaceOrigins: [{ origin: "http://127.0.0.1:9999", scope: "visit-only" }],
      transport: async () => Response.json({ email }),
      browserStateTransitionCollector: async (probe) => {
        expect(probe.cookies).toEqual([
          { name: "session", value: "victim", url: "http://127.0.0.1:8888" },
        ]);
        expect(probe.decideRequest("GET", new URL("http://127.0.0.1:9999/csrf/email"))).toBe(true);
        expect(probe.decideRequest("POST", new URL("http://127.0.0.1:8888/account/email"))).toBe(
          true,
        );
        email = "after@example.test";
        return {
          policyId: probe.policyId,
          sourceOrigin: probe.sourceOrigin,
          sourcePath: probe.sourcePath,
          targetPath: probe.targetPath,
          method: probe.method,
          status: 302,
        };
      },
    });
    target.setSession("ordinary-user", {
      browserState: {
        cookies: [{ name: "session", value: "victim", url: "http://127.0.0.1:8888" }],
      },
    });
    const finding: Finding = {
      fingerprint: "cross-site-request-forgery:POST:/account/email",
      agentId: "explorer-1",
      title: "Cross-origin email update",
      category: "cross-site-request-forgery",
      severity: "high",
      cwe: "CWE-352",
      endpoint: "/account/email",
      method: "POST",
      resource: "account email",
      rationale: "A cross-origin form changes authenticated state.",
      impact: "An attacker can change the victim's email.",
      mitigation: "Require a CSRF token and validate Origin.",
      reproduction: [
        { path: "/account", actorId: "ordinary-user", sampleId: "before" },
        { path: "/account", actorId: "ordinary-user", sampleId: "after" },
      ],
      proof: {
        type: "browser-state-transition",
        policyId: "email-csrf",
        beforeRequestIndex: 0,
        afterRequestIndex: 1,
        pageActorId: "ordinary-user",
        collectorRequestBudget: 2,
      },
    };

    const replay = await replayFinding(target, finding, artifacts, [
      {
        id: "email-csrf",
        kind: "browser-state-transition",
        category: "cross-site-request-forgery",
        description: "Cross-origin email fixture.",
        endpoint: "/account/email",
        method: "POST",
        sourceOrigin: "http://127.0.0.1:9999",
        sourcePath: "/csrf/email",
        pageActorId: "ordinary-user",
        requestBudget: 2,
        readEndpoint: "/account",
        readMethod: "GET",
        jsonPointer: "/email",
        before: "before@example.test",
        after: "after@example.test",
      },
    ]);

    expect(replay.observations.map(({ body }) => body)).toEqual([
      { email: "before@example.test" },
      { email: "after@example.test" },
    ]);
    expect(replay.artifacts.browserStateTransitions).toEqual([
      {
        policyId: "email-csrf",
        sourceOrigin: "http://127.0.0.1:9999",
        sourcePath: "/csrf/email",
        targetPath: "/account/email",
        method: "POST",
        status: 302,
      },
    ]);
  });

  it("does not begin a browser replay without capacity for its declared collector budget", async () => {
    let restRequests = 0;
    let browserCollections = 0;
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      allowedRequests: [{ method: "POST", path: "/comments" }],
      transport: async () => {
        restRequests += 1;
        return Response.json({ stored: true });
      },
      browserEffectCollector: async () => {
        browserCollections += 1;
        return undefined;
      },
    });
    const finding: Finding = {
      fingerprint: "cross-site-scripting:POST:/comments",
      agentId: "explorer-1",
      title: "Stored dialog",
      category: "cross-site-scripting",
      severity: "high",
      cwe: "CWE-79",
      endpoint: "/comments",
      method: "POST",
      resource: "comment",
      rationale: "A synthetic marker executes in the browser.",
      impact: "Stored script execution is possible.",
      mitigation: "Encode output for its rendering context.",
      reproduction: [
        {
          path: "/comments",
          method: "POST",
          actorId: "anonymous",
          body: JSON.stringify({ value: '<script>alert("old")</script>' }),
        },
      ],
      proof: {
        type: "browser-visible-effect",
        policyId: "comment-dialog",
        probeId: "old-probe",
        marker: "old",
        requestIndex: 0,
        pagePath: "/comments/latest",
        kind: "dialog",
        challenge: {
          location: "json-body",
          parameter: "value",
          template: '<script>alert("{{challenge}}")</script>',
        },
        pageActorId: "anonymous",
        collectorRequestBudget: 2,
      },
    };

    await expect(replayFinding(target, finding)).rejects.toThrow(
      "Validation requires 3 requests but only 2 remain",
    );
    expect(restRequests).toBe(0);
    expect(browserCollections).toBe(0);
  });

  it("refreshes a fragment-only DOM-XSS challenge", async () => {
    await using artifacts = new ProofArtifactStore();
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      transport: async () => Response.json({ rendered: true }),
      browserEffectCollector: async (probe) => {
        expect(probe.path).toMatch(/^\/app#payload=QUIVER-BROWSER-/);
        expect(probe.decideRequest("GET", "/app")).toBe(true);
        return {
          probeId: probe.probeId,
          path: probe.path,
          kind: probe.kind,
          value: probe.marker,
        };
      },
    });
    const finding: Finding = {
      fingerprint: "cross-site-scripting:GET:/app",
      agentId: "explorer-1",
      title: "DOM dialog",
      category: "cross-site-scripting",
      severity: "high",
      cwe: "CWE-79",
      endpoint: "/app",
      method: "GET",
      resource: "preview",
      rationale: "A synthetic marker executes in the preview route.",
      impact: "Reflected script execution is possible.",
      mitigation: "Encode output for its rendering context.",
      reproduction: [{ path: "/app#payload=old", actorId: "anonymous" }],
      proof: {
        type: "browser-visible-effect",
        policyId: "preview-dialog",
        probeId: "old-probe",
        marker: "old",
        requestIndex: 0,
        pagePath: "/app#payload=old",
        kind: "dialog",
        challenge: { location: "fragment", parameter: "payload", template: "{{challenge}}" },
        pageActorId: "anonymous",
        pageChallenge: { location: "fragment", parameter: "payload", template: "{{challenge}}" },
        collectorRequestBudget: 1,
      },
    };

    const replay = await replayFinding(target, finding, artifacts, [
      {
        id: "preview-dialog",
        kind: "browser-effect",
        category: "cross-site-scripting",
        workflow: "dom",
        endpoint: "/app",
        method: "GET",
        description: "DOM preview dialog.",
        effect: "dialog",
        markerPattern: "^QUIVER-BROWSER-",
        pagePath: "/app#payload=old",
        payloadTemplate: "{{challenge}}",
        challenge: { location: "fragment", parameter: "payload", template: "{{challenge}}" },
        submissionActorId: "anonymous",
        pageActorId: "anonymous",
        pageChallenge: { location: "fragment", parameter: "payload", template: "{{challenge}}" },
        requestBudget: 1,
      },
    ]);

    expect(replay.replayedFinding.reproduction[0]?.path).toMatch(/#payload=QUIVER-BROWSER-/);
    expect(
      replay.replayedFinding.proof.type === "browser-visible-effect"
        ? replay.replayedFinding.proof.pagePath
        : "",
    ).toMatch(/#payload=QUIVER-BROWSER-/);
  });

  it("independently repeats every REST request in the submitted plan", async () => {
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      transport: async (input) =>
        new Response(JSON.stringify({ path: new URL(String(input)).pathname }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    target.setSession("ordinary-user", { headers: { authorization: "Bearer opaque" } });
    const finding: Finding = {
      fingerprint: "broken-object-authorization:GET:/items/{id}",
      agentId: "explorer-1",
      title: "Cross-owner item",
      category: "broken-object-authorization",
      severity: "high",
      cwe: "CWE-639",
      endpoint: "/items/other",
      resource: "other",
      rationale: "An unrelated item was returned.",
      impact: "Another user's item is disclosed.",
      mitigation: "Authorize object access against the current principal.",
      reproduction: [
        { path: "/items/mine", actorId: "ordinary-user" },
        { path: "/items/other", actorId: "ordinary-user" },
      ],
      proof: {
        type: "cross-principal-access",
        actor: { requestIndex: 0, jsonPointer: "/owner" },
        resourceOwner: { requestIndex: 1, jsonPointer: "/owner" },
        accessRequestIndex: 1,
        evidencePointers: ["/path"],
      },
    };

    await expect(replayFinding(target, finding)).resolves.toEqual({
      fingerprint: finding.fingerprint,
      replayedFinding: finding,
      observations: [
        {
          status: 200,
          method: "GET",
          path: "/items/mine",
          actorId: "ordinary-user",
          body: { path: "/items/mine" },
          truncated: false,
          contentType: "application/json",
          redirected: false,
          durationMs: expect.any(Number),
        },
        {
          status: 200,
          method: "GET",
          path: "/items/other",
          actorId: "ordinary-user",
          body: { path: "/items/other" },
          truncated: false,
          contentType: "application/json",
          redirected: false,
          durationMs: expect.any(Number),
        },
      ],
      artifacts: { browserEffects: [], browserStateTransitions: [], oastCallbacks: [] },
    });
  });

  it("mints and binds a fresh OAST challenge for independent replay", async () => {
    await using artifacts = new ProofArtifactStore();
    const original = artifacts.issueOastProbe();
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
      allowedRequests: [{ method: "POST", path: "/preview/{name}" }],
      transport: async (_input, init) => {
        const body = JSON.parse(String(init?.body)) as { url: string };
        await fetch(body.url, { method: "POST" });
        return Response.json({ queued: true });
      },
    });
    const finding: Finding = {
      fingerprint: "server-side-request-forgery:POST:/preview",
      agentId: "explorer-1",
      title: "Preview fetch callback",
      category: "server-side-request-forgery",
      severity: "high",
      cwe: "CWE-918",
      endpoint: "/preview/{name}",
      method: "POST",
      resource: "preview URL",
      rationale: "The server fetched a supplied callback URL.",
      impact: "Internal network requests may be possible.",
      mitigation: "Allowlist preview destinations.",
      reproduction: [
        {
          path: "/preview/report",
          method: "POST",
          actorId: "anonymous",
          body: JSON.stringify({ url: original.url }),
        },
      ],
      proof: {
        type: "oast-callback",
        policyId: "preview-fetch",
        probeId: original.probeId,
        token: original.token,
        callbackUrl: original.url,
        requestIndex: 0,
        challenge: { location: "json-body", parameter: "url", template: "{{challenge}}" },
      },
    };

    const replay = await replayFinding(target, finding, artifacts, [
      {
        id: "preview-fetch",
        kind: "oast",
        category: "server-side-request-forgery",
        description: "Preview callback.",
        protocol: "http",
        endpoint: "/preview/{name}",
        method: "POST",
        challenge: { location: "json-body", parameter: "url", template: "{{challenge}}" },
      },
    ]);

    expect(replay.replayedFinding.proof).toMatchObject({
      type: "oast-callback",
      token: expect.not.stringMatching(original.token),
    });
    expect(replay.artifacts.oastCallbacks).toEqual([
      expect.objectContaining({
        probeId: (replay.replayedFinding.proof as { probeId: string }).probeId,
        token: (replay.replayedFinding.proof as { token: string }).token,
      }),
    ]);
  });
});
