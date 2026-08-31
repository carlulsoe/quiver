import { describe, expect, it } from "vitest";
import { replayFinding } from "./replay.ts";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { ScopedTarget } from "./scoped-target.ts";
import type { Finding } from "./state.ts";

describe("finding replay", () => {
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
          authenticated: false,
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
        pageAuthenticated: false,
        collectorRequestBudget: 2,
      },
    };

    await expect(replayFinding(target, finding)).rejects.toThrow(
      "Validation requires 3 requests but only 2 remain",
    );
    expect(restRequests).toBe(0);
    expect(browserCollections).toBe(0);
  });

  it("preserves SPA fragments while refreshing reflected browser challenges", async () => {
    await using artifacts = new ProofArtifactStore();
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      transport: async () => Response.json({ rendered: true }),
      browserEffectCollector: async (probe) => {
        expect(probe.path).toMatch(/^\/app\?payload=QUIVER-BROWSER-[^#]+#\/preview$/);
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
      title: "Reflected dialog",
      category: "cross-site-scripting",
      severity: "high",
      cwe: "CWE-79",
      endpoint: "/app",
      method: "GET",
      resource: "preview",
      rationale: "A synthetic marker executes in the preview route.",
      impact: "Reflected script execution is possible.",
      mitigation: "Encode output for its rendering context.",
      reproduction: [{ path: "/app?payload=old#/preview", authenticated: false }],
      proof: {
        type: "browser-visible-effect",
        policyId: "preview-dialog",
        probeId: "old-probe",
        marker: "old",
        requestIndex: 0,
        pagePath: "/app?payload=old#/admin",
        kind: "dialog",
        challenge: { location: "query", parameter: "payload", template: "{{challenge}}" },
        pageAuthenticated: false,
        pageChallenge: { location: "query", parameter: "payload", template: "{{challenge}}" },
        collectorRequestBudget: 1,
      },
    };

    const replay = await replayFinding(target, finding, artifacts, [
      {
        id: "preview-dialog",
        kind: "browser-effect",
        category: "cross-site-scripting",
        description: "Reflected preview dialog.",
        effect: "dialog",
        markerPattern: "^QUIVER-BROWSER-",
        pagePath: "/app?payload=old#/preview",
        payloadTemplate: "{{challenge}}",
        challenge: { location: "query", parameter: "payload", template: "{{challenge}}" },
        pageAuthenticated: false,
        pageChallenge: { location: "query", parameter: "payload", template: "{{challenge}}" },
        requestBudget: 1,
      },
    ]);

    expect(replay.replayedFinding.reproduction[0]?.path).toMatch(/#\/preview$/);
    expect(
      replay.replayedFinding.proof.type === "browser-visible-effect"
        ? replay.replayedFinding.proof.pagePath
        : "",
    ).toMatch(/#\/preview$/);
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
    target.setAuthentication({ authorization: "Bearer opaque" });
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
        { path: "/items/mine", authenticated: true },
        { path: "/items/other", authenticated: true },
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
          authenticated: true,
          body: { path: "/items/mine" },
          truncated: false,
          durationMs: expect.any(Number),
        },
        {
          status: 200,
          method: "GET",
          path: "/items/other",
          authenticated: true,
          body: { path: "/items/other" },
          truncated: false,
          durationMs: expect.any(Number),
        },
      ],
      artifacts: { browserEffects: [], oastCallbacks: [] },
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
          authenticated: false,
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
