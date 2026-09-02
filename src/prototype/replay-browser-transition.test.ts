import { describe, expect, it } from "vitest";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { replayFinding } from "./replay.ts";
import { ScopedTarget } from "./scoped-target.ts";
import type { Finding } from "./state.ts";

describe("browser state-transition replay", () => {
  it("places a policy-owned cross-origin transition between exact state reads", async () => {
    await using artifacts = new ProofArtifactStore();
    let email = "before@example.test";
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 4,
      allowedRequests: [{ method: "POST", path: "/account/email" }],
      attackSurfaceOrigins: [{ origin: "http://127.0.0.1:9999", scope: "visit-only" }],
      transport: async () => Response.json({ email }),
      browserStateTransitionCollector: async (probe) => {
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
      rationale: "A cross-origin form changes state.",
      impact: "An attacker can change the email.",
      mitigation: "Require a CSRF token.",
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
      expect.objectContaining({ policyId: "email-csrf", status: 302 }),
    ]);
  });
});
