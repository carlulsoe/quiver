import { describe, expect, it } from "vitest";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { replayFinding } from "./replay.ts";
import { ScopedTarget } from "./scoped-target.ts";
import type { Finding } from "./state.ts";

describe("finding browser replay", () => {
  it("refreshes a fragment-only DOM-XSS challenge", async () => {
    await using artifacts = new ProofArtifactStore();
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      transport: async () => Response.json({ rendered: true }),
      browserEffectCollector: async (probe) => ({
        probeId: probe.probeId,
        path: probe.path,
        kind: probe.kind,
        value: probe.marker,
      }),
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
      rationale: "A marker executes.",
      impact: "Script execution.",
      mitigation: "Encode output.",
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
    expect(replay.artifacts.browserEffects).toHaveLength(1);
  });
});
