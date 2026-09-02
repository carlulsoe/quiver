import { describe, expect, it } from "vitest";
import { object, parse, string } from "valibot";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { replayFinding } from "./replay.ts";
import { ScopedTarget } from "./scoped-target.ts";
import type { Finding } from "./state.ts";

describe("finding OAST replay", () => {
  it("mints and binds a fresh OAST challenge", async () => {
    await using artifacts = new ProofArtifactStore();
    const original = artifacts.issueOastProbe();
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
      allowedRequests: [{ method: "POST", path: "/preview/{name}" }],
      transport: async (_input, init) => {
        const body = parse(object({ url: string() }), JSON.parse(String(init?.body)));
        await fetch(body.url, { method: "POST" });
        return Response.json({ queued: true });
      },
    });
    const finding: Finding = {
      fingerprint: "server-side-request-forgery:POST:/preview",
      agentId: "explorer-1",
      title: "Preview callback",
      category: "server-side-request-forgery",
      severity: "high",
      cwe: "CWE-918",
      endpoint: "/preview/{name}",
      method: "POST",
      resource: "preview URL",
      rationale: "The server fetched a callback.",
      impact: "Internal requests.",
      mitigation: "Allowlist destinations.",
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
    expect(replay.artifacts.oastCallbacks).toHaveLength(1);
  });
});
