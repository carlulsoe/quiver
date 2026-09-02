import { describe, expect, it } from "vitest";
import { replayFinding } from "./replay.ts";
import { ScopedTarget } from "./scoped-target.ts";
import type { Finding } from "./state.ts";

const baseFinding = {
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
} as const;

describe("finding REST replay", () => {
  it("independently repeats every REST request in the submitted plan", async () => {
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      transport: async (input) => Response.json({ path: new URL(String(input)).pathname }),
    });
    target.setSession("ordinary-user", { headers: { authorization: "Bearer opaque" } });
    const finding: Finding = {
      ...baseFinding,
      fingerprint: "broken-object-authorization:GET:/items/{id}",
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
    const result = await replayFinding(target, finding);
    expect(result.observations.map(({ path }) => path)).toEqual(["/items/mine", "/items/other"]);
    expect(result.artifacts).toEqual({
      browserEffects: [],
      browserStateTransitions: [],
      oastCallbacks: [],
    });
  });

  it("does not begin browser replay without the collector budget", async () => {
    let requests = 0;
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      transport: async () => {
        requests += 1;
        return Response.json({ stored: true });
      },
    });
    const finding: Finding = {
      ...baseFinding,
      fingerprint: "cross-site-scripting:POST:/comments",
      title: "Stored dialog",
      category: "cross-site-scripting",
      cwe: "CWE-79",
      endpoint: "/comments",
      method: "POST",
      reproduction: [{ path: "/comments", method: "POST", actorId: "anonymous", body: "{}" }],
      proof: {
        type: "browser-visible-effect",
        policyId: "comment-dialog",
        probeId: "old",
        marker: "old",
        requestIndex: 0,
        pagePath: "/comments/latest",
        kind: "dialog",
        challenge: { location: "json-body", parameter: "value", template: "{{challenge}}" },
        pageActorId: "anonymous",
        collectorRequestBudget: 2,
      },
    };
    await expect(replayFinding(target, finding)).rejects.toThrow("Validation requires 3 requests");
    expect(requests).toBe(0);
  });
});
