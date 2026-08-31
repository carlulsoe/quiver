import { describe, expect, it } from "vitest";
import { replayFinding } from "./replay.ts";
import { ScopedTarget } from "./scoped-target.ts";
import type { Finding } from "./state.ts";

describe("finding replay", () => {
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
    });
  });
});
