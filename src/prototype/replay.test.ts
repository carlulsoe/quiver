import { describe, expect, it } from "vitest";
import { replayFinding } from "./replay.ts";
import { ScopedTarget } from "./scoped-target.ts";
import type { Finding } from "./state.ts";

describe("finding replay", () => {
  it("independently repeats every read-only request in the submitted plan", async () => {
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
      endpoint: "/items/other",
      resource: "other",
      rationale: "An unrelated item was returned.",
      reproduction: [
        { path: "/items/mine", authenticated: true },
        { path: "/items/other", authenticated: true },
      ],
    };

    await expect(replayFinding(target, finding)).resolves.toEqual({
      fingerprint: finding.fingerprint,
      observations: [
        { status: 200, path: "/items/mine", body: { path: "/items/mine" }, truncated: false },
        { status: 200, path: "/items/other", body: { path: "/items/other" }, truncated: false },
      ],
    });
  });
});
