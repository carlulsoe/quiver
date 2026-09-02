import { describe, expect, it } from "vitest";
import type { ProofPolicy } from "./target-profile.ts";
import { evaluateWithPolicy, observation, policyFinding } from "./proof-policy-test-helpers.ts";

describe("target-owned state proof policies", () => {
  it("confirms an exact protected state transition declared by the profile", () => {
    const finding = policyFinding(
      "business-logic",
      "/settings/email",
      "POST",
      [
        { path: "/settings", actorId: "ordinary-user" },
        {
          path: "/settings/email",
          method: "POST",
          body: '{"public":true}',
          actorId: "ordinary-user",
        },
        { path: "/settings", actorId: "ordinary-user" },
      ],
      {
        type: "state-transition",
        policyId: "email-public",
        transitionRequestIndex: 1,
        beforeRequestIndex: 0,
        afterRequestIndex: 2,
      },
    );
    const policy: ProofPolicy = {
      id: "email-public",
      kind: "state-transition",
      category: "business-logic",
      description: "Email visibility must not change through this operation.",
      endpoint: "/settings/email",
      method: "POST",
      jsonPointer: "/emailPublic",
      before: false,
      after: true,
      readEndpoint: "/settings",
      readMethod: "GET",
    };

    expect(
      evaluateWithPolicy(
        finding,
        [
          observation("/settings", { emailPublic: false }),
          observation("/settings/email", { ok: true }, "POST"),
          observation("/settings", { emailPublic: true }),
        ],
        policy,
        { stateResetAvailable: true },
      ).passed,
    ).toBe(true);
    expect(
      evaluateWithPolicy(
        finding,
        [
          { ...observation("/settings", { emailPublic: false }), status: 500 },
          observation("/settings/email", { ok: true }, "POST"),
          observation("/settings", { emailPublic: true }),
        ],
        policy,
        { stateResetAvailable: true },
      ).passed,
    ).toBe(false);
    expect(
      evaluateWithPolicy(
        {
          ...finding,
          proof: {
            type: "state-transition",
            policyId: "email-public",
            beforeRequestIndex: 2,
            transitionRequestIndex: 1,
            afterRequestIndex: 0,
          },
        },
        [
          observation("/settings", { emailPublic: false }),
          observation("/settings/email", { ok: true }, "POST"),
          observation("/settings", { emailPublic: true }),
        ],
        policy,
        { stateResetAvailable: true },
      ).passed,
    ).toBe(false);
    expect(
      evaluateWithPolicy(
        {
          ...finding,
          reproduction: [
            { path: "/settings?account=a", actorId: "ordinary-user" },
            finding.reproduction[1]!,
            { path: "/settings?account=b", actorId: "ordinary-user" },
          ],
        },
        [
          observation("/settings?account=a", { emailPublic: false }),
          observation("/settings/email", { ok: true }, "POST"),
          observation("/settings?account=b", { emailPublic: true }),
        ],
        policy,
        { stateResetAvailable: true },
      ).passed,
    ).toBe(false);
    expect(
      evaluateWithPolicy(
        {
          ...finding,
          reproduction: [
            finding.reproduction[0]!,
            { path: "/settings/other", method: "POST", actorId: "ordinary-user" },
            finding.reproduction[1]!,
            finding.reproduction[2]!,
          ],
          proof: {
            type: "state-transition",
            policyId: "email-public",
            beforeRequestIndex: 0,
            transitionRequestIndex: 2,
            afterRequestIndex: 3,
          },
        },
        [
          observation("/settings", { emailPublic: false }),
          observation("/settings/other", { changed: true }, "POST"),
          observation("/settings/email", { ok: true }, "POST"),
          observation("/settings", { emailPublic: true }),
        ],
        policy,
        { stateResetAvailable: true },
      ).passed,
    ).toBe(false);
  });
});
