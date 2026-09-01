import { describe, expect, it } from "vitest";
import { impactSafetyChecks, requiredImpactLevel } from "./impact.ts";
import type { Finding } from "./state.ts";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    fingerprint: "security-misconfiguration:GET:/status",
    agentId: "explorer-1",
    title: "Status disclosure",
    category: "security-misconfiguration",
    severity: "low",
    cwe: "CWE-200",
    endpoint: "/status",
    method: "GET",
    resource: "status",
    rationale: "Internal status is public.",
    impact: "Internal details are disclosed.",
    mitigation: "Require authorization.",
    impactLevel: "observation",
    reproduction: [{ path: "/status", authenticated: false }],
    proof: { type: "unauthenticated-success", requestIndex: 0, evidencePointers: ["/build"] },
    ...overrides,
  };
}

describe("impact demonstration safety", () => {
  it("derives levels from behavior and enforces the target ceiling", () => {
    const read = finding();
    expect(requiredImpactLevel(read)).toBe("observation");
    expect(impactSafetyChecks(read, "observation").every(({ passed }) => passed)).toBe(true);

    const active = finding({
      method: "POST",
      impactLevel: "state-change",
      reproduction: [{ path: "/status", method: "POST", authenticated: false }],
    });
    expect(requiredImpactLevel(active)).toBe("state-change");
    expect(impactSafetyChecks(active, "observation").some(({ passed }) => !passed)).toBe(true);
    expect(impactSafetyChecks(active, "state-change").every(({ passed }) => passed)).toBe(true);
  });

  it("always rejects DELETE and understated levels", () => {
    const findingWithDelete = finding({
      method: "DELETE",
      reproduction: [{ path: "/status", method: "DELETE", authenticated: false }],
    });
    const checks = impactSafetyChecks(findingWithDelete, "state-change");
    expect(checks.filter(({ passed }) => !passed).map(({ description }) => description)).toEqual([
      "declared impact level matches the code-derived state-change level",
      "impact demonstration never uses DELETE",
    ]);
  });
});
