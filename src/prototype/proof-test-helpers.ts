import { actorIds } from "./sessions.ts";
import type { Finding, ValidationObservation } from "./state.ts";

export const identities = [
  { id: actorIds.anonymous, label: "Anonymous", role: "anonymous" as const },
  { id: actorIds.userA, label: "User A", role: "user" as const },
  { id: actorIds.userB, label: "User B", role: "user" as const },
  { id: actorIds.administrator, label: "Administrator", role: "administrator" as const },
];

export function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    fingerprint: "broken-object-authorization:GET:/orders/{id}",
    agentId: "explorer-1",
    title: "Cross-owner order",
    category: "broken-object-authorization",
    severity: "high",
    cwe: "CWE-639",
    endpoint: "/orders/{id}",
    resource: "order 7",
    rationale: "Another principal's order was returned.",
    impact: "Order data is disclosed.",
    mitigation: "Authorize each lookup.",
    reproduction: [
      { path: "/me", actorId: "ordinary-user" },
      { path: "/orders/7", actorId: "ordinary-user" },
    ],
    proof: {
      type: "cross-principal-access",
      actor: { requestIndex: 0, jsonPointer: "/email" },
      resourceOwner: { requestIndex: 1, jsonPointer: "/order/user/email" },
      accessRequestIndex: 1,
      evidencePointers: ["/order/id"],
    },
    ...overrides,
  };
}

export function observation<Body>(
  path: string,
  body: Body,
  overrides: Partial<ValidationObservation> = {},
): ValidationObservation {
  return { status: 200, path, actorId: "ordinary-user", body, truncated: false, ...overrides };
}

export function sqlDifferentialFinding(): Finding {
  return finding({
    category: "sql-injection",
    endpoint: "/search",
    reproduction: [
      { path: "/search?q=control", actorId: "anonymous" },
      { path: "/search?q=%27", actorId: "anonymous" },
    ],
    proof: {
      type: "response-differential",
      controlRequestIndex: 0,
      probeRequestIndex: 1,
      comparison: "json-value",
      expectation: "different",
      jsonPointer: "/error/code",
      mutation: {
        location: "query",
        parameter: "q",
        controlValue: "control",
        probeValue: "'",
      },
    },
  });
}
