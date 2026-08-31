import { describe, expect, it } from "vitest";
import { evaluateProof } from "./proof.ts";
import type { Finding, ValidationObservation } from "./state.ts";

function finding(overrides: Partial<Finding> = {}): Finding {
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
      { path: "/me", authenticated: true },
      { path: "/orders/7", authenticated: true },
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

function observation(
  path: string,
  body: unknown,
  overrides: Partial<ValidationObservation> = {},
): ValidationObservation {
  return { status: 200, path, authenticated: true, body, truncated: false, ...overrides };
}

describe("deterministic finding proof", () => {
  it("confirms successful access when actor and resource owner differ", () => {
    const result = evaluateProof(finding(), [
      observation("/me", { email: "actor@example.com" }),
      observation("/orders/7", { order: { id: 7, user: { email: "owner@example.com" } } }),
    ]);

    expect(result.passed).toBe(true);
    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          description: "actor and resource owner are different principals",
          passed: true,
        }),
      ]),
    );
  });

  it("rejects same-owner, missing, unsuccessful, or truncated BOLA evidence", () => {
    const result = evaluateProof(finding(), [
      observation("/me", { email: "same@example.com" }),
      observation(
        "/orders/7",
        { order: { id: 7, user: { email: "same@example.com" } } },
        { status: 403, truncated: true },
      ),
    ]);

    expect(result.passed).toBe(false);
    expect(
      result.checks.filter(({ passed }) => !passed).map(({ description }) => description),
    ).toEqual(
      expect.arrayContaining([
        "proof responses were not truncated",
        "actor and resource owner are different principals",
        "cross-principal request returned a successful response",
      ]),
    );
  });

  it("confirms anonymous success only for an actually anonymous request with declared fields", () => {
    const anonymousFinding = finding({
      category: "security-misconfiguration",
      reproduction: [{ path: "/orders/7", authenticated: false }],
      proof: {
        type: "unauthenticated-success",
        requestIndex: 0,
        evidencePointers: ["/order/id", "/payment/card_number"],
      },
    });

    expect(
      evaluateProof(anonymousFinding, [
        observation(
          "/orders/7",
          { order: { id: 7 }, payment: { card_number: "XXXX1234" } },
          { authenticated: false },
        ),
      ]).passed,
    ).toBe(true);
    expect(
      evaluateProof(anonymousFinding, [
        observation("/orders/7", { order: { id: 7 } }, { authenticated: false }),
      ]).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...anonymousFinding,
          reproduction: [
            { path: "/orders/7", authenticated: false, headers: { "x-api-key": "secret" } },
          ],
        },
        [
          observation(
            "/orders/7",
            { order: { id: 7 }, payment: { card_number: "XXXX1234" } },
            { authenticated: false },
          ),
        ],
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...anonymousFinding,
          method: "POST",
          reproduction: [
            {
              path: "/orders/7",
              method: "POST",
              authenticated: false,
              headers: { "content-type": "application/json" },
              body: '{"apiKey":"secret"}',
            },
          ],
        },
        [
          observation(
            "/orders/7",
            { order: { id: 7 }, payment: { card_number: "XXXX1234" } },
            { authenticated: false },
          ),
        ],
      ).passed,
    ).toBe(false);
  });

  it("requires a different subject for cross-principal data exposure", () => {
    const exposed = finding({
      category: "excessive-data-exposure",
      endpoint: "/feed",
      reproduction: [
        { path: "/me", authenticated: true },
        { path: "/feed", authenticated: true },
      ],
      proof: {
        type: "cross-principal-data-exposure",
        actor: { requestIndex: 0, jsonPointer: "/email" },
        exposedSubject: { requestIndex: 1, jsonPointer: "/authors/0/email" },
        responseRequestIndex: 1,
        evidencePointers: ["/authors/0/email", "/authors/0/vehicleId"],
      },
    });

    expect(
      evaluateProof(exposed, [
        observation("/me", { email: "actor@example.com" }),
        observation("/feed", {
          authors: [{ email: "other@example.com", vehicleId: "foreign-vehicle" }],
        }),
      ]).passed,
    ).toBe(true);
    expect(
      evaluateProof(exposed, [
        observation("/me", { email: "actor@example.com" }),
        observation("/feed", {
          authors: [{ email: "actor@example.com", vehicleId: "owned-vehicle" }],
        }),
      ]).passed,
    ).toBe(false);
  });

  it("rejects an affected operation that was not reproduced", () => {
    const result = evaluateProof(finding({ endpoint: "/orders/{id}/audit" }), [
      observation("/me", { email: "actor@example.com" }),
      observation("/orders/7", { order: { id: 7, user: { email: "owner@example.com" } } }),
    ]);

    expect(result.passed).toBe(false);
    expect(result.checks).toContainEqual({
      description: "affected operation matches a reproduction request",
      passed: false,
    });
  });

  it("rejects a proof predicate that is incompatible with the finding category", () => {
    const result = evaluateProof(
      finding({
        category: "excessive-data-exposure",
        proof: {
          type: "cross-principal-access",
          actor: { requestIndex: 0, jsonPointer: "/email" },
          resourceOwner: { requestIndex: 1, jsonPointer: "/order/user/email" },
          accessRequestIndex: 1,
          evidencePointers: ["/order/id"],
        },
      }),
      [
        observation("/me", { email: "actor@example.com" }),
        observation("/orders/7", { order: { id: 7, user: { email: "owner@example.com" } } }),
      ],
    );

    expect(result.passed).toBe(false);
    expect(result.checks[0]).toMatchObject({ passed: false });
  });
});
