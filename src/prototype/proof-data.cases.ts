import { describe, expect, it } from "vitest";
import { evaluateProof } from "./proof.ts";
import { actorIds } from "./sessions.ts";
import { finding, observation } from "./proof-test-helpers.ts";

describe("deterministic data proof", () => {
  it("confirms anonymous success only for an actually anonymous request with declared fields", () => {
    const anonymousFinding = finding({
      category: "security-misconfiguration",
      reproduction: [{ path: "/orders/7", actorId: "anonymous" }],
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
          { actorId: "anonymous" },
        ),
      ]).passed,
    ).toBe(true);
    expect(
      evaluateProof(anonymousFinding, [
        observation("/orders/7", { order: { id: 7 } }, { actorId: "anonymous" }),
      ]).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...anonymousFinding,
          reproduction: [
            { path: "/orders/7", actorId: "anonymous", headers: { "x-api-key": "secret" } },
          ],
        },
        [
          observation(
            "/orders/7",
            { order: { id: 7 }, payment: { card_number: "XXXX1234" } },
            { actorId: "anonymous" },
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
              actorId: "anonymous",
              headers: { "content-type": "application/json" },
              body: '{"apiKey":"secret"}',
            },
          ],
        },
        [
          observation(
            "/orders/7",
            { order: { id: 7 }, payment: { card_number: "XXXX1234" } },
            { actorId: "anonymous" },
          ),
        ],
      ).passed,
    ).toBe(false);
  });

  it.each(["broken-object-authorization", "broken-function-authorization"] as const)(
    "does not treat a public anonymous GET as %s",
    (category) => {
      const publicEndpointFinding = finding({
        category,
        endpoint: "/catalog/7",
        reproduction: [{ path: "/catalog/7", actorId: actorIds.anonymous }],
        proof: {
          type: "unauthenticated-success",
          requestIndex: 0,
          evidencePointers: ["/item/id"],
        },
      });

      const result = evaluateProof(publicEndpointFinding, [
        observation("/catalog/7", { item: { id: 7 } }, { actorId: actorIds.anonymous }),
      ]);

      expect(result.passed).toBe(false);
      expect(result.checks).toContainEqual({
        passed: false,
        description: `predicate unauthenticated-success is compatible with ${category}`,
      });
    },
  );

  it("requires a different subject for cross-principal data exposure", () => {
    const exposed = finding({
      category: "excessive-data-exposure",
      endpoint: "/feed",
      reproduction: [
        { path: "/me", actorId: "ordinary-user" },
        { path: "/feed", actorId: "ordinary-user" },
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
