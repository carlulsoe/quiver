import { describe, expect, it } from "vitest";
import { evaluateProof } from "./proof.ts";
import { actorIds } from "./sessions.ts";
import { finding, identities, observation } from "./proof-test-helpers.ts";

describe("deterministic access and authentication proof", () => {
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

  it("proves authentication bypass against a manifest-declared protected operation", () => {
    const bypass = finding({
      fingerprint: "authentication-bypass:GET:/account",
      category: "authentication-bypass",
      endpoint: "/account",
      reproduction: [
        { path: "/account", actorId: actorIds.userA },
        { path: "/account", actorId: actorIds.anonymous },
      ],
      proof: {
        type: "authentication-bypass",
        authenticatedRequestIndex: 0,
        anonymousRequestIndex: 1,
        evidencePointers: ["/account/id", "/account/plan"],
      },
    });
    const context = {
      identities,
      protectedOperations: [
        {
          method: "GET" as const,
          path: "/{resource}",
          authorizedActors: [actorIds.administrator],
        },
        {
          method: "GET" as const,
          path: "/account",
          authorizedActors: [actorIds.userA, actorIds.administrator],
        },
      ],
    };
    const observations = [
      observation(
        "/account",
        { account: { id: "account-7", plan: "internal" } },
        { actorId: actorIds.userA },
      ),
      observation(
        "/account",
        { account: { id: "account-7", plan: "internal" } },
        { actorId: actorIds.anonymous },
      ),
    ];

    expect(evaluateProof(bypass, observations, context)).toMatchObject({
      passed: true,
      predicate: "authentication-bypass",
    });
    expect(
      evaluateProof(
        bypass,
        [observations[0]!, { ...observations[1]!, body: { account: { id: "public" } } }],
        context,
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(bypass, observations, { identities, protectedOperations: [] }).passed,
    ).toBe(false);
    expect(
      evaluateProof(bypass, observations, {
        identities,
        protectedOperations: [
          {
            method: "GET",
            path: "/{resource}",
            authorizedActors: [actorIds.userA],
          },
          {
            method: "GET",
            path: "/:resource",
            authorizedActors: [actorIds.administrator],
          },
        ],
      }).passed,
    ).toBe(false);
    expect(
      evaluateProof({ ...bypass, endpoint: "/{resource}" }, observations, {
        identities,
        protectedOperations: [
          {
            method: "GET",
            path: "/{resource}",
            authorizedActors: [actorIds.userA],
          },
          {
            method: "GET",
            path: "/account",
            authorizedActors: [actorIds.administrator],
          },
        ],
      }).passed,
    ).toBe(false);
  });
});
