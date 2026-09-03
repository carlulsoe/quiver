import { describe, expect, it } from "vitest";
import { evaluateProof } from "./proof.ts";
import { actorIds } from "./sessions.ts";
import { finding, observation } from "./proof-test-helpers.ts";

describe("proof-bearing operation binding", () => {
  it("rejects unrelated access evidence accompanied by a matching decoy request", () => {
    const decoy = finding({
      reproduction: [
        { path: "/me", actorId: actorIds.userA },
        { path: "/cached-order", actorId: actorIds.userA },
        { path: "/orders/7", actorId: actorIds.userA },
      ],
      proof: {
        type: "cross-principal-access",
        actor: { requestIndex: 0, jsonPointer: "/email" },
        resourceOwner: { requestIndex: 1, jsonPointer: "/order/user/email" },
        accessRequestIndex: 1,
        evidencePointers: ["/order/id"],
      },
    });
    const result = evaluateProof(decoy, [
      observation("/me", { email: "actor@example.com" }),
      observation("/cached-order", {
        order: { id: 7, user: { email: "owner@example.com" } },
      }),
      observation("/orders/7", { decoy: true }),
    ]);

    expect(result.passed).toBe(false);
    expect(result.checks).toContainEqual({
      description: "cross-principal access request matches the affected operation",
      passed: false,
    });
  });

  it("rejects unrelated anonymous evidence accompanied by a matching decoy request", () => {
    const decoy = finding({
      category: "security-misconfiguration",
      endpoint: "/admin/config",
      reproduction: [
        { path: "/public-config", actorId: actorIds.anonymous },
        { path: "/admin/config", actorId: actorIds.anonymous },
      ],
      proof: {
        type: "unauthenticated-success",
        requestIndex: 0,
        evidencePointers: ["/build"],
      },
    });
    const result = evaluateProof(decoy, [
      observation("/public-config", { build: "public" }, { actorId: actorIds.anonymous }),
      observation("/admin/config", { decoy: true }, { actorId: actorIds.anonymous }),
    ]);

    expect(result.passed).toBe(false);
    expect(result.checks).toContainEqual({
      description: "unauthenticated request matches the affected operation",
      passed: false,
    });
  });

  it("rejects unrelated data evidence accompanied by a matching decoy request", () => {
    const decoy = finding({
      category: "excessive-data-exposure",
      endpoint: "/feed",
      reproduction: [
        { path: "/me", actorId: actorIds.userA },
        { path: "/cached-feed", actorId: actorIds.userA },
        { path: "/feed", actorId: actorIds.userA },
      ],
      proof: {
        type: "cross-principal-data-exposure",
        actor: { requestIndex: 0, jsonPointer: "/email" },
        exposedSubject: { requestIndex: 1, jsonPointer: "/authors/0/email" },
        responseRequestIndex: 1,
        evidencePointers: ["/authors/0/email"],
      },
    });
    const result = evaluateProof(decoy, [
      observation("/me", { email: "actor@example.com" }),
      observation("/cached-feed", { authors: [{ email: "other@example.com" }] }),
      observation("/feed", { decoy: true }),
    ]);

    expect(result.passed).toBe(false);
    expect(result.checks).toContainEqual({
      description: "cross-principal data response matches the affected operation",
      passed: false,
    });
  });

  it("rejects unrelated internal-field evidence accompanied by a matching decoy request", () => {
    const decoy = finding({
      category: "sensitive-data-exposure",
      endpoint: "/account",
      reproduction: [
        { path: "/cached-account", actorId: actorIds.userA },
        { path: "/account", actorId: actorIds.userA },
      ],
      proof: {
        type: "internal-field-exposure",
        requestIndex: 0,
        evidencePointers: ["/internalBuild"],
      },
    });
    const result = evaluateProof(decoy, [
      observation("/cached-account", { internalBuild: "debug" }),
      observation("/account", { decoy: true }),
    ]);

    expect(result.passed).toBe(false);
    expect(result.checks).toContainEqual({
      description: "internal-field evidence response matches the affected operation",
      passed: false,
    });
  });
});
