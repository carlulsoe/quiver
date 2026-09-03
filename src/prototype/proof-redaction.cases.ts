import { describe, expect, it } from "vitest";
import { evaluateProof } from "./proof.ts";
import { actorIds } from "./sessions.ts";
import { finding, observation } from "./proof-test-helpers.ts";

describe("proof evidence redaction", () => {
  it("redacts credential ancestors without hiding benign proof evidence", () => {
    const result = evaluateProof(
      finding({
        category: "sensitive-data-exposure",
        endpoint: "/account",
        reproduction: [{ path: "/account", actorId: actorIds.userA }],
        proof: {
          type: "internal-field-exposure",
          requestIndex: 0,
          evidencePointers: ["/apiToken", "/tokens/0", "/credentials/primary/value", "/buildId"],
        },
      }),
      [
        observation("/account", {
          apiToken: "proof-token-sentinel",
          tokens: ["array-token-sentinel"],
          credentials: { primary: { value: "nested-credential-sentinel" } },
          buildId: "build-7",
        }),
      ],
    );

    expect(result.passed).toBe(true);
    for (const description of [
      "response contains /apiToken",
      "response contains /tokens/0",
      "response contains /credentials/primary/value",
    ])
      expect(result.checks).toContainEqual({ description, passed: true, actual: "[REDACTED]" });
    expect(result.checks).toContainEqual({
      description: "response contains /buildId",
      passed: true,
      actual: "build-7",
    });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("proof-token-sentinel");
    expect(serialized).not.toContain("array-token-sentinel");
    expect(serialized).not.toContain("nested-credential-sentinel");
  });

  it("redacts a credential copied into another selected field in the same observation", () => {
    const result = evaluateProof(
      finding({
        category: "sensitive-data-exposure",
        endpoint: "/account",
        reproduction: [{ path: "/account", actorId: actorIds.userA }],
        proof: {
          type: "internal-field-exposure",
          requestIndex: 0,
          evidencePointers: ["/apiToken", "/message"],
        },
      }),
      [
        observation("/account", {
          apiToken: "same-observation-secret",
          message: "received same-observation-secret",
        }),
      ],
    );

    expect(result.passed).toBe(true);
    expect(result.checks).toContainEqual({
      description: "response contains /message",
      passed: true,
      actual: "received [REDACTED]",
    });
    expect(JSON.stringify(result)).not.toContain("same-observation-secret");
  });

  it("redacts a selected value copied from a credential in another observation", () => {
    const result = evaluateProof(
      finding({
        category: "sensitive-data-exposure",
        endpoint: "/account",
        reproduction: [
          { path: "/session", actorId: actorIds.userA },
          { path: "/account", actorId: actorIds.userA },
        ],
        proof: {
          type: "internal-field-exposure",
          requestIndex: 1,
          evidencePointers: ["/message"],
        },
      }),
      [
        observation("/session", { apiToken: "cross-observation-secret" }),
        observation("/account", { message: "received cross-observation-secret" }),
      ],
    );

    expect(result.passed).toBe(true);
    expect(result.checks).toContainEqual({
      description: "response contains /message",
      passed: true,
      actual: "received [REDACTED]",
    });
    expect(JSON.stringify(result)).not.toContain("cross-observation-secret");
  });
});
