import { describe, expect, it, vi } from "vitest";
import { applyVampiDifferentialScoring, createSecurityEvalOutput } from "./harness.ts";
import {
  campaignRun,
  finding,
  heldOutBolaFinding,
  heldOutFinding,
  nativeFinding,
  output,
} from "./harness-test-fixtures.ts";

describe("profile-agnostic eval scoring", () => {
  it("scores the held-out canary and records the uniform metrics", async () => {
    const run = campaignRun([heldOutFinding(), heldOutBolaFinding()]);

    const result = await createSecurityEvalOutput(
      "held-out",
      new URL("http://127.0.0.1:8899"),
      run,
    );

    expect(result).toMatchObject({
      profileId: "held-out",
      scoreKind: "held-out-canary",
      coverage: 1,
      precision: 1,
      findingCount: 2,
      benchmarkFalsePositiveCount: 0,
      validationCompleteness: 1,
      durationMs: 2_500,
      tokens: 321,
      failures: [],
    });
  });

  it("automatically invokes VulnerableApp's native scoring adapter", async () => {
    const transport = vi.fn(async () =>
      Response.json({
        coverage: 25,
        totalExpected: 8,
        detected: 2,
        missed: 6,
        unmatched: 1,
        missedItems: [{ url: "/missed" }],
        unmatchedItems: [{ url: "/unmatched" }],
      }),
    );
    vi.stubGlobal("fetch", transport);
    try {
      const result = await createSecurityEvalOutput(
        "vulnerableapp",
        new URL("http://127.0.0.1:9090/VulnerableApp/"),
        campaignRun(nativeFinding()),
      );

      expect(transport).toHaveBeenCalledOnce();
      expect(result).toMatchObject({
        scoreKind: "vulnerableapp-native",
        coverage: 0.25,
        precision: 2 / 3,
        benchmarkFalsePositiveCount: 1,
        scoreDetails: {
          missedItems: [{ url: "/missed" }],
          falsePositiveItems: [{ url: "/unmatched" }],
        },
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("applies the VAmPI differential adapter to both isolated mode outputs", () => {
    const shared = finding("sensitive-data-exposure", "/users/v1/_debug");
    const vulnerableOnly = finding("broken-object-authorization", "/books/v1/foreign-title");
    const vulnerable = output("vampi-vulnerable", [shared, vulnerableOnly]);
    const secure = output("vampi-secure", [shared]);

    applyVampiDifferentialScoring(vulnerable, secure);

    expect(vulnerable).toMatchObject({
      scoreKind: "vampi-differential",
      coverage: 0.75,
      precision: 0.5,
      benchmarkTruePositiveCount: 1,
      benchmarkFalsePositiveCount: 1,
      scoreDetails: {
        vulnerableOnly: ["broken-object-authorization:GET:/books/v1/foreign-title"],
        secureAlso: ["sensitive-data-exposure:GET:/users/v1/_debug"],
      },
    });
    expect(secure).toMatchObject({
      scoreKind: "vampi-differential",
      precision: 0,
      benchmarkFalsePositiveCount: 1,
    });
  });
});
