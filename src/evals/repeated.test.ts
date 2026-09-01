import { describe, expect, it } from "vitest";
import {
  conciseEvalFailure,
  findSecurityEvalOutput,
  renderRepeatedEvalSummary,
  summarizeRepeatedEvals,
} from "./repeated.ts";
import type { SecurityEvalOutput } from "./harness.ts";

function output(overrides: Partial<SecurityEvalOutput> = {}): SecurityEvalOutput {
  return {
    profileId: "crapi",
    target: "http://127.0.0.1:8888/",
    model: "openrouter/z-ai/glm-5.3-flash",
    phase: "complete",
    findingCount: 2,
    confirmedCount: 2,
    rejectedCount: 0,
    unvalidatedCount: 0,
    confirmedFingerprints: [],
    confirmedFindings: [],
    coverage: 0.5,
    coverageKind: "benchmark",
    precision: 1,
    validationCompleteness: 1,
    tokens: 1_000,
    failures: [],
    failureClassifications: [],
    failureCount: 0,
    scoreKind: "crapi-read-only",
    scoreDetails: {},
    benchmarkTruePositiveCount: 2,
    benchmarkFalsePositiveCount: 0,
    benchmarkMissedCount: 2,
    benchmarkUnscoredCount: 0,
    benchmarkCoverage: 0.5,
    benchmarkPrecision: 1,
    requestsPerTruePositive: 12,
    matchedBenchmarkIds: [],
    missedBenchmarkIds: [],
    requestsUsed: 24,
    requestBudget: 36,
    explorationRequests: 18,
    validationRequests: 6,
    agentFailures: 0,
    operationCoverage: 0.8,
    durationMs: 120_000,
    modelTokens: 1_000,
    approximateModelCost: 0.02,
    error: null,
    heldOutSeed: null,
    ...overrides,
  };
}

describe("repeated eval summary", () => {
  it("aggregates success, strength, efficiency, duration, and model cost", () => {
    const summary = summarizeRepeatedEvals(
      [
        {
          index: 1,
          passed: true,
          wallDurationMs: 121_000,
          output: output(),
          artifactPath: "trial-1.json",
        },
        {
          index: 2,
          passed: false,
          wallDurationMs: 181_000,
          output: output({
            confirmedCount: 2,
            benchmarkFalsePositiveCount: 1,
            benchmarkUnscoredCount: 1,
            benchmarkCoverage: 0.25,
            benchmarkPrecision: 0.5,
            coverage: 0.25,
            precision: 0.5,
            requestsPerTruePositive: 20,
            durationMs: 180_000,
            approximateModelCost: 0.04,
          }),
          artifactPath: "trial-2.json",
        },
      ],
      new Date("2026-08-31T00:00:00.000Z"),
      "repeated-test-seed",
    );

    expect(summary).toMatchObject({
      requestedTrials: 2,
      passedTrials: 1,
      completedTrials: 2,
      successRate: 0.5,
      infrastructureCompletionRate: 1,
      meanCoverage: 0.375,
      meanPrecision: 0.75,
      meanValidationCompleteness: 1,
      falsePositiveRate: 0.5,
      meanRequestsPerTruePositive: 16,
      meanDurationMs: 150_000,
      totalTokens: 2_000,
      meanTokens: 1_000,
      totalFailures: 0,
      totalApproximateModelCost: 0.06,
      meanApproximateModelCost: 0.03,
      costedTrials: 2,
      runSeed: "repeated-test-seed",
    });
    expect(renderRepeatedEvalSummary(summary)).toContain("| Profile runs passed | 1/2 |");
  });

  it("recovers harness output when an acceptance assertion fails", () => {
    const expected = output({ benchmarkUnscoredCount: 1, benchmarkPrecision: 0.5 });

    expect(
      findSecurityEvalOutput([
        { type: "message", role: "user", content: "input" },
        { type: "message", role: "assistant", content: expected },
      ]),
    ).toBe(expected);
  });

  it("keeps judge errors concise while preserving the actionable reason", () => {
    const verboseOutput = `Output: ${"missed item ".repeat(500)}`;
    expect(
      conciseEvalFailure([
        "Error: Score: 0.00 below threshold: 1.00",
        verboseOutput,
        "CampaignContractJudge [0.0]",
        "reason  vulnerableapp completed with zero native coverage.",
        "    at evaluator.ts:1:1",
      ]),
    ).toBe(
      "Error: Score: 0.00 below threshold: 1.00\nreason  vulnerableapp completed with zero native coverage.",
    );
  });
});
