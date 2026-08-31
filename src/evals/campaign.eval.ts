import { expect } from "vitest";
import { createJudge, describeEval, toolCalls } from "vitest-evals";
import { securityHarness, type SecurityEvalInput, type SecurityEvalOutput } from "./harness.ts";

const CampaignContractJudge = createJudge<SecurityEvalInput, SecurityEvalOutput>(
  "CampaignContractJudge",
  async ({ output }) => {
    const passed =
      output.phase === "complete" &&
      output.benchmarkCoverage >= 0.5 &&
      output.benchmarkFalsePositiveCount === 0 &&
      output.benchmarkUnscoredCount === 0 &&
      output.benchmarkPrecision === 1 &&
      output.unvalidatedCount === 0 &&
      output.agentFailures === 0 &&
      output.requestsUsed <= output.requestBudget;
    return {
      score: passed ? 1 : 0,
      metadata: {
        rationale: passed
          ? `Campaign covered ${(output.benchmarkCoverage * 100).toFixed(0)}% of the benchmark with no false or unscored confirmations in ${output.requestsUsed} requests.`
          : `Campaign ended phase=${output.phase}, coverage=${(output.benchmarkCoverage * 100).toFixed(0)}%, precision=${output.benchmarkPrecision}, safe-control false positives=${output.benchmarkFalsePositiveCount}, unscored=${output.benchmarkUnscoredCount}, unvalidated=${output.unvalidatedCount}, agent failures=${output.agentFailures}, requests=${output.requestsUsed}/${output.requestBudget}.`,
      },
    };
  },
);

const target = process.env.XBOW_TARGET ?? "http://127.0.0.1:8888";
const trialIndex = Number.parseInt(process.env.QUIVER_EVAL_TRIAL_INDEX ?? "1", 10);
const trialTotal = Number.parseInt(process.env.QUIVER_EVAL_TRIAL_TOTAL ?? "1", 10);

describeEval("crAPI read-only vulnerability campaign", { harness: securityHarness }, (it) => {
  it(`finds and deterministically validates vulnerabilities within budget (trial ${trialIndex} of ${trialTotal})`, async ({
    run,
  }) => {
    const result = await run({ target, requestBudget: 42, explorerCount: 3 });

    expect(result.output).toMatchObject({ phase: "complete", unvalidatedCount: 0 });
    expect(result.output.benchmarkCoverage).toBeGreaterThanOrEqual(0.5);
    expect(result.output.benchmarkFalsePositiveCount).toBe(0);
    expect(result.output.benchmarkUnscoredCount).toBe(0);
    expect(result.output.benchmarkPrecision).toBe(1);
    expect(result.output.agentFailures).toBe(0);
    expect(new Set(result.output.confirmedFingerprints).size).toBe(
      result.output.confirmedFingerprints.length,
    );
    expect(result.output.requestsUsed).toBeLessThanOrEqual(result.output.requestBudget);
    expect(toolCalls(result).map((call) => call.name)).toEqual(
      expect.arrayContaining([
        "map_attack_surface",
        "review_campaign",
        "submit_finding",
        "finish_exploration",
        "replay_finding",
        "submit_validation",
      ]),
    );
    await expect(result).toSatisfyJudge(CampaignContractJudge);
  });
});
