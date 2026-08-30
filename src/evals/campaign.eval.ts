import { expect } from "vitest";
import { createJudge, describeEval, toolCalls } from "vitest-evals";
import { securityHarness, type SecurityEvalInput, type SecurityEvalOutput } from "./harness.ts";

const CampaignContractJudge = createJudge<SecurityEvalInput, SecurityEvalOutput>(
  "CampaignContractJudge",
  async ({ output }) => {
    const passed =
      output.phase === "complete" &&
      output.confirmedCount > 0 &&
      output.unvalidatedCount === 0 &&
      output.requestsUsed <= output.requestBudget;
    return {
      score: passed ? 1 : 0,
      metadata: {
        rationale: passed
          ? `Campaign confirmed ${output.confirmedCount} of ${output.findingCount} unique findings within budget.`
          : `Campaign ended phase=${output.phase}, confirmed=${output.confirmedCount}, unvalidated=${output.unvalidatedCount}, requests=${output.requestsUsed}/${output.requestBudget}.`,
      },
    };
  },
);

const target = process.env.XBOW_TARGET ?? "http://127.0.0.1:8888";
const trialCount = Number.parseInt(process.env.XBOW_EVAL_TRIALS ?? "1", 10);
if (!Number.isInteger(trialCount) || trialCount < 1) {
  throw new Error("XBOW_EVAL_TRIALS must be a positive integer");
}
const trials = Array.from({ length: trialCount }, (_, index) => ({
  name: `trial ${index + 1} of ${trialCount}`,
}));

describeEval("crAPI read-only vulnerability campaign", { harness: securityHarness }, (it) => {
  it.for(trials)(
    "finds and validates unique vulnerabilities within budget ($name)",
    async (_, { run }) => {
      const result = await run({ target, requestBudget: 36, explorerCount: 2 });

      expect(result.output).toMatchObject({ phase: "complete", unvalidatedCount: 0 });
      expect(result.output.confirmedCount).toBeGreaterThan(0);
      expect(new Set(result.output.confirmedFingerprints).size).toBe(
        result.output.confirmedFingerprints.length,
      );
      expect(result.output.requestsUsed).toBeLessThanOrEqual(result.output.requestBudget);
      expect(toolCalls(result).map((call) => call.name)).toEqual(
        expect.arrayContaining([
          "crawl_target",
          "submit_finding",
          "finish_exploration",
          "replay_finding",
          "submit_validation",
          "finish_validation",
        ]),
      );
      await expect(result).toSatisfyJudge(CampaignContractJudge);
    },
  );
});
