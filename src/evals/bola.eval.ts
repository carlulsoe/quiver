import { expect } from "vitest";
import { createJudge, describeEval } from "vitest-evals";
import { securityHarness, type SecurityEvalInput, type SecurityEvalOutput } from "./harness.ts";

const BehavioralContractJudge = createJudge<SecurityEvalInput, SecurityEvalOutput>(
  "BehavioralContractJudge",
  async ({ input, output }) => {
    const expectedStatus = input.scenario === "discover" ? "confirmed" : "rejected";
    const passed =
      output.phase === "complete" &&
      output.validationStatus === expectedStatus &&
      output.requestsUsed <= output.requestBudget;

    return {
      score: passed ? 1 : 0,
      metadata: {
        rationale: passed
          ? `${input.scenario} satisfied its bounded behavioral contract.`
          : `${input.scenario} ended phase=${output.phase}, verdict=${output.validationStatus}, requests=${output.requestsUsed}/${output.requestBudget}.`,
      },
    };
  },
);

const target = process.env.XBOW_TARGET ?? "http://127.0.0.1:8888";
const trialCount = Number.parseInt(process.env.XBOW_EVAL_TRIALS ?? "1", 10);
if (!Number.isInteger(trialCount) || trialCount < 1) {
  throw new Error("XBOW_EVAL_TRIALS must be a positive integer");
}
const discoveryTrials = Array.from({ length: trialCount }, (_, index) => ({
  name: `trial ${index + 1} of ${trialCount}`,
}));

describeEval("crAPI vehicle-location BOLA", { harness: securityHarness }, (it) => {
  it.for(discoveryTrials)(
    "discovers and confirms the vulnerable cross-owner path ($name)",
    async (_trial, { run }) => {
      const result = await run({
        scenario: "discover",
        target,
        requestBudget: 30,
        explorerCount: 2,
      });

      expect(result.output).toMatchObject({
        phase: "complete",
        validationStatus: "confirmed",
      });
      expect(result.output.candidateCount).toBeGreaterThan(0);
      expect(result.output.requestsUsed).toBeLessThanOrEqual(result.output.requestBudget);
      await expect(result).toSatisfyJudge(BehavioralContractJudge);
    },
  );

  it("rejects the authenticated user's own vehicle", async ({ run }) => {
    const result = await run({
      scenario: "safe-control",
      target,
      requestBudget: 10,
    });

    expect(result.output).toMatchObject({
      phase: "complete",
      validationStatus: "rejected",
      candidateCount: 1,
    });
    expect(result.output.requestsUsed).toBeLessThanOrEqual(result.output.requestBudget);
    await expect(result).toSatisfyJudge(BehavioralContractJudge);
  });
});
