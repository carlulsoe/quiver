import { expect } from "vitest";
import { createJudge, describeEval, toolCalls } from "vitest-evals";
import { getDefaultTarget } from "../targets/profiles.ts";
import {
  SECURITY_EVAL_PROFILE_IDS,
  securityHarness,
  type SecurityEvalInput,
  type SecurityEvalOutput,
  type SecurityEvalProfileId,
} from "./harness.ts";

const CampaignContractJudge = createJudge<SecurityEvalInput, SecurityEvalOutput>(
  "CampaignContractJudge",
  async ({ output }) => {
    const passed = meetsContract(output);
    return {
      score: passed ? 1 : 0,
      metadata: {
        rationale: passed
          ? `${output.profileId} completed with ${(output.coverage * 100).toFixed(0)}% ${output.coverageKind} coverage, ${(output.precision * 100).toFixed(0)}% precision, and ${(output.validationCompleteness * 100).toFixed(0)}% validation completeness.`
          : `${output.profileId} ended phase=${output.phase}, coverage=${output.coverage}, precision=${output.precision}, validation completeness=${output.validationCompleteness}, false/unscored=${output.benchmarkFalsePositiveCount + output.benchmarkUnscoredCount}, failures=${output.failureCount}, requests=${output.requestsUsed}/${output.requestBudget}.`,
      },
    };
  },
);

const profileId = parseProfileId(process.env.QUIVER_EVAL_PROFILE ?? "crapi");
const target = process.env.XBOW_TARGET ?? getDefaultTarget(profileId).href;
const trialIndex = Number.parseInt(process.env.QUIVER_EVAL_TRIAL_INDEX ?? "1", 10);
const trialTotal = Number.parseInt(process.env.QUIVER_EVAL_TRIAL_TOTAL ?? "1", 10);
const requestBudget: Record<SecurityEvalProfileId, number> = {
  crapi: 42,
  "vampi-vulnerable": 42,
  "vampi-secure": 42,
  vulnerableapp: 60,
  "held-out": 30,
};

describeEval(`${profileId} vulnerability campaign`, { harness: securityHarness }, (it) => {
  it(`finds and deterministically validates vulnerabilities within budget (trial ${trialIndex} of ${trialTotal})`, async ({
    run,
  }) => {
    const result = await run({
      profileId,
      target,
      requestBudget: requestBudget[profileId],
      explorerCount: 3,
    });

    expect(result.output).toMatchObject({
      profileId,
      phase: "complete",
      validationCompleteness: 1,
      failureCount: 0,
    });
    expect(result.output.requestsUsed).toBeLessThanOrEqual(result.output.requestBudget);
    expect(new Set(result.output.confirmedFingerprints).size).toBe(
      result.output.confirmedFingerprints.length,
    );
    expect(toolCalls(result).map((call) => call.name)).toEqual(
      expect.arrayContaining(["map_attack_surface", "review_campaign", "finish_exploration"]),
    );
    await expect(result).toSatisfyJudge(CampaignContractJudge);
  });
});

function meetsContract(output: SecurityEvalOutput): boolean {
  const complete =
    output.phase === "complete" &&
    output.validationCompleteness === 1 &&
    output.failureCount === 0 &&
    output.requestsUsed <= output.requestBudget;
  if (!complete) return false;
  if (output.profileId.startsWith("vampi-")) {
    return output.scoreKind === "vampi-differential-pending";
  }
  if (output.profileId === "crapi") {
    return (
      output.coverage >= 0.5 &&
      output.precision === 1 &&
      output.benchmarkFalsePositiveCount === 0 &&
      output.benchmarkUnscoredCount === 0
    );
  }
  return (
    output.coverage > 0 &&
    output.precision === 1 &&
    output.benchmarkFalsePositiveCount === 0 &&
    output.benchmarkUnscoredCount === 0
  );
}

function parseProfileId(value: string): SecurityEvalProfileId {
  if ((SECURITY_EVAL_PROFILE_IDS as readonly string[]).includes(value)) {
    return value as SecurityEvalProfileId;
  }
  throw new Error(`QUIVER_EVAL_PROFILE must be one of: ${SECURITY_EVAL_PROFILE_IDS.join(", ")}`);
}
