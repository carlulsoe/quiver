import { createHarness, toJsonValue } from "vitest-evals";
import { campaignOperationCoverage } from "../prototype/state.ts";
import { runCampaign, type CampaignRun } from "../prototype/runner.ts";
import { getDefaultTarget, getTargetProfile } from "../targets/profiles.ts";
import { createHeldOutFixture } from "../targets/held-out-fixture.ts";
import { createHeldOutProfile } from "../targets/held-out.ts";
import { emptyScore, evalFinding, scoreProfile, type NormalizedScore } from "./eval-scoring.ts";
import { classifyCampaignFailures } from "./failure-classification.ts";
import type {
  SecurityEvalInput,
  SecurityEvalOutput,
  SecurityEvalProfileId,
} from "./security-eval.ts";
import { transcriptEvents } from "./transcript-events.ts";

export { applyVampiDifferentialScoring, SECURITY_EVAL_PROFILE_IDS } from "./security-eval.ts";
export type {
  CoverageKind,
  EvalFinding,
  ScoreKind,
  SecurityEvalInput,
  SecurityEvalOutput,
  SecurityEvalProfileId,
} from "./security-eval.ts";

export const securityHarness = createHarness<SecurityEvalInput, SecurityEvalOutput>({
  name: "bounded-security-campaign",
  run: async ({ input, setArtifact }) => {
    const fixture =
      input.profileId === "held-out" && input.heldOutSeed
        ? createHeldOutFixture(input.heldOutSeed)
        : undefined;
    const fixtureServer =
      fixture && !input.target
        ? Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: fixture.fetch })
        : undefined;
    const profile = fixture
      ? createHeldOutProfile(fixture.seed)
      : getTargetProfile(input.profileId);
    const target = new URL(input.target ?? fixtureServer?.url ?? getDefaultTarget(input.profileId));
    const transitions: string[] = [];
    try {
      const run = await runCampaign({
        target,
        profile,
        requestBudget: input.requestBudget,
        explorerCount: input.explorerCount,
        onState: (_state, action) => {
          if (action) transitions.push(action.type);
        },
      });
      const output = await createSecurityEvalOutput(input.profileId, target, run, {
        heldOutSeed: input.heldOutSeed,
      });

      setArtifact("findings", toJsonValue(run.state.findings) ?? []);
      setArtifact("validations", toJsonValue(run.state.validations) ?? []);
      setArtifact("transitions", transitions);
      setArtifact("runTrace", toJsonValue(run.events) ?? []);

      return {
        output,
        events: [
          { type: "message", role: "user", content: JSON.stringify(input) },
          ...transcriptEvents(run),
          { type: "message", role: "assistant", content: output },
        ],
        usage: { model: run.model, provider: "openrouter" },
      };
    } finally {
      fixtureServer?.stop(true);
    }
  },
});

export async function createSecurityEvalOutput(
  profileId: SecurityEvalProfileId,
  target: URL,
  run: CampaignRun,
  metadata: { heldOutSeed?: string } = {},
): Promise<SecurityEvalOutput> {
  const confirmedFingerprints = run.state.validations
    .filter((validation) => validation.status === "confirmed")
    .map((validation) => validation.fingerprint);
  const confirmedSet = new Set(confirmedFingerprints);
  const confirmed = run.state.findings.filter((finding) => confirmedSet.has(finding.fingerprint));
  const rejectedCount = run.state.validations.filter(
    (validation) => validation.status === "rejected",
  ).length;
  const unvalidatedCount = run.state.findings.length - run.state.validations.length;
  const operationCoverage = campaignOperationCoverage(run.state).coverage;
  const failures = run.state.agents
    .filter((agent) => agent.status === "failed")
    .map((agent) => `agent:${agent.id}`);
  if (run.state.error) failures.push(`campaign:${run.state.error}`);
  const failureClassifications = classifyCampaignFailures(run);

  let score: NormalizedScore;
  try {
    score = await scoreProfile(
      profileId,
      target,
      confirmed,
      run.state.requests.total,
      operationCoverage,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    failures.push(`scoring:${message}`);
    failureClassifications.push({ kind: "infrastructure", source: "scoring", message });
    score = emptyScore(profileId, operationCoverage);
  }

  return {
    profileId,
    target: target.href,
    model: run.model,
    phase: run.state.phase,
    findingCount: run.state.findings.length,
    confirmedCount: confirmed.length,
    rejectedCount,
    unvalidatedCount,
    confirmedFingerprints,
    confirmedFindings: confirmed.map(evalFinding),
    coverage: score.coverage,
    coverageKind: score.coverageKind,
    precision: score.precision,
    validationCompleteness:
      run.state.findings.length === 0
        ? 1
        : run.state.validations.length / run.state.findings.length,
    durationMs: run.durationMs,
    tokens: run.usage.totalTokens,
    failures,
    failureClassifications,
    failureCount: failures.length,
    scoreKind: score.kind,
    scoreDetails: score.details,
    benchmarkTruePositiveCount: score.truePositiveCount,
    benchmarkFalsePositiveCount: score.falsePositiveCount,
    benchmarkMissedCount: score.missedCount,
    benchmarkUnscoredCount: score.unscoredCount,
    benchmarkCoverage: score.coverage,
    benchmarkPrecision: score.precision,
    requestsPerTruePositive: score.requestsPerTruePositive,
    matchedBenchmarkIds: score.matchedIds,
    missedBenchmarkIds: score.missedIds,
    requestsUsed: run.state.requests.total,
    requestBudget: run.state.budget.total,
    explorationRequests: run.state.requests.exploration,
    validationRequests: run.state.requests.validation,
    agentFailures: run.state.agents.filter((agent) => agent.status === "failed").length,
    operationCoverage,
    modelTokens: run.usage.totalTokens,
    approximateModelCost: run.usage.cost.total,
    error: run.state.error ?? null,
    heldOutSeed: metadata.heldOutSeed ?? null,
  };
}
