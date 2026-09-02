import { EVAL_FAILURE_KINDS, type EvalFailureKind } from "./failure-classification.ts";
import type { RepeatedEvalSummary, RepeatedEvalTrial } from "./repeated.ts";

export function renderRepeatedEvalSummary(summary: RepeatedEvalSummary): string {
  const lines = [
    "# Quiver repeated eval results",
    "",
    `Generated: ${summary.generatedAt}`,
    `Run seed: ${summary.runSeed ?? "not recorded"}`,
    "",
    "## Aggregate",
    "",
    "| Metric | Result |",
    "| --- | ---: |",
    `| Profile runs passed | ${summary.passedTrials}/${summary.requestedTrials} |`,
    `| Success rate | ${percent(summary.successRate)} |`,
    `| Infrastructure completion | ${summary.completedTrials}/${summary.requestedTrials} (${percent(summary.infrastructureCompletionRate)}) |`,
    `| Mean coverage | ${percent(summary.meanCoverage)} |`,
    `| Mean precision | ${percent(summary.meanPrecision)} |`,
    `| Mean validation completeness | ${percent(summary.meanValidationCompleteness)} |`,
    `| False-positive rate | ${percent(summary.falsePositiveRate)} |`,
    `| Mean requests / true positive | ${numberOrDash(summary.meanRequestsPerTruePositive)} |`,
    `| Mean duration | ${(summary.meanDurationMs / 1_000).toFixed(1)}s |`,
    `| Model tokens | ${summary.totalTokens} total (${summary.meanTokens.toFixed(0)} mean) |`,
    `| Recorded failures | ${summary.totalFailures} |`,
    `| Failure classes | ${renderFailureCounts(summary.failureCounts)} |`,
    `| Approximate model cost (known total) | $${summary.totalApproximateModelCost.toFixed(4)} (${summary.costedTrials}/${summary.requestedTrials} trials reported usage) |`,
    `| Approximate model cost (mean of reported) | $${summary.meanApproximateModelCost.toFixed(4)} |`,
    "",
    "## Profiles",
    "",
    "| Profile | Passed | Coverage | Precision | Validation | Duration | Tokens | Failures | Failure classes |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ...summary.profiles.map(
      (profile) =>
        `| ${profile.profileId} | ${profile.passed}/${profile.runs} | ${percent(profile.meanCoverage)} | ${percent(profile.meanPrecision)} | ${percent(profile.meanValidationCompleteness)} | ${duration(profile.meanDurationMs)} | ${profile.totalTokens} | ${profile.totalFailures} | ${renderFailureCounts(profile.failureCounts)} |`,
    ),
    "",
    "## Runs",
    "",
    "| Trial | Profile | Seed | Result | Coverage | Precision | Validation | Tokens | Failures | Duration | Cost |",
    "| ---: | --- | --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: |",
  ];
  for (const trial of summary.trials) appendTrial(lines, trial);
  return `${lines.join("\n").trimEnd()}\n`;
}

function appendTrial(lines: string[], trial: RepeatedEvalTrial): void {
  const output = trial.output;
  lines.push(
    `| ${trial.index} | ${output?.profileId ?? trial.profileId ?? "—"} | ${trial.heldOutSeed ?? "—"} | ${trial.passed ? "PASS" : "FAIL"} | ${output ? percent(output.coverage) : "—"} | ${output ? percent(output.precision) : "—"} | ${output ? percent(output.validationCompleteness) : "—"} | ${output?.tokens ?? "—"} | ${renderTrialFailures(trial)} | ${duration(output?.durationMs ?? trial.wallDurationMs)} | ${output ? `$${output.approximateModelCost.toFixed(4)}` : "—"} |`,
  );
  if (trial.error)
    lines.push(
      "",
      `Trial ${trial.index} (${output?.profileId ?? trial.profileId ?? "unknown"}) error: ${trial.error}`,
      "",
    );
}

function renderTrialFailures(trial: RepeatedEvalTrial): string {
  const failures = trial.failureClassifications ?? trial.output?.failureClassifications ?? [];
  const counts = {
    budget: 0,
    infrastructure: 0,
    mapping: 0,
    model: 0,
    validation: 0,
  } satisfies Record<EvalFailureKind, number>;
  for (const failure of failures) counts[failure.kind] += 1;
  return renderFailureCounts(counts);
}

function renderFailureCounts(counts: Record<EvalFailureKind, number>): string {
  const populated = EVAL_FAILURE_KINDS.filter((kind) => counts[kind] > 0).map(
    (kind) => `${kind}=${counts[kind]}`,
  );
  return populated.length === 0 ? "—" : populated.join(", ");
}

function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}
function numberOrDash(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : value.toFixed(2);
}
function duration(value: number | undefined): string {
  return value === undefined ? "—" : `${(value / 1_000).toFixed(1)}s`;
}
