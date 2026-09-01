import type { SecurityEvalOutput } from "./harness.ts";

export interface RepeatedEvalTrial {
  index: number;
  profileId?: string;
  passed: boolean;
  wallDurationMs?: number;
  output?: SecurityEvalOutput;
  error?: string;
  artifactPath: string;
}

export interface RepeatedEvalSummary {
  schemaVersion: 2;
  generatedAt: string;
  requestedTrials: number;
  passedTrials: number;
  completedTrials: number;
  successRate: number;
  infrastructureCompletionRate: number;
  meanCoverage: number;
  meanPrecision: number;
  meanValidationCompleteness: number;
  falsePositiveRate: number;
  meanRequestsPerTruePositive: number | null;
  meanDurationMs: number;
  totalTokens: number;
  meanTokens: number;
  totalFailures: number;
  totalApproximateModelCost: number;
  meanApproximateModelCost: number;
  costedTrials: number;
  profiles: RepeatedEvalProfileSummary[];
  trials: RepeatedEvalTrial[];
}

export interface RepeatedEvalProfileSummary {
  profileId: string;
  runs: number;
  passed: number;
  meanCoverage: number;
  meanPrecision: number;
  meanValidationCompleteness: number;
  meanDurationMs: number;
  totalTokens: number;
  totalFailures: number;
}

export function summarizeRepeatedEvals(
  trials: RepeatedEvalTrial[],
  generatedAt = new Date(),
): RepeatedEvalSummary {
  if (trials.length === 0) throw new Error("At least one eval trial is required");
  const outputs = trials.flatMap(({ output }) => (output ? [output] : []));
  const totalConfirmedClaims = outputs.reduce((total, output) => total + output.confirmedCount, 0);
  const totalFalseOrUnscored = outputs.reduce(
    (total, output) => total + output.benchmarkFalsePositiveCount + output.benchmarkUnscoredCount,
    0,
  );
  const requestsPerTruePositive = outputs.flatMap(({ requestsPerTruePositive }) =>
    requestsPerTruePositive === null ? [] : [requestsPerTruePositive],
  );
  const totalApproximateModelCost = outputs.reduce(
    (total, output) => total + output.approximateModelCost,
    0,
  );
  const groups = Map.groupBy(
    trials,
    ({ output, profileId }) => output?.profileId ?? profileId ?? "unknown",
  );

  return {
    schemaVersion: 2,
    generatedAt: generatedAt.toISOString(),
    requestedTrials: trials.length,
    passedTrials: trials.filter(({ passed }) => passed).length,
    completedTrials: outputs.length,
    successRate: trials.filter(({ passed }) => passed).length / trials.length,
    infrastructureCompletionRate: outputs.length / trials.length,
    meanCoverage:
      outputs.length === 0
        ? 0
        : outputs.reduce((total, output) => total + output.coverage, 0) / outputs.length,
    meanPrecision: meanOrZero(outputs.map(({ precision }) => precision)),
    meanValidationCompleteness: meanOrZero(
      outputs.map(({ validationCompleteness }) => validationCompleteness),
    ),
    falsePositiveRate: totalConfirmedClaims === 0 ? 0 : totalFalseOrUnscored / totalConfirmedClaims,
    meanRequestsPerTruePositive: mean(requestsPerTruePositive),
    meanDurationMs:
      trials.reduce(
        (total, { output, wallDurationMs }) => total + (output?.durationMs ?? wallDurationMs ?? 0),
        0,
      ) / trials.length,
    totalTokens: outputs.reduce((total, output) => total + output.tokens, 0),
    meanTokens: meanOrZero(outputs.map(({ tokens }) => tokens)),
    totalFailures: outputs.reduce((total, output) => total + output.failureCount, 0),
    totalApproximateModelCost,
    meanApproximateModelCost: outputs.length === 0 ? 0 : totalApproximateModelCost / outputs.length,
    costedTrials: outputs.length,
    profiles: [...groups].map(([profileId, profileTrials]) =>
      summarizeProfile(profileId, profileTrials),
    ),
    trials,
  };
}

export function renderRepeatedEvalSummary(summary: RepeatedEvalSummary): string {
  const lines = [
    "# Quiver repeated eval results",
    "",
    `Generated: ${summary.generatedAt}`,
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
    `| Approximate model cost (known total) | $${summary.totalApproximateModelCost.toFixed(4)} (${summary.costedTrials}/${summary.requestedTrials} trials reported usage) |`,
    `| Approximate model cost (mean of reported) | $${summary.meanApproximateModelCost.toFixed(4)} |`,
    "",
    "## Profiles",
    "",
    "| Profile | Passed | Coverage | Precision | Validation | Duration | Tokens | Failures |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ...summary.profiles.map(
      (profile) =>
        `| ${profile.profileId} | ${profile.passed}/${profile.runs} | ${percent(profile.meanCoverage)} | ${percent(profile.meanPrecision)} | ${percent(profile.meanValidationCompleteness)} | ${duration(profile.meanDurationMs)} | ${profile.totalTokens} | ${profile.totalFailures} |`,
    ),
    "",
    "## Runs",
    "",
    "| Trial | Profile | Result | Coverage | Precision | Validation | Tokens | Failures | Duration | Cost |",
    "| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
  ];
  for (const trial of summary.trials) {
    const output = trial.output;
    lines.push(
      `| ${trial.index} | ${output?.profileId ?? trial.profileId ?? "—"} | ${trial.passed ? "PASS" : "FAIL"} | ${output ? percent(output.coverage) : "—"} | ${output ? percent(output.precision) : "—"} | ${output ? percent(output.validationCompleteness) : "—"} | ${output?.tokens ?? "—"} | ${output?.failureCount ?? "—"} | ${duration(output?.durationMs ?? trial.wallDurationMs)} | ${output ? `$${output.approximateModelCost.toFixed(4)}` : "—"} |`,
    );
    if (trial.error) {
      lines.push(
        "",
        `Trial ${trial.index} (${output?.profileId ?? trial.profileId ?? "unknown"}) error: ${trial.error}`,
        "",
      );
    }
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

export function findSecurityEvalOutput(events: readonly unknown[]): SecurityEvalOutput | undefined {
  for (const event of events.toReversed()) {
    if (!event || typeof event !== "object") continue;
    const candidate = event as { type?: unknown; role?: unknown; content?: unknown };
    if (
      candidate.type === "message" &&
      candidate.role === "assistant" &&
      isSecurityEvalOutput(candidate.content)
    ) {
      return candidate.content;
    }
  }
  return undefined;
}

function mean(values: readonly number[]): number | null {
  return values.length === 0
    ? null
    : values.reduce((total, value) => total + value, 0) / values.length;
}

function meanOrZero(values: readonly number[]): number {
  return mean(values) ?? 0;
}

function summarizeProfile(
  profileId: string,
  trials: RepeatedEvalTrial[],
): RepeatedEvalProfileSummary {
  const outputs = trials.flatMap(({ output }) => (output ? [output] : []));
  return {
    profileId,
    runs: trials.length,
    passed: trials.filter(({ passed }) => passed).length,
    meanCoverage: meanOrZero(outputs.map(({ coverage }) => coverage)),
    meanPrecision: meanOrZero(outputs.map(({ precision }) => precision)),
    meanValidationCompleteness: meanOrZero(
      outputs.map(({ validationCompleteness }) => validationCompleteness),
    ),
    meanDurationMs: meanOrZero(
      trials.map(({ output, wallDurationMs }) => output?.durationMs ?? wallDurationMs ?? 0),
    ),
    totalTokens: outputs.reduce((total, { tokens }) => total + tokens, 0),
    totalFailures: outputs.reduce((total, { failureCount }) => total + failureCount, 0),
  };
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

function isSecurityEvalOutput(value: unknown): value is SecurityEvalOutput {
  if (!value || typeof value !== "object") return false;
  const output = value as Partial<SecurityEvalOutput>;
  return (
    typeof output.model === "string" &&
    typeof output.profileId === "string" &&
    typeof output.phase === "string" &&
    typeof output.coverage === "number" &&
    typeof output.precision === "number" &&
    typeof output.validationCompleteness === "number" &&
    typeof output.confirmedCount === "number" &&
    typeof output.requestsUsed === "number" &&
    typeof output.durationMs === "number" &&
    typeof output.tokens === "number" &&
    Array.isArray(output.failures) &&
    typeof output.approximateModelCost === "number"
  );
}
