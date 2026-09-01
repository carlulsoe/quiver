import type { SecurityEvalOutput } from "./harness.ts";
import {
  EVAL_FAILURE_KINDS,
  type EvalFailure,
  type EvalFailureKind,
} from "./failure-classification.ts";

export interface RepeatedEvalTrial {
  index: number;
  profileId?: string;
  passed: boolean;
  wallDurationMs?: number;
  output?: SecurityEvalOutput;
  error?: string;
  artifactPath: string;
  heldOutSeed?: string;
  failureClassifications?: EvalFailure[];
}

export interface RepeatedEvalSummary {
  schemaVersion: 3;
  generatedAt: string;
  runSeed: string | null;
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
  failureCounts: Record<EvalFailureKind, number>;
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
  failureCounts: Record<EvalFailureKind, number>;
}

export function summarizeRepeatedEvals(
  trials: RepeatedEvalTrial[],
  generatedAt = new Date(),
  runSeed: string | null = null,
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
    schemaVersion: 3,
    generatedAt: generatedAt.toISOString(),
    runSeed,
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
    totalFailures: trials.reduce((total, trial) => total + trialFailures(trial).length, 0),
    failureCounts: countFailures(trials),
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
  for (const trial of summary.trials) {
    const output = trial.output;
    lines.push(
      `| ${trial.index} | ${output?.profileId ?? trial.profileId ?? "—"} | ${trial.heldOutSeed ?? "—"} | ${trial.passed ? "PASS" : "FAIL"} | ${output ? percent(output.coverage) : "—"} | ${output ? percent(output.precision) : "—"} | ${output ? percent(output.validationCompleteness) : "—"} | ${output?.tokens ?? "—"} | ${renderTrialFailures(trial)} | ${duration(output?.durationMs ?? trial.wallDurationMs)} | ${output ? `$${output.approximateModelCost.toFixed(4)}` : "—"} |`,
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

export function conciseEvalFailure(messages: readonly string[], maxLength = 1_200): string {
  const message = messages.join("\n").trim();
  if (!message) return "Eval process failed without an assertion message";
  const lines = message.split("\n");
  const judgeIndex = lines.findLastIndex((line) => line.startsWith("CampaignContractJudge ["));
  if (judgeIndex >= 0) {
    const reasonIndex = lines.findIndex(
      (line, index) => index > judgeIndex && line.trimStart().startsWith("reason "),
    );
    if (reasonIndex >= 0) {
      const reason: string[] = [];
      for (const line of lines.slice(reasonIndex)) {
        if (line.trimStart().startsWith("at ")) break;
        reason.push(line.trim());
      }
      return truncateFailure(`${lines[0]}\n${reason.join(" ")}`, maxLength);
    }
  }
  return truncateFailure(message, maxLength);
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
    totalFailures: trials.reduce((total, trial) => total + trialFailures(trial).length, 0),
    failureCounts: countFailures(trials),
  };
}

function countFailures(trials: readonly RepeatedEvalTrial[]): Record<EvalFailureKind, number> {
  const counts = Object.fromEntries(EVAL_FAILURE_KINDS.map((kind) => [kind, 0])) as Record<
    EvalFailureKind,
    number
  >;
  for (const trial of trials) {
    for (const failure of trialFailures(trial)) counts[failure.kind] += 1;
  }
  return counts;
}

function renderFailureCounts(counts: Record<EvalFailureKind, number>): string {
  const populated = EVAL_FAILURE_KINDS.filter((kind) => counts[kind] > 0).map(
    (kind) => `${kind}=${counts[kind]}`,
  );
  return populated.length === 0 ? "—" : populated.join(", ");
}

function renderTrialFailures(trial: RepeatedEvalTrial): string {
  const counts = countFailures([trial]);
  return renderFailureCounts(counts);
}

function trialFailures(trial: RepeatedEvalTrial): readonly EvalFailure[] {
  return trial.failureClassifications ?? trial.output?.failureClassifications ?? [];
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

function truncateFailure(message: string, maxLength: number): string {
  if (message.length <= maxLength) return message;
  return `${message.slice(0, maxLength).trimEnd()}… (full message in trial artifact)`;
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
    Array.isArray(output.failureClassifications) &&
    typeof output.approximateModelCost === "number"
  );
}
