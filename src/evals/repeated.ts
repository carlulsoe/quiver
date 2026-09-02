import type { SecurityEvalOutput } from "./harness.ts";
import {
  EVAL_FAILURE_KINDS,
  type EvalFailure,
  type EvalFailureKind,
} from "./failure-classification.ts";

export { renderRepeatedEvalSummary } from "./repeated-render.ts";
export { findSecurityEvalOutput } from "./repeated-output-parser.ts";

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

function trialFailures(trial: RepeatedEvalTrial): readonly EvalFailure[] {
  return trial.failureClassifications ?? trial.output?.failureClassifications ?? [];
}

function truncateFailure(message: string, maxLength: number): string {
  if (message.length <= maxLength) return message;
  return `${message.slice(0, maxLength).trimEnd()}… (full message in trial artifact)`;
}
