import type { SecurityEvalOutput } from "./harness.ts";

export interface RepeatedEvalTrial {
  index: number;
  passed: boolean;
  wallDurationMs?: number;
  output?: SecurityEvalOutput;
  error?: string;
  artifactPath: string;
}

export interface RepeatedEvalSummary {
  schemaVersion: 1;
  generatedAt: string;
  requestedTrials: number;
  passedTrials: number;
  completedTrials: number;
  successRate: number;
  infrastructureCompletionRate: number;
  meanCoverage: number;
  falsePositiveRate: number;
  meanRequestsPerTruePositive: number | null;
  meanDurationMs: number;
  totalApproximateModelCost: number;
  meanApproximateModelCost: number;
  costedTrials: number;
  trials: RepeatedEvalTrial[];
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

  return {
    schemaVersion: 1,
    generatedAt: generatedAt.toISOString(),
    requestedTrials: trials.length,
    passedTrials: trials.filter(({ passed }) => passed).length,
    completedTrials: outputs.length,
    successRate: trials.filter(({ passed }) => passed).length / trials.length,
    infrastructureCompletionRate: outputs.length / trials.length,
    meanCoverage:
      outputs.length === 0
        ? 0
        : outputs.reduce((total, output) => total + output.benchmarkCoverage, 0) / outputs.length,
    falsePositiveRate: totalConfirmedClaims === 0 ? 0 : totalFalseOrUnscored / totalConfirmedClaims,
    meanRequestsPerTruePositive: mean(requestsPerTruePositive),
    meanDurationMs:
      trials.reduce(
        (total, { output, wallDurationMs }) => total + (output?.durationMs ?? wallDurationMs ?? 0),
        0,
      ) / trials.length,
    totalApproximateModelCost,
    meanApproximateModelCost: outputs.length === 0 ? 0 : totalApproximateModelCost / outputs.length,
    costedTrials: outputs.length,
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
    `| Trials passed | ${summary.passedTrials}/${summary.requestedTrials} |`,
    `| Success rate | ${percent(summary.successRate)} |`,
    `| Infrastructure completion | ${summary.completedTrials}/${summary.requestedTrials} (${percent(summary.infrastructureCompletionRate)}) |`,
    `| Mean benchmark coverage | ${percent(summary.meanCoverage)} |`,
    `| False-positive rate | ${percent(summary.falsePositiveRate)} |`,
    `| Mean requests / true positive | ${numberOrDash(summary.meanRequestsPerTruePositive)} |`,
    `| Mean duration | ${(summary.meanDurationMs / 1_000).toFixed(1)}s |`,
    `| Approximate model cost (known total) | $${summary.totalApproximateModelCost.toFixed(4)} (${summary.costedTrials}/${summary.requestedTrials} trials reported usage) |`,
    `| Approximate model cost (mean of reported) | $${summary.meanApproximateModelCost.toFixed(4)} |`,
    "",
    "## Trials",
    "",
    "| Trial | Result | Coverage | Precision | False/unscored | Requests / TP | Duration | Cost |",
    "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
  ];
  for (const trial of summary.trials) {
    const output = trial.output;
    lines.push(
      `| ${trial.index} | ${trial.passed ? "PASS" : "FAIL"} | ${output ? percent(output.benchmarkCoverage) : "—"} | ${output ? percent(output.benchmarkPrecision) : "—"} | ${output ? output.benchmarkFalsePositiveCount + output.benchmarkUnscoredCount : "—"} | ${numberOrDash(output?.requestsPerTruePositive)} | ${duration(output?.durationMs ?? trial.wallDurationMs)} | ${output ? `$${output.approximateModelCost.toFixed(4)}` : "—"} |`,
    );
    if (trial.error) lines.push("", `Trial ${trial.index} error: ${trial.error}`, "");
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
    typeof output.phase === "string" &&
    typeof output.benchmarkCoverage === "number" &&
    typeof output.benchmarkPrecision === "number" &&
    typeof output.confirmedCount === "number" &&
    typeof output.requestsUsed === "number" &&
    typeof output.durationMs === "number" &&
    typeof output.approximateModelCost === "number"
  );
}
