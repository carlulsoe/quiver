import type { JsonValue } from "vitest-evals";
import type { CampaignRun } from "../prototype/runner.ts";

export const EVAL_FAILURE_KINDS = [
  "model",
  "infrastructure",
  "budget",
  "mapping",
  "validation",
] as const;

export type EvalFailureKind = (typeof EVAL_FAILURE_KINDS)[number];

export interface EvalFailure extends Record<string, JsonValue> {
  kind: EvalFailureKind;
  source: string;
  message: string;
}

export interface TrialFailureInput {
  passed: boolean;
  failureClassifications?: EvalFailure[];
  output?: {
    phase: string;
    coverage: number;
    precision: number;
    validationCompleteness: number;
    benchmarkFalsePositiveCount: number;
    benchmarkUnscoredCount: number;
    failureClassifications: EvalFailure[];
  };
  error?: string;
}

export function classifyCampaignFailures(run: CampaignRun): EvalFailure[] {
  const failures: EvalFailure[] = [];
  const add = failureCollector(failures);

  for (const agent of run.state.agents) {
    if (agent.status !== "failed") continue;
    add(classifyMessage(agent.summary ?? "Agent failed without a summary", `agent:${agent.id}`));
  }
  if (run.state.error) add(classifyMessage(run.state.error, "campaign"));
  if (run.state.requests.total > run.state.budget.total) {
    add({
      kind: "budget",
      source: "campaign",
      message: `Campaign used ${run.state.requests.total}/${run.state.budget.total} requests`,
    });
  }

  const unvalidated = run.state.findings.length - run.state.validations.length;
  if (unvalidated > 0) {
    const exhausted =
      run.state.requests.total >= run.state.budget.total ||
      run.state.requests.validation >= run.state.budget.validation;
    add({
      kind: exhausted ? "budget" : "validation",
      source: "validation",
      message: `${unvalidated} finding${unvalidated === 1 ? "" : "s"} lacked an independent validation outcome`,
    });
  }

  if (
    run.state.phase === "complete" &&
    run.state.discoveredOperations.length === 0 &&
    run.state.discoveredRoutes.length === 0
  ) {
    add({
      kind: "mapping",
      source: "attack-surface",
      message: "Campaign completed without discovering an attack-surface operation",
    });
  }

  return failures;
}

export function classifyTrialFailures(input: TrialFailureInput): EvalFailure[] {
  const failures = [
    ...(input.failureClassifications ?? []),
    ...(input.output?.failureClassifications ?? []),
  ];
  const add = failureCollector(failures);
  if (input.passed) return failures;

  if (!input.output) {
    add(classifyMessage(input.error ?? "Eval process failed without a result", "eval-process"));
    return failures;
  }

  if (input.output.validationCompleteness < 1) {
    add({
      kind: "validation",
      source: "contract",
      message: `Validation completeness was ${input.output.validationCompleteness}`,
    });
  }
  if (
    input.output.phase === "complete" &&
    (input.output.coverage <= 0 ||
      input.output.precision < 1 ||
      input.output.benchmarkFalsePositiveCount > 0 ||
      input.output.benchmarkUnscoredCount > 0)
  ) {
    add({
      kind: "model",
      source: "contract",
      message: "Model output did not meet the benchmark coverage and precision contract",
    });
  }
  if (input.output.phase !== "complete" && failures.length === 0) {
    add(
      classifyMessage(input.error ?? `Campaign ended in phase ${input.output.phase}`, "contract"),
    );
  }
  if (failures.length === 0) {
    add(
      input.output.phase === "complete"
        ? {
            kind: "model",
            source: "contract",
            message: input.error ?? "Completed model output did not meet the eval contract",
          }
        : classifyMessage(input.error ?? "Eval assertion failed", "contract"),
    );
  }
  return failures;
}

export function classifyMessage(message: string, source: string): EvalFailure {
  const normalized = message.toLowerCase();
  if (/budget|request limit|allocation exhausted/.test(normalized)) {
    return { kind: "budget", source, message };
  }
  if (/map_attack_surface|attack.surface|chromium|browser mapping|playwright/.test(normalized)) {
    return { kind: "mapping", source, message };
  }
  if (/validat|replay_finding|deterministic proof/.test(normalized)) {
    return { kind: "validation", source, message };
  }
  if (/openrouter|model|provider|rate.?limit|context length|response.*token/.test(normalized)) {
    return { kind: "model", source, message };
  }
  return { kind: "infrastructure", source, message };
}

function failureCollector(failures: EvalFailure[]): (failure: EvalFailure) => void {
  const seen = new Set(failures.map(failureKey));
  return (failure) => {
    const key = failureKey(failure);
    if (seen.has(key)) return;
    seen.add(key);
    failures.push(failure);
  };
}

function failureKey(failure: EvalFailure): string {
  return `${failure.kind}:${failure.source}:${failure.message}`;
}
