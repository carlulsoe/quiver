import type { EvalFailure } from "../src/evals/failure-classification.ts";
import type { RepeatedEvalTrial } from "../src/evals/repeated.ts";
import { profileOf, trialKey } from "./run-evals-config.ts";
import type { JsonTestReport, ReportEntry } from "./run-evals-types.ts";

export function synchronizeReport(
  trial: RepeatedEvalTrial,
  entries: Map<string, ReportEntry>,
): void {
  const entry = entries.get(trialKey(trial.index, profileOf(trial)));
  if (!entry) return;
  if (trial.output) {
    entry.assertion.meta ??= {};
    entry.assertion.meta.eval ??= {};
    entry.assertion.meta.eval.output = trial.output;
  }
  if (trial.passed || entry.assertion.status === "failed") return;
  entry.assertion.status = "failed";
  if (trial.error && !entry.assertion.failureMessages.includes(trial.error))
    entry.assertion.failureMessages.push(trial.error);
  entry.report.success = false;
}
export function addTrialFailure(trial: RepeatedEvalTrial, failure: EvalFailure): void {
  trial.failureClassifications ??= [];
  if (
    !trial.failureClassifications.some(
      (item) =>
        item.kind === failure.kind &&
        item.source === failure.source &&
        item.message === failure.message,
    )
  )
    trial.failureClassifications.push(failure);
}
export function mergeReports(items: JsonTestReport[]): JsonTestReport {
  if (!items.length) return { success: false, testResults: [] };
  const first = items[0]!;
  const testResults = items.flatMap(({ testResults }) => testResults);
  const assertions = testResults.flatMap(({ assertionResults }) => assertionResults);
  const suiteFailed = (result: (typeof testResults)[number]) =>
    result.assertionResults.some(({ status }) => status === "failed");
  const suitePassed = (result: (typeof testResults)[number]) =>
    !suiteFailed(result) && result.assertionResults.some(({ status }) => status === "passed");
  return {
    ...first,
    success: assertions.every(({ status }) => status !== "failed"),
    numTotalTests: assertions.length,
    numPassedTests: assertions.filter(({ status }) => status === "passed").length,
    numFailedTests: assertions.filter(({ status }) => status === "failed").length,
    numPendingTests: assertions.filter(({ status }) => status === "pending").length,
    numTodoTests: assertions.filter(({ status }) => status === "todo").length,
    numTotalTestSuites: testResults.length,
    numPassedTestSuites: testResults.filter(suitePassed).length,
    numFailedTestSuites: testResults.filter(suiteFailed).length,
    numPendingTestSuites: testResults.filter(
      (result) => !suiteFailed(result) && !suitePassed(result),
    ).length,
    testResults,
  };
}
