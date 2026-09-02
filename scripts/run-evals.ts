#!/usr/bin/env bun
import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { classifyTrialFailures } from "../src/evals/failure-classification.ts";
import { buildEvalMatrix } from "../src/evals/matrix.ts";
import {
  renderRepeatedEvalSummary,
  summarizeRepeatedEvals,
  type RepeatedEvalTrial,
} from "../src/evals/repeated.ts";
import { applyVampiDifferentialScoring } from "../src/evals/security-eval.ts";
import { parseProfiles, positiveInteger, profileOf, trialKey } from "./run-evals-config.ts";
import { runProfile, type EvalRunContext } from "./run-evals-profile.ts";
import { addTrialFailure, mergeReports, synchronizeReport } from "./run-evals-report.ts";
import type { ReportEntry } from "./run-evals-types.ts";

const trialCount = positiveInteger("XBOW_EVAL_TRIALS", "1");
const concurrency = positiveInteger("XBOW_EVAL_CONCURRENCY", "1");
const profileIds = parseProfiles(process.env.XBOW_EVAL_PROFILES);
const runSeed = process.env.XBOW_EVAL_SEED ?? crypto.randomUUID();
const matrix = buildEvalMatrix({ profileIds, trialCount, runSeed });
const casesByTrial = Map.groupBy(matrix, ({ index }) => index);
const projectRoot = resolve(import.meta.dir, "..");
const runId = new Date().toISOString().replaceAll(/[:.]/g, "-");
const runDirectory = join(projectRoot, ".prototype", "eval-trials", runId);
await mkdir(runDirectory, { recursive: true });

const trials: RepeatedEvalTrial[] = [];
const reportEntries = new Map<string, ReportEntry>();
const context: EvalRunContext = {
  trialCount,
  profileIds,
  runDirectory,
  projectRoot,
  trials,
  reportEntries,
};
let nextTrialIndex = 1;
await Promise.all(
  Array.from({ length: Math.min(concurrency, trialCount) }, async () => {
    while (nextTrialIndex <= trialCount) {
      const index = nextTrialIndex;
      nextTrialIndex += 1;
      for (const item of casesByTrial.get(index) ?? []) await runProfile(item, context);
    }
  }),
);

for (let index = 1; index <= trialCount; index += 1) applyDifferentialScoring(index, trials);
for (const trial of trials) {
  trial.failureClassifications = classifyTrialFailures(trial);
  if (trial.output) {
    trial.output.failureClassifications = trial.failureClassifications;
    trial.output.failureCount = trial.failureClassifications.length;
  }
  synchronizeReport(trial, reportEntries);
}
trials.sort((left, right) =>
  left.index === right.index
    ? profileIds.indexOf(profileOf(left)) - profileIds.indexOf(profileOf(right))
    : left.index - right.index,
);
const summary = summarizeRepeatedEvals(trials, new Date(), runSeed);
const mergedReport = mergeReports(
  trials.flatMap((trial) => {
    const entry = reportEntries.get(trialKey(trial.index, profileOf(trial)));
    return entry ? [entry.report] : [];
  }),
);
const outputDirectory = join(projectRoot, ".prototype");
const reportPath = join(outputDirectory, "eval-results.json");
const summaryPath = join(outputDirectory, "eval-summary.json");
const markdownPath = join(outputDirectory, "eval-summary.md");
await Promise.all([
  Bun.write(reportPath, `${JSON.stringify(mergedReport)}\n`),
  Bun.write(summaryPath, `${JSON.stringify(summary, null, 2)}\n`),
  Bun.write(markdownPath, renderRepeatedEvalSummary(summary)),
]);
console.error(`\nRepeated eval summary: ${markdownPath}`);
console.error(`Evaluation run seed: ${runSeed}`);
console.log(renderRepeatedEvalSummary(summary));
if (summary.passedTrials !== summary.requestedTrials) process.exitCode = 1;

function applyDifferentialScoring(index: number, allTrials: RepeatedEvalTrial[]): void {
  const vulnerable = allTrials.find(
    (trial) => trial.index === index && profileOf(trial) === "vampi-vulnerable",
  );
  const secure = allTrials.find(
    (trial) => trial.index === index && profileOf(trial) === "vampi-secure",
  );
  if (!vulnerable || !secure || !vulnerable.output || !secure.output) {
    for (const trial of [vulnerable, secure])
      if (trial) {
        trial.passed = false;
        addTrialFailure(trial, {
          kind: "infrastructure",
          source: "vampi-differential",
          message: "VAmPI differential scoring requires both vulnerable and secure run outputs",
        });
      }
    return;
  }
  applyVampiDifferentialScoring(vulnerable.output, secure.output);
  if (
    vulnerable.output.benchmarkTruePositiveCount === 0 ||
    vulnerable.output.benchmarkFalsePositiveCount > 0
  ) {
    vulnerable.passed = false;
    vulnerable.error ??=
      "VAmPI differential oracle found no vulnerable-only confirmation or found a secure-mode match";
  }
  if (secure.output.benchmarkFalsePositiveCount > 0) {
    secure.passed = false;
    secure.error ??= "VAmPI secure mode produced confirmed findings";
  }
}
