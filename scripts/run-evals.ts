#!/usr/bin/env bun
import { join, resolve } from "node:path";
import { mkdir } from "node:fs/promises";
import type { SecurityEvalOutput } from "../src/evals/harness.ts";
import {
  findSecurityEvalOutput,
  renderRepeatedEvalSummary,
  summarizeRepeatedEvals,
  type RepeatedEvalTrial,
} from "../src/evals/repeated.ts";

interface JsonTestReport {
  success: boolean;
  testResults: Array<{
    assertionResults: Array<{
      status: string;
      duration?: number;
      failureMessages: string[];
      meta?: {
        eval?: { output?: SecurityEvalOutput };
        harness?: { run?: { session?: { events?: unknown[] } } };
      };
    }>;
  }>;
  [key: string]: unknown;
}

const trialCount = Number.parseInt(process.env.XBOW_EVAL_TRIALS ?? "1", 10);
if (!Number.isInteger(trialCount) || trialCount < 1) {
  throw new Error("XBOW_EVAL_TRIALS must be a positive integer");
}
const concurrency = Number.parseInt(process.env.XBOW_EVAL_CONCURRENCY ?? "1", 10);
if (!Number.isInteger(concurrency) || concurrency < 1) {
  throw new Error("XBOW_EVAL_CONCURRENCY must be a positive integer");
}

const projectRoot = resolve(import.meta.dir, "..");
const runId = new Date().toISOString().replaceAll(/[:.]/g, "-");
const runDirectory = join(projectRoot, ".prototype", "eval-trials", runId);
await mkdir(runDirectory, { recursive: true });

const reports: Array<JsonTestReport | undefined> = Array.from({ length: trialCount });
const trials: Array<RepeatedEvalTrial | undefined> = Array.from({ length: trialCount });
let nextTrialIndex = 1;
await Promise.all(
  Array.from({ length: Math.min(concurrency, trialCount) }, async () => {
    while (nextTrialIndex <= trialCount) {
      const index = nextTrialIndex;
      nextTrialIndex += 1;
      await runTrial(index);
    }
  }),
);

async function runTrial(index: number): Promise<void> {
  const artifactPath = join(runDirectory, `trial-${String(index).padStart(2, "0")}.json`);
  console.error(`\nQuiver eval trial ${index}/${trialCount} (isolated process)`);
  const process = Bun.spawn(
    [
      "bunx",
      "--bun",
      "vitest",
      "run",
      "--config",
      "vitest.evals.config.ts",
      "--reporter=vitest-evals/reporter",
      "--reporter=json",
      `--outputFile.json=${artifactPath}`,
    ],
    {
      cwd: projectRoot,
      env: {
        ...globalThis.process.env,
        QUIVER_EVAL_TRIAL_INDEX: String(index),
        QUIVER_EVAL_TRIAL_TOTAL: String(trialCount),
      },
      stdout: "inherit",
      stderr: "inherit",
    },
  );
  const exitCode = await process.exited;

  let report: JsonTestReport | undefined;
  let parseError: string | undefined;
  try {
    report = (await Bun.file(artifactPath).json()) as JsonTestReport;
    reports[index - 1] = report;
  } catch (error) {
    parseError = `Could not read trial artifact: ${String(error)}`;
  }
  const assertion = report?.testResults.flatMap(({ assertionResults }) => assertionResults)[0];
  const output =
    assertion?.meta?.eval?.output ??
    findSecurityEvalOutput(assertion?.meta?.harness?.run?.session?.events ?? []);
  trials[index - 1] = {
    index,
    passed: exitCode === 0 && assertion?.status === "passed",
    ...(typeof assertion?.duration === "number" ? { wallDurationMs: assertion.duration } : {}),
    ...(output ? { output } : {}),
    ...((parseError ?? assertion?.failureMessages.join("\n"))
      ? { error: parseError ?? assertion?.failureMessages.join("\n") }
      : {}),
    artifactPath,
  };
}

const completedTrials = trials.flatMap((trial) => (trial ? [trial] : []));
const completedReports = reports.flatMap((report) => (report ? [report] : []));
const summary = summarizeRepeatedEvals(completedTrials);
const mergedReport = mergeReports(completedReports);
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
console.log(renderRepeatedEvalSummary(summary));
if (summary.passedTrials !== summary.requestedTrials) process.exitCode = 1;

function mergeReports(items: JsonTestReport[]): JsonTestReport {
  if (items.length === 0) return { success: false, testResults: [] };
  const first = items[0]!;
  return {
    ...first,
    success: items.every(({ success }) => success),
    numTotalTests: sum(items, "numTotalTests"),
    numPassedTests: sum(items, "numPassedTests"),
    numFailedTests: sum(items, "numFailedTests"),
    numPendingTests: sum(items, "numPendingTests"),
    numTodoTests: sum(items, "numTodoTests"),
    numTotalTestSuites: sum(items, "numTotalTestSuites"),
    numPassedTestSuites: sum(items, "numPassedTestSuites"),
    numFailedTestSuites: sum(items, "numFailedTestSuites"),
    numPendingTestSuites: sum(items, "numPendingTestSuites"),
    testResults: items.flatMap(({ testResults }) => testResults),
  };
}

function sum(items: JsonTestReport[], key: string): number {
  return items.reduce((total, item) => total + (typeof item[key] === "number" ? item[key] : 0), 0);
}
