#!/usr/bin/env bun
import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  applyVampiDifferentialScoring,
  SECURITY_EVAL_PROFILE_IDS,
  type SecurityEvalOutput,
  type SecurityEvalProfileId,
} from "../src/evals/security-eval.ts";
import { classifyTrialFailures, type EvalFailure } from "../src/evals/failure-classification.ts";
import { buildEvalMatrix } from "../src/evals/matrix.ts";
import {
  conciseEvalFailure,
  findSecurityEvalOutput,
  renderRepeatedEvalSummary,
  summarizeRepeatedEvals,
  type RepeatedEvalTrial,
} from "../src/evals/repeated.ts";
import { getDefaultTarget } from "../src/targets/profiles.ts";

interface JsonAssertionResult {
  status: string;
  duration?: number;
  failureMessages: string[];
  meta?: {
    eval?: { output?: SecurityEvalOutput };
    harness?: { run?: { session?: { events?: unknown[] } } };
  };
}

interface JsonTestReport {
  success: boolean;
  testResults: Array<{ assertionResults: JsonAssertionResult[] }>;
  [key: string]: unknown;
}

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
const reportEntries = new Map<string, { report: JsonTestReport; assertion: JsonAssertionResult }>();
let nextTrialIndex = 1;
await Promise.all(
  Array.from({ length: Math.min(concurrency, trialCount) }, async () => {
    while (nextTrialIndex <= trialCount) {
      const index = nextTrialIndex;
      nextTrialIndex += 1;
      for (const item of casesByTrial.get(index) ?? []) await runProfile(item);
    }
  }),
);

for (let index = 1; index <= trialCount; index += 1) {
  const vulnerable = trials.find(
    (trial) => trial.index === index && profileOf(trial) === "vampi-vulnerable",
  );
  const secure = trials.find(
    (trial) => trial.index === index && profileOf(trial) === "vampi-secure",
  );
  if (!vulnerable || !secure || !vulnerable.output || !secure.output) {
    for (const trial of [vulnerable, secure]) {
      if (!trial) continue;
      trial.passed = false;
      addTrialFailure(trial, {
        kind: "infrastructure",
        source: "vampi-differential",
        message: "VAmPI differential scoring requires both vulnerable and secure run outputs",
      });
    }
  } else {
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
}

for (const trial of trials) {
  trial.failureClassifications = classifyTrialFailures(trial);
  if (trial.output) {
    trial.output.failureClassifications = trial.failureClassifications;
    trial.output.failureCount = trial.failureClassifications.length;
  }
}
for (const trial of trials) synchronizeReport(trial);

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

async function runProfile(item: {
  index: number;
  profileId: SecurityEvalProfileId;
  heldOutSeed?: string;
}): Promise<void> {
  const { index, profileId, heldOutSeed } = item;
  const target = targetFor(profileId);
  const managedHeldOutSeed = profileId === "held-out" && !target ? heldOutSeed : undefined;
  const recordedHeldOutSeed =
    managedHeldOutSeed ?? (profileId === "held-out" ? process.env.QUIVER_HELD_OUT_SEED : undefined);
  const artifactPath = join(
    runDirectory,
    `trial-${String(index).padStart(2, "0")}-${profileId}.json`,
  );
  console.error(`\nQuiver eval trial ${index}/${trialCount}: ${profileId} (isolated process)`);
  const childEnvironment = evalEnvironment(profileId, index, target, managedHeldOutSeed);
  const child = Bun.spawn(
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
      env: childEnvironment,
      stdout: "inherit",
      stderr: "inherit",
    },
  );
  const exitCode = await child.exited;

  let report: JsonTestReport | undefined;
  let parseError: string | undefined;
  try {
    report = (await Bun.file(artifactPath).json()) as JsonTestReport;
  } catch (error) {
    parseError = `Could not read trial artifact: ${String(error)}`;
  }
  const assertion = report?.testResults.flatMap(({ assertionResults }) => assertionResults)[0];
  const output =
    assertion?.meta?.eval?.output ??
    findSecurityEvalOutput(assertion?.meta?.harness?.run?.session?.events ?? []);
  const trial: RepeatedEvalTrial = {
    index,
    profileId,
    passed: exitCode === 0 && assertion?.status === "passed",
    ...(typeof assertion?.duration === "number" ? { wallDurationMs: assertion.duration } : {}),
    ...(output ? { output } : {}),
    ...((parseError ?? (assertion?.failureMessages.length ? assertion.failureMessages : undefined))
      ? {
          error: parseError ?? conciseEvalFailure(assertion?.failureMessages ?? []),
        }
      : {}),
    artifactPath,
    ...(recordedHeldOutSeed ? { heldOutSeed: recordedHeldOutSeed } : {}),
  };
  trials.push(trial);
  if (report && assertion) reportEntries.set(trialKey(index, profileId), { report, assertion });
}

function parseProfiles(value: string | undefined): SecurityEvalProfileId[] {
  const requested = value
    ? value
        .split(",")
        .map((profile) => profile.trim())
        .filter(Boolean)
    : [...SECURITY_EVAL_PROFILE_IDS];
  if (requested.length === 0) throw new Error("XBOW_EVAL_PROFILES must not be empty");
  for (const profile of requested) {
    if (!(SECURITY_EVAL_PROFILE_IDS as readonly string[]).includes(profile)) {
      throw new Error(
        `XBOW_EVAL_PROFILES contains ${profile}; expected: ${SECURITY_EVAL_PROFILE_IDS.join(", ")}`,
      );
    }
  }
  const unique = [...new Set(requested)] as SecurityEvalProfileId[];
  const hasVulnerable = unique.includes("vampi-vulnerable");
  const hasSecure = unique.includes("vampi-secure");
  if (hasVulnerable !== hasSecure) {
    throw new Error(
      "XBOW_EVAL_PROFILES must include both vampi-vulnerable and vampi-secure for differential scoring",
    );
  }
  return unique;
}

function targetFor(profileId: SecurityEvalProfileId): string | undefined {
  const suffix = profileId.toUpperCase().replaceAll("-", "_");
  const specific = process.env[`XBOW_TARGET_${suffix}`];
  if (specific) return specific;
  if (profileIds.length === 1 && process.env.XBOW_TARGET) return process.env.XBOW_TARGET;
  if (profileId === "held-out") return undefined;
  return getDefaultTarget(profileId).href;
}

function evalEnvironment(
  profileId: SecurityEvalProfileId,
  index: number,
  target: string | undefined,
  heldOutSeed: string | undefined,
): Record<string, string> {
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] =>
        !["XBOW_TARGET", "QUIVER_EVAL_HELD_OUT_SEED"].includes(entry[0]) && entry[1] !== undefined,
    ),
  );
  environment.QUIVER_EVAL_PROFILE = profileId;
  environment.QUIVER_EVAL_TRIAL_INDEX = String(index);
  environment.QUIVER_EVAL_TRIAL_TOTAL = String(trialCount);
  if (target) environment.XBOW_TARGET = target;
  if (heldOutSeed) {
    environment.QUIVER_EVAL_HELD_OUT_SEED = heldOutSeed;
    environment.QUIVER_HELD_OUT_SEED = heldOutSeed;
  }
  return environment;
}

function positiveInteger(name: string, fallback: string): number {
  const value = Number.parseInt(process.env[name] ?? fallback, 10);
  if (!Number.isInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
  return value;
}

function profileOf(trial: RepeatedEvalTrial): SecurityEvalProfileId {
  return (trial.output?.profileId ?? trial.profileId) as SecurityEvalProfileId;
}

function trialKey(index: number, profileId: string): string {
  return `${index}:${profileId}`;
}

function synchronizeReport(trial: RepeatedEvalTrial): void {
  const profileId = profileOf(trial);
  const entry = reportEntries.get(trialKey(trial.index, profileId));
  if (!entry) return;
  if (trial.output) {
    entry.assertion.meta ??= {};
    entry.assertion.meta.eval ??= {};
    entry.assertion.meta.eval.output = trial.output;
  }
  if (trial.passed || entry.assertion.status === "failed") return;
  entry.assertion.status = "failed";
  if (trial.error && !entry.assertion.failureMessages.includes(trial.error)) {
    entry.assertion.failureMessages.push(trial.error);
  }
  entry.report.success = false;
}

function addTrialFailure(trial: RepeatedEvalTrial, failure: EvalFailure): void {
  trial.failureClassifications ??= [];
  if (
    !trial.failureClassifications.some(
      (item) =>
        item.kind === failure.kind &&
        item.source === failure.source &&
        item.message === failure.message,
    )
  ) {
    trial.failureClassifications.push(failure);
  }
}

function mergeReports(items: JsonTestReport[]): JsonTestReport {
  if (items.length === 0) return { success: false, testResults: [] };
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
