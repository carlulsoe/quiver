import { join } from "node:path";
import {
  conciseEvalFailure,
  findSecurityEvalOutput,
  type RepeatedEvalTrial,
} from "../src/evals/repeated.ts";
import type { SecurityEvalProfileId } from "../src/evals/security-eval.ts";
import { evalEnvironment, targetFor, trialKey } from "./run-evals-config.ts";
import type { JsonTestReport, ReportEntry } from "./run-evals-types.ts";

export interface EvalRunContext {
  trialCount: number;
  profileIds: readonly SecurityEvalProfileId[];
  runDirectory: string;
  projectRoot: string;
  trials: RepeatedEvalTrial[];
  reportEntries: Map<string, ReportEntry>;
}
export interface EvalProfileItem {
  index: number;
  profileId: SecurityEvalProfileId;
  heldOutSeed?: string;
}

export async function runProfile(item: EvalProfileItem, context: EvalRunContext): Promise<void> {
  const { index, profileId, heldOutSeed } = item;
  const target = targetFor(profileId, context.profileIds);
  const managedSeed = profileId === "held-out" && !target ? heldOutSeed : undefined;
  const recordedSeed =
    managedSeed ?? (profileId === "held-out" ? process.env.QUIVER_HELD_OUT_SEED : undefined);
  const artifactPath = join(
    context.runDirectory,
    `trial-${String(index).padStart(2, "0")}-${profileId}.json`,
  );
  console.error(
    `\nQuiver eval trial ${index}/${context.trialCount}: ${profileId} (isolated process)`,
  );
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
      cwd: context.projectRoot,
      env: evalEnvironment(profileId, index, context.trialCount, target, managedSeed),
      stdout: "inherit",
      stderr: "inherit",
    },
  );
  const exitCode = await child.exited;
  let report: JsonTestReport | undefined;
  let parseError: string | undefined;
  try {
    report = await Bun.file(artifactPath).json();
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
    artifactPath,
  };
  if (assertion?.duration !== undefined) trial.wallDurationMs = assertion.duration;
  if (output) trial.output = output;
  const failure =
    parseError ??
    (assertion?.failureMessages.length ? conciseEvalFailure(assertion.failureMessages) : undefined);
  if (failure) trial.error = failure;
  if (recordedSeed) trial.heldOutSeed = recordedSeed;
  context.trials.push(trial);
  if (report && assertion)
    context.reportEntries.set(trialKey(index, profileId), { report, assertion });
}
