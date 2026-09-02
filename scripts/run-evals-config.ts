import {
  SECURITY_EVAL_PROFILE_IDS,
  type SecurityEvalProfileId,
} from "../src/evals/security-eval.ts";
import type { RepeatedEvalTrial } from "../src/evals/repeated.ts";
import { getDefaultTarget } from "../src/targets/profiles.ts";

export function parseProfiles(value: string | undefined): SecurityEvalProfileId[] {
  const requested = value
    ? value
        .split(",")
        .map((profile) => profile.trim())
        .filter(Boolean)
    : [...SECURITY_EVAL_PROFILE_IDS];
  if (!requested.length) throw new Error("XBOW_EVAL_PROFILES must not be empty");
  for (const profile of requested)
    if (!isProfileId(profile))
      throw new Error(
        `XBOW_EVAL_PROFILES contains ${profile}; expected: ${SECURITY_EVAL_PROFILE_IDS.join(", ")}`,
      );
  const unique: SecurityEvalProfileId[] = [];
  for (const profile of requested)
    if (isProfileId(profile) && !unique.includes(profile)) unique.push(profile);
  if (unique.includes("vampi-vulnerable") !== unique.includes("vampi-secure"))
    throw new Error(
      "XBOW_EVAL_PROFILES must include both vampi-vulnerable and vampi-secure for differential scoring",
    );
  return unique;
}
export function targetFor(
  profileId: SecurityEvalProfileId,
  profileIds: readonly SecurityEvalProfileId[],
): string | undefined {
  const specific = process.env[`XBOW_TARGET_${profileId.toUpperCase().replaceAll("-", "_")}`];
  if (specific) return specific;
  if (profileIds.length === 1 && process.env.XBOW_TARGET) return process.env.XBOW_TARGET;
  return profileId === "held-out" ? undefined : getDefaultTarget(profileId).href;
}
export function evalEnvironment(
  profileId: SecurityEvalProfileId,
  index: number,
  trialCount: number,
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
export function positiveInteger(name: string, fallback: string): number {
  const value = Number.parseInt(process.env[name] ?? fallback, 10);
  if (!Number.isInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
  return value;
}
export function profileOf(trial: RepeatedEvalTrial): SecurityEvalProfileId {
  const profileId = trial.output?.profileId ?? trial.profileId;
  if (!profileId || !isProfileId(profileId))
    throw new Error(`Unknown evaluation profile ${profileId}`);
  return profileId;
}
export function trialKey(index: number, profileId: string): string {
  return `${index}:${profileId}`;
}
function isProfileId(profileId: string): profileId is SecurityEvalProfileId {
  return SECURITY_EVAL_PROFILE_IDS.some((candidate) => candidate === profileId);
}
