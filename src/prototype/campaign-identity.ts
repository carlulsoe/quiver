import { createHash } from "node:crypto";
import type { CampaignIdentity } from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";

export interface CampaignConfiguration {
  target: URL;
  profile: TargetProfile;
  requestBudget: number;
  explorerCount: number;
  openApi?: unknown;
  context?: string;
}

/** Creates the opaque identity persisted with a durable campaign checkpoint. */
export function createCampaignIdentity(configuration: CampaignConfiguration): CampaignIdentity {
  const hasCallbacks = containsFunction(configuration.profile);
  return {
    schemaVersion: 2,
    profileId: configuration.profile.id,
    configurationFingerprint: createHash("sha256")
      .update(stableConfiguration(configuration))
      .digest("hex"),
    resumable:
      !hasCallbacks ||
      validCallbackFingerprint(configuration.profile.callbackConfigurationFingerprint),
  };
}

/** Rejects checkpoints whose target profile or safety-relevant inputs changed. */
export function assertCampaignIdentity(
  stored: CampaignIdentity | undefined,
  expected: CampaignIdentity,
  campaignId: string,
  resuming = true,
): void {
  if (!stored) {
    throw new Error(
      `Campaign ${campaignId} predates configuration binding and cannot be resumed safely`,
    );
  }
  if (stored.profileId !== expected.profileId) {
    throw new Error(
      `Campaign ${campaignId} belongs to profile ${stored.profileId}, not ${expected.profileId}`,
    );
  }
  if (resuming && !expected.resumable) {
    throw new Error(
      `Campaign ${campaignId} profile callbacks must declare callbackConfigurationFingerprint before durable resume`,
    );
  }
  if (
    stored.schemaVersion !== expected.schemaVersion ||
    stored.resumable !== expected.resumable ||
    stored.configurationFingerprint !== expected.configurationFingerprint
  ) {
    throw new Error(`Campaign ${campaignId} configuration does not match its durable checkpoint`);
  }
}

function stableConfiguration(configuration: CampaignConfiguration): string {
  return stableStringify({
    target: `${configuration.target.origin}${configuration.target.pathname}${configuration.target.search}`,
    requestBudget: configuration.requestBudget,
    explorerCount: configuration.explorerCount,
    context: configuration.context,
    openApi: configuration.openApi,
    profile: configuration.profile,
  });
}

function stableStringify<Value>(value: Value): string {
  return JSON.stringify(normalize(value)) ?? "null";
}

type StableValue =
  | string
  | number
  | boolean
  | null
  | StableValue[]
  | { [key: string]: StableValue };

function normalize<Value>(value: Value): Value | StableValue {
  // Source text detects code changes. Closed-over values are bound separately by the
  // profile's callbackConfigurationFingerprint; profiles without one are non-resumable.
  if (value instanceof Function) return { $function: Function.prototype.toString.call(value) };
  if (Array.isArray(value)) return value.map(normalize);
  if (!(value instanceof Object)) return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, normalize(entry)]),
  );
}

function containsFunction<Value>(value: Value, seen = new Set<object>()): boolean {
  if (value instanceof Function) return true;
  if (!(value instanceof Object) || seen.has(value)) return false;
  seen.add(value);
  return Array.isArray(value)
    ? value.some((entry) => containsFunction(entry, seen))
    : Object.values(value).some((entry) => containsFunction(entry, seen));
}

function validCallbackFingerprint(value: string | undefined): boolean {
  return value !== undefined && value.trim().length > 0;
}
