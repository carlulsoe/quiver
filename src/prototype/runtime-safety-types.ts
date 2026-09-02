import type { CampaignControlStatus } from "./state.ts";

export interface TestingWindow {
  /** Inclusive ISO-8601 timestamp. */
  start: string;
  /** Exclusive ISO-8601 timestamp. */
  end: string;
}

export interface RuntimeSafetyPolicy {
  requestsPerSecond: number;
  maxConcurrency: number;
  testingWindows?: readonly TestingWindow[];
  maxConsecutiveFailures: number;
  maxDisruptiveResponses: number;
}

export interface RuntimeSafetyEvents {
  controlStatus?: () => CampaignControlStatus;
  onSuccess?: () => void;
  onFailure?: (disruptive: boolean) => void;
  onHalt?: (reason: string) => void;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
  initialConsecutiveFailures?: number;
  initialDisruptiveResponses?: number;
}

export interface RuntimeRequestLease {
  finish(outcome?: "success" | "failure" | "disruptive"): void;
  fail(disruptive?: boolean): void;
  release(): void;
}

export const DEFAULT_RUNTIME_SAFETY_POLICY: RuntimeSafetyPolicy = {
  requestsPerSecond: 5,
  maxConcurrency: 2,
  maxConsecutiveFailures: 3,
  maxDisruptiveResponses: 3,
};

export class CampaignPausedError extends Error {
  override readonly name = "CampaignPausedError";
}

export class CampaignCancelledError extends Error {
  override readonly name = "CampaignCancelledError";
}

export class CampaignHaltedError extends Error {
  override readonly name = "CampaignHaltedError";
}

export class OutsideTestingWindowError extends Error {
  override readonly name = "OutsideTestingWindowError";
}
