import type { RuntimeSafetyPolicy, TestingWindow } from "./runtime-safety-types.ts";

export function classifyHttpStatus(status: number): "success" | "failure" | "disruptive" {
  if (!Number.isFinite(status) || status <= 0) return "failure";
  if (status === 408 || status === 425 || status === 429 || status >= 500) return "disruptive";
  return "success";
}

export function withinTestingWindow(now: number, window: TestingWindow): boolean {
  const start = Date.parse(window.start);
  const end = Date.parse(window.end);
  return Number.isFinite(start) && Number.isFinite(end) && start <= now && now < end;
}

export function assertRuntimeSafetyPolicy(policy: RuntimeSafetyPolicy): void {
  if (!Number.isInteger(policy.requestsPerSecond) || policy.requestsPerSecond < 1) {
    throw new Error("requestsPerSecond must be a positive integer");
  }
  if (!Number.isInteger(policy.maxConcurrency) || policy.maxConcurrency < 1) {
    throw new Error("maxConcurrency must be a positive integer");
  }
  if (!Number.isInteger(policy.maxConsecutiveFailures) || policy.maxConsecutiveFailures < 1) {
    throw new Error("maxConsecutiveFailures must be a positive integer");
  }
  if (!Number.isInteger(policy.maxDisruptiveResponses) || policy.maxDisruptiveResponses < 1) {
    throw new Error("maxDisruptiveResponses must be a positive integer");
  }
  for (const window of policy.testingWindows ?? []) {
    const start = Date.parse(window.start);
    const end = Date.parse(window.end);
    if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) {
      throw new Error("Testing windows require valid ISO timestamps with start before end");
    }
  }
}
