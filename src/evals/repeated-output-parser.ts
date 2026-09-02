import type { SecurityEvalOutput } from "./harness.ts";

interface TranscriptCandidate {
  type?: unknown;
  role?: unknown;
  content?: unknown;
}

export function findSecurityEvalOutput(events: readonly unknown[]): SecurityEvalOutput | undefined {
  for (const event of events.toReversed()) {
    if (!(event instanceof Object)) continue;
    const candidate = event as TranscriptCandidate;
    if (
      candidate.type === "message" &&
      candidate.role === "assistant" &&
      isSecurityEvalOutput(candidate.content)
    )
      return candidate.content;
  }
  return undefined;
}

function isSecurityEvalOutput<T>(value: T): value is T & SecurityEvalOutput {
  if (!(value instanceof Object)) return false;
  const output = value as Partial<SecurityEvalOutput>;
  return (
    isString(output.model) &&
    isString(output.profileId) &&
    isString(output.phase) &&
    isNumber(output.coverage) &&
    isNumber(output.precision) &&
    isNumber(output.validationCompleteness) &&
    isNumber(output.confirmedCount) &&
    isNumber(output.requestsUsed) &&
    isNumber(output.durationMs) &&
    isNumber(output.tokens) &&
    Array.isArray(output.failures) &&
    Array.isArray(output.failureClassifications) &&
    isNumber(output.approximateModelCost)
  );
}

function isString<T>(value: T): boolean {
  return Object.prototype.toString.call(value) === "[object String]";
}

function isNumber<T>(value: T): boolean {
  return Object.prototype.toString.call(value) === "[object Number]";
}
