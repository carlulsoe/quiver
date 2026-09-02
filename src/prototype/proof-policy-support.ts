import * as v from "valibot";
import type { ProofCheck } from "./state.ts";
import type { ProofPolicy } from "./target-profile.ts";
import type { ProofRequest } from "./proof-request-comparison.ts";
import { requestMutationValue } from "./proof-request-mutation.ts";

const serializedStringSchema = v.string();

export function policyFor<K extends ProofPolicy["kind"]>(
  policies: readonly ProofPolicy[] | undefined,
  id: string,
  kind: K,
): Extract<ProofPolicy, { kind: K }> | undefined {
  return policies?.find(
    (policy): policy is Extract<ProofPolicy, { kind: K }> =>
      policy.id === id && policy.kind === kind,
  );
}

export function safeRegex(pattern: string, flags?: string): RegExp | undefined {
  if (pattern.length > 256) return undefined;
  try {
    return new RegExp(pattern, flags);
  } catch {
    return undefined;
  }
}

export function verifyCanary(
  policy: Extract<ProofPolicy, { kind: "canary" }>,
  value: string,
): boolean {
  try {
    return policy.verify(value);
  } catch {
    return false;
  }
}

export function verifyFileContent(
  policy: Extract<ProofPolicy, { kind: "file-content" }>,
  value: string,
): boolean {
  try {
    return policy.verify(value);
  } catch {
    return false;
  }
}

export function commandChallengeOutput(
  policy: Extract<ProofPolicy, { kind: "command-execution-challenge" }>,
  challenge: number,
): string | undefined {
  const result = challenge * policy.multiplier + policy.addend;
  return Number.isSafeInteger(result) ? `${policy.outputPrefix}${result}` : undefined;
}

export function challengeRequestMatches(
  request: ProofRequest | undefined,
  challenge: {
    location: "query" | "json-body" | "fragment";
    parameter: string;
    template: string;
  },
  value: string,
): boolean {
  return (
    challenge.template.split("{{challenge}}").length === 2 &&
    requestMutationValue(request, challenge) === challenge.template.replace("{{challenge}}", value)
  );
}

export function challengePathMatches(
  path: string,
  challenge: {
    location: "query" | "json-body" | "fragment";
    parameter: string;
    template: string;
  },
  value: string,
): boolean {
  return (
    ["query", "fragment"].includes(challenge.location) &&
    challengeRequestMatches({ path, actorId: "anonymous" }, challenge, value)
  );
}

export function responseContains(body: ProofCheck["actual"], value: string): boolean {
  try {
    const serialized = JSON.stringify(body);
    const parsed = v.safeParse(serializedStringSchema, serialized);
    return parsed.success && parsed.output.includes(value);
  } catch {
    return true;
  }
}

export function isExactOrigin(value: string): boolean {
  try {
    return new URL(value).origin === value;
  } catch {
    return false;
  }
}

export function isCompletedStateTransition(status: number): boolean {
  return status >= 200 && status < 400;
}
