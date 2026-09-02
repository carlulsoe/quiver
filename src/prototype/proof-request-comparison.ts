import * as v from "valibot";
import type { Finding, RequestMutation } from "./state.ts";
import type { ProofCheck, ValidationObservation } from "./state.ts";
import type { ActorId } from "./sessions.ts";
import { canonicalJson } from "./proof-json.ts";
import { jsonPointer } from "./proof-json.ts";
import {
  hasUniqueHeaderNames,
  normalizeHeaders,
  requestWithoutMutation,
} from "./proof-request-mutation.ts";

const stringSchema = v.string();
const jsonObjectSchema = v.record(v.string(), v.unknown());

export function selectedAt(
  observations: readonly ValidationObservation[],
  requestIndex: number,
  pointer: string,
): { found: boolean; value?: unknown } {
  const observation = observations[requestIndex];
  return observation ? jsonPointer(observation.body, pointer) : { found: false };
}

export function requestContains(request: ProofRequest, value: string): boolean {
  const entries = [
    request.path,
    request.body ?? "",
    ...Object.entries(request.headers ?? {}).flatMap(([name, entry]) => [name, entry]),
  ];
  try {
    entries.push(...controlledStrings(JSON.parse(request.body ?? "")));
  } catch {
    // Non-JSON bodies remain covered by their raw representation.
  }
  return entries.some((entry) => entry.includes(value) || decodeRequestText(entry).includes(value));
}

export function controlledStrings(value: ProofCheck["actual"]): string[] {
  const stringValue = v.safeParse(stringSchema, value);
  if (stringValue.success) return [stringValue.output];
  if (Array.isArray(value)) return value.flatMap(controlledStrings);
  const object = v.safeParse(jsonObjectSchema, value);
  if (object.success)
    return Object.entries(object.output).flatMap(([name, entry]) => [
      name,
      ...controlledStrings(entry),
    ]);
  return [];
}

export function sameConcreteRequest(
  left: Finding["reproduction"][number] | undefined,
  right: Finding["reproduction"][number] | undefined,
): boolean {
  if (!left || !right) return false;
  return (
    canonicalJson({ ...left, path: canonicalRequestPath(left.path), sampleId: undefined }) ===
    canonicalJson({ ...right, path: canonicalRequestPath(right.path), sampleId: undefined })
  );
}

export function sameRequestAcrossActors(
  left: Finding["reproduction"][number] | undefined,
  right: Finding["reproduction"][number] | undefined,
): boolean {
  if (
    !left ||
    !right ||
    !hasUniqueHeaderNames(left.headers) ||
    !hasUniqueHeaderNames(right.headers)
  ) {
    return false;
  }
  const normalized = (request: Finding["reproduction"][number]) => ({
    path: canonicalRequestPath(request.path),
    method: request.method ?? "GET",
    headers: normalizeHeaders(request.headers),
    body: request.body,
  });
  return canonicalJson(normalized(left)) === canonicalJson(normalized(right));
}

export function canonicalRequestPath(path: string): string {
  const url = new URL(path, "http://proof.invalid");
  url.searchParams.sort();
  return `${url.pathname}${url.search}`;
}

export function decodeRequestText(value: string): string {
  try {
    return decodeURIComponent(value.replaceAll("+", " "));
  } catch {
    return value;
  }
}

export type ProofRequest = {
  path: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  actorId: ActorId;
};

export function requestsShareMutationContract(
  left: ProofRequest | undefined,
  right: ProofRequest | undefined,
  mutation: RequestMutation,
): boolean {
  if (!left || !right) return false;
  const leftNormalized = requestWithoutMutation(left, mutation);
  const rightNormalized = requestWithoutMutation(right, mutation);
  return (
    leftNormalized !== undefined &&
    leftNormalized === rightNormalized &&
    hasUniqueHeaderNames(left.headers) &&
    hasUniqueHeaderNames(right.headers) &&
    (left.method ?? "GET") === (right.method ?? "GET") &&
    left.actorId === right.actorId &&
    canonicalJson(normalizeHeaders(left.headers)) === canonicalJson(normalizeHeaders(right.headers))
  );
}
