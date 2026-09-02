import type { RequestMutation } from "./state.ts";
import type { ProofRequest } from "./proof-request-comparison.ts";
import { canonicalJson } from "./proof-json.ts";

const jsonObjectSchema = v.record(v.string(), v.unknown());
const stringSchema = v.string();

export function requestMutationValue(
  request: Pick<ProofRequest, "path" | "body"> | undefined,
  mutation: {
    location: "query" | "json-body" | "fragment";
    parameter: string;
  },
): string | undefined {
  if (!request) return undefined;
  if (mutation.location === "query") {
    const values = new URL(request.path, "http://proof.invalid").searchParams.getAll(
      mutation.parameter,
    );
    return values.length === 1 ? values[0] : undefined;
  }
  if (mutation.location === "fragment") {
    const values = new URLSearchParams(
      new URL(request.path, "http://proof.invalid").hash.slice(1),
    ).getAll(mutation.parameter);
    return values.length === 1 ? values[0] : undefined;
  }
  const body = parseJsonObject(request.body);
  const value = body?.[mutation.parameter];
  const parsed = v.safeParse(stringSchema, value);
  return parsed.success ? parsed.output : undefined;
}

export function requestWithoutMutation(
  request: Pick<ProofRequest, "path" | "body">,
  mutation: RequestMutation,
): string | undefined {
  const marker = "__QUIVER_PROOF_MUTATION__";
  const url = new URL(request.path, "http://proof.invalid");
  if (mutation.location === "query") {
    if (url.searchParams.getAll(mutation.parameter).length !== 1) return undefined;
    url.searchParams.set(mutation.parameter, marker);
    url.searchParams.sort();
    return canonicalJson({ path: `${url.pathname}${url.search}`, body: request.body });
  }
  const body = parseJsonObject(request.body);
  if (!body || !v.safeParse(stringSchema, body[mutation.parameter]).success) return undefined;
  return canonicalJson({
    path: `${url.pathname}${url.search}`,
    body: { ...body, [mutation.parameter]: marker },
  });
}

export function parseJsonObject(value: string | undefined) {
  if (value === undefined) return undefined;
  try {
    const parsed = v.safeParse(jsonObjectSchema, JSON.parse(value));
    return parsed.success ? parsed.output : undefined;
  } catch {
    return undefined;
  }
}

export function hasUniqueHeaderNames(headers: Record<string, string> | undefined): boolean {
  const names = Object.keys(headers ?? {}).map((name) => name.toLowerCase());
  return new Set(names).size === names.length;
}

export function normalizeHeaders(
  headers: Record<string, string> | undefined,
): Array<[string, string]> {
  return Object.entries(headers ?? {})
    .map(([name, value]): [string, string] => [name.toLowerCase(), value])
    .sort(([leftName, leftValue], [rightName, rightValue]) =>
      leftName === rightName
        ? leftValue.localeCompare(rightValue)
        : leftName.localeCompare(rightName),
    );
}
import * as v from "valibot";
