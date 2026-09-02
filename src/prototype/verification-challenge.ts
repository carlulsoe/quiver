import * as v from "valibot";
import type { Finding, ReproductionRequest } from "./state.ts";

const jsonObjectSchema = v.record(v.string(), v.unknown());
const stringSchema = v.string();

export function challengeFromRequest(
  request: Pick<ReproductionRequest, "path" | "body">,
  mutation: { location: "query" | "json-body"; parameter: string; template: string },
): number | undefined {
  let value;
  if (mutation.location === "query") {
    const values = new URL(request.path, "http://verification.invalid").searchParams.getAll(
      mutation.parameter,
    );
    if (values.length !== 1) return undefined;
    value = values[0];
  } else {
    try {
      const parsed = v.safeParse(jsonObjectSchema, JSON.parse(request.body ?? ""));
      if (!parsed.success) return undefined;
      value = parsed.output[mutation.parameter];
    } catch {
      return undefined;
    }
  }
  const parsedValue = v.safeParse(stringSchema, value);
  if (!parsedValue.success) return undefined;
  const parts = mutation.template.split("{{challenge}}");
  if (parts.length !== 2) return undefined;
  const [prefix = "", suffix = ""] = parts;
  if (!parsedValue.output.startsWith(prefix) || !parsedValue.output.endsWith(suffix))
    return undefined;
  const encoded = parsedValue.output.slice(
    prefix.length,
    parsedValue.output.length - suffix.length,
  );
  return /^(?:0|[1-9]\d*)$/.test(encoded) ? Number(encoded) : undefined;
}

export function replaceVerificationChallenge(
  finding: Finding,
  requestIndex: number,
  mutation: { location: "query" | "json-body"; parameter: string; template: string },
  challenge: string,
  proof: Finding["proof"],
): Finding {
  const request = finding.reproduction[requestIndex];
  if (!request || mutation.template.split("{{challenge}}").length !== 2) return finding;
  const replacement = mutation.template.replace("{{challenge}}", challenge);
  const nextRequest = { ...request };
  if (mutation.location === "query") {
    const url = new URL(request.path, "http://verification.invalid");
    if (url.searchParams.getAll(mutation.parameter).length !== 1) return finding;
    url.searchParams.set(mutation.parameter, replacement);
    nextRequest.path = `${url.pathname}${url.search}${url.hash}`;
  } else {
    try {
      const parsed = v.safeParse(jsonObjectSchema, JSON.parse(request.body ?? ""));
      if (!parsed.success) return finding;
      nextRequest.body = JSON.stringify({
        ...parsed.output,
        [mutation.parameter]: replacement,
      });
    } catch {
      return finding;
    }
  }
  return {
    ...finding,
    proof,
    reproduction: finding.reproduction.map((candidate, index) =>
      index === requestIndex ? nextRequest : candidate,
    ),
  };
}
