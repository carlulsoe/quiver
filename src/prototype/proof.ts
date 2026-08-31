import type {
  Finding,
  FindingCategory,
  ProofCheck,
  ProofPredicate,
  ProofResult,
  RequestMutation,
  ValidationObservation,
} from "./state.ts";
import { hasPotentialAuthenticationHeaders } from "./scoped-target.ts";

/** Code-owned compatibility is the first vulnerability-specific validation boundary. */
export const compatiblePredicates: Record<FindingCategory, readonly ProofPredicate["type"][]> = {
  "broken-object-authorization": ["cross-principal-access", "unauthenticated-success"],
  "broken-function-authorization": ["cross-principal-access", "unauthenticated-success"],
  "authentication-bypass": [],
  "excessive-data-exposure": ["cross-principal-data-exposure", "internal-field-exposure"],
  "sensitive-data-exposure": ["cross-principal-data-exposure", "internal-field-exposure"],
  "cross-site-scripting": [],
  "sql-injection": [],
  "command-injection": [],
  "server-side-request-forgery": [],
  "path-traversal": [],
  "open-redirect": [],
  "cross-site-request-forgery": [],
  "business-logic": [],
  "security-misconfiguration": ["unauthenticated-success"],
  other: [],
};

export function evaluateProof(
  finding: Pick<Finding, "category" | "endpoint" | "method" | "proof" | "reproduction">,
  observations: readonly ValidationObservation[],
): ProofResult {
  const checks: ProofCheck[] = [
    check(
      compatiblePredicates[finding.category].includes(finding.proof.type),
      `predicate ${finding.proof.type} is compatible with ${finding.category}`,
    ),
    check(
      observations.length === finding.reproduction.length,
      "every reproduction request was replayed",
      `${observations.length}/${finding.reproduction.length}`,
    ),
    check(
      finding.reproduction.some(
        ({ path, method }) =>
          endpointMatchesRequest(finding.endpoint, path) &&
          (method ?? "GET") === (finding.method ?? "GET"),
      ),
      "affected operation matches a reproduction request",
    ),
    check(!observations.some(({ truncated }) => truncated), "proof responses were not truncated"),
  ];

  switch (finding.proof.type) {
    case "cross-principal-access": {
      const actor = selectedValue(observations, finding.proof.actor);
      const owner = selectedValue(observations, finding.proof.resourceOwner);
      const access = observations[finding.proof.accessRequestIndex];
      checks.push(
        check(
          finding.reproduction[finding.proof.actor.requestIndex]?.authenticated === true,
          "actor identity was established in an authenticated request",
        ),
        check(actor.found && isScalar(actor.value), "actor identity exists", actor.value),
        check(owner.found && isScalar(owner.value), "resource-owner identity exists", owner.value),
        check(
          actor.found && owner.found && !sameValue(actor.value, owner.value),
          "actor and resource owner are different principals",
          actor.found && owner.found
            ? `${String(actor.value)} != ${String(owner.value)}`
            : undefined,
        ),
        check(
          access !== undefined && isSuccess(access.status),
          "cross-principal request returned a successful response",
          access?.status,
        ),
        check(
          finding.reproduction[finding.proof.accessRequestIndex]?.authenticated === true,
          "cross-principal access used the authenticated actor session",
        ),
        ...pointerChecks(access, finding.proof.evidencePointers),
      );
      break;
    }
    case "unauthenticated-success": {
      const observation = observations[finding.proof.requestIndex];
      const request = finding.reproduction[finding.proof.requestIndex];
      checks.push(
        check(
          request !== undefined &&
            !request.authenticated &&
            ["GET", "HEAD"].includes(request.method ?? "GET") &&
            request.body === undefined &&
            !hasPotentialAuthenticationHeaders(request.headers),
          "bodyless GET/HEAD request was sent without authentication",
        ),
        check(
          observation !== undefined && isSuccess(observation.status),
          "unauthenticated request returned a successful response",
          observation?.status,
        ),
        ...pointerChecks(observation, finding.proof.evidencePointers),
      );
      break;
    }
    case "cross-principal-data-exposure": {
      const actor = selectedValue(observations, finding.proof.actor);
      const subject = selectedValue(observations, finding.proof.exposedSubject);
      const observation = observations[finding.proof.responseRequestIndex];
      checks.push(
        check(
          finding.reproduction[finding.proof.actor.requestIndex]?.authenticated === true,
          "actor identity was established in an authenticated request",
        ),
        check(actor.found && isScalar(actor.value), "actor identity exists", actor.value),
        check(
          subject.found && isScalar(subject.value),
          "exposed-subject identity exists",
          subject.value,
        ),
        check(
          actor.found && subject.found && !sameValue(actor.value, subject.value),
          "actor and exposed subject are different principals",
          actor.found && subject.found
            ? `${String(actor.value)} != ${String(subject.value)}`
            : undefined,
        ),
        check(
          observation !== undefined && isSuccess(observation.status),
          "cross-principal data response returned successfully",
          observation?.status,
        ),
        check(
          finding.reproduction[finding.proof.responseRequestIndex]?.authenticated === true,
          "cross-principal data was observed in the authenticated actor session",
        ),
        ...pointerChecks(observation, finding.proof.evidencePointers),
      );
      break;
    }
    case "internal-field-exposure": {
      const observation = observations[finding.proof.requestIndex];
      checks.push(
        check(
          observation !== undefined && isSuccess(observation.status),
          "evidence response returned a successful response",
          observation?.status,
        ),
        check(finding.proof.evidencePointers.length > 0, "at least one exposed field was declared"),
        ...pointerChecks(observation, finding.proof.evidencePointers),
      );
      break;
    }
    case "timing-differential": {
      const controlDurations = selectedDurations(observations, finding.proof.controlRequestIndexes);
      const probeDurations = selectedDurations(observations, finding.proof.probeRequestIndexes);
      const controlMedian = median(controlDurations);
      const probeMedian = median(probeDurations);
      const delta =
        controlMedian === undefined || probeMedian === undefined
          ? undefined
          : probeMedian - controlMedian;
      checks.push(
        check(
          distinctSampleCount(finding.reproduction, finding.proof.controlRequestIndexes) >= 3,
          "control timing requests use three distinct sample identifiers",
        ),
        check(
          distinctSampleCount(finding.reproduction, finding.proof.probeRequestIndexes) >= 3,
          "probe timing requests use three distinct sample identifiers",
        ),
        check(
          distinctSampleCount(finding.reproduction, [
            ...finding.proof.controlRequestIndexes,
            ...finding.proof.probeRequestIndexes,
          ]) >= 6,
          "control and probe sample identifiers are disjoint",
        ),
        check(
          new Set(finding.proof.controlRequestIndexes).size >= 3,
          "at least three distinct control samples were replayed",
          controlDurations,
        ),
        check(
          new Set(finding.proof.probeRequestIndexes).size >= 3,
          "at least three distinct probe samples were replayed",
          probeDurations,
        ),
        check(
          controlDurations.length === finding.proof.controlRequestIndexes.length,
          "every control sample has timing evidence",
          controlDurations,
        ),
        check(
          probeDurations.length === finding.proof.probeRequestIndexes.length,
          "every probe sample has timing evidence",
          probeDurations,
        ),
        check(
          delta !== undefined && delta >= finding.proof.minimumDeltaMs,
          `probe median is at least ${finding.proof.minimumDeltaMs}ms slower than control median`,
          delta,
        ),
        ...timingDifferentialSecurityChecks(finding, observations),
      );
      break;
    }
  }

  const passed = checks.every((item) => item.passed);
  return {
    predicate: finding.proof.type,
    passed,
    summary: passed
      ? `Deterministic ${finding.proof.type} predicate passed ${checks.length}/${checks.length} checks.`
      : `Deterministic ${finding.proof.type} predicate failed ${checks.filter((item) => !item.passed).length}/${checks.length} checks.`,
    checks,
  };
}

function timingDifferentialSecurityChecks(
  finding: Pick<Finding, "category" | "endpoint" | "method" | "proof" | "reproduction">,
  observations: readonly ValidationObservation[],
): ProofCheck[] {
  if (finding.proof.type !== "timing-differential") return [];
  const proof = finding.proof;
  const controls = proof.controlRequestIndexes.map((index) => finding.reproduction[index]);
  const probes = proof.probeRequestIndexes.map((index) => finding.reproduction[index]);
  const requestedDelayMs =
    finding.category === "sql-injection"
      ? sqlDelayMs(proof.mutation.probeValue)
      : commandDelayMs(proof.mutation.probeValue);
  const controlDelayMs =
    finding.category === "sql-injection"
      ? sqlDelayMs(proof.mutation.controlValue)
      : commandDelayMs(proof.mutation.controlValue);
  const orderedCohorts = [
    ...proof.controlRequestIndexes.map((index) => ({ index, cohort: "control" })),
    ...proof.probeRequestIndexes.map((index) => ({ index, cohort: "probe" })),
  ].sort((left, right) => left.index - right.index);
  const chronologicalPairs = Array.from(
    { length: 3 },
    (_, index) => [orderedCohorts[index * 2], orderedCohorts[index * 2 + 1]] as const,
  );
  const pairedDeltas = chronologicalPairs.flatMap(([controlSample, probeSample]) => {
    const control = observations[controlSample?.index ?? -1]?.durationMs;
    const probe = observations[probeSample?.index ?? -1]?.durationMs;
    return control === undefined || probe === undefined ? [] : [probe - control];
  });
  return [
    check(
      finding.reproduction.length === 6 && orderedCohorts.length === 6,
      "timing differential is a closed six-request reproduction",
    ),
    check(
      [...controls, ...probes].every((request) => affectedOperationMatches(finding, request)),
      "timing differential requests match the affected operation",
    ),
    check(
      proof.mutation.controlValue !== proof.mutation.probeValue,
      "timing control and probe mutation values are different",
    ),
    check(controlDelayMs === undefined, "timing control contains no recognized delay payload"),
    check(
      controls.every(
        (request) =>
          request !== undefined &&
          requestMutationValue(request, proof.mutation) === proof.mutation.controlValue,
      ),
      `${finding.category} controls contain no delay payload`,
    ),
    check(
      probes.every(
        (request) =>
          request !== undefined &&
          requestMutationValue(request, proof.mutation) === proof.mutation.probeValue,
      ),
      `${finding.category} probes contain recognized delay payloads`,
    ),
    check(
      [...controls, ...probes].every((request) =>
        requestsShareMutationShape(controls[0], request, proof.mutation),
      ),
      "timing controls and probes differ only by the declared mutation",
    ),
    check(
      requestedDelayMs !== undefined && requestedDelayMs >= 1_000,
      "timing probe requests a code-recognized delay of at least 1000ms",
      requestedDelayMs,
    ),
    check(
      requestedDelayMs !== undefined && proof.minimumDeltaMs >= requestedDelayMs * 0.5,
      "timing threshold is at least half of the requested delay",
      proof.minimumDeltaMs,
    ),
    check(
      chronologicalPairs.every(
        ([controlSample, probeSample], pairIndex) =>
          controlSample?.cohort === "control" &&
          probeSample?.cohort === "probe" &&
          controlSample.index === pairIndex * 2 &&
          probeSample.index === pairIndex * 2 + 1,
      ),
      "timing requests are ordered as three adjacent control-probe pairs",
    ),
    check(
      pairedDeltas.length >= 3 &&
        pairedDeltas.every((delta) => delta >= proof.minimumDeltaMs * 0.8),
      "every paired probe has a conservative timing gap",
      pairedDeltas,
    ),
  ];
}

function affectedOperationMatches(
  finding: Pick<Finding, "endpoint" | "method">,
  request: Pick<ProofRequest, "path" | "method"> | undefined,
): boolean {
  return (
    request !== undefined &&
    (request.method ?? "GET") === (finding.method ?? "GET") &&
    endpointMatchesRequest(finding.endpoint, request.path)
  );
}

type ProofRequest = {
  path: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  authenticated: boolean;
};

function requestsShareMutationShape(
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
    left.authenticated === right.authenticated &&
    canonicalJson(normalizeHeaders(left.headers)) === canonicalJson(normalizeHeaders(right.headers))
  );
}

function requestMutationValue(
  request: Pick<ProofRequest, "path" | "body"> | undefined,
  mutation: RequestMutation,
): string | undefined {
  if (!request) return undefined;
  if (mutation.location === "query") {
    const values = new URL(request.path, "http://proof.invalid").searchParams.getAll(
      mutation.parameter,
    );
    return values.length === 1 ? values[0] : undefined;
  }
  const body = parseJsonObject(request.body);
  const value = body?.[mutation.parameter];
  return typeof value === "string" ? value : undefined;
}

function requestWithoutMutation(
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
  if (!body || typeof body[mutation.parameter] !== "string") return undefined;
  return canonicalJson({
    path: `${url.pathname}${url.search}`,
    body: { ...body, [mutation.parameter]: marker },
  });
}

function parseJsonObject(value: string | undefined): Record<string, unknown> | undefined {
  if (value === undefined) return undefined;
  try {
    const parsed: unknown = JSON.parse(value);
    return parsed !== null && !Array.isArray(parsed) && typeof parsed === "object"
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function hasUniqueHeaderNames(headers: Record<string, string> | undefined): boolean {
  const names = Object.keys(headers ?? {}).map((name) => name.toLowerCase());
  return new Set(names).size === names.length;
}

function normalizeHeaders(headers: Record<string, string> | undefined): Array<[string, string]> {
  return Object.entries(headers ?? {})
    .map(([name, value]): [string, string] => [name.toLowerCase(), value])
    .sort(([leftName, leftValue], [rightName, rightValue]) =>
      leftName === rightName
        ? leftValue.localeCompare(rightValue)
        : leftName.localeCompare(rightName),
    );
}

function sqlDelayMs(value: string): number | undefined {
  const seconds = value.match(/\b(?:sleep|pg_sleep)\s*\(\s*(\d+(?:\.\d+)?)\s*\)/i)?.[1];
  const waitfor = value.match(/\bwaitfor\s+delay\s+['"]\d{1,2}:\d{2}:(\d{2})['"]/i)?.[1];
  const delay = Number(seconds ?? waitfor);
  return Number.isFinite(delay) && delay > 0 ? delay * 1_000 : undefined;
}

function commandDelayMs(value: string): number | undefined {
  const seconds = value.match(/(?:;|&&|\|\||\||\r|\n)\s*sleep\s+(\d+(?:\.\d+)?)(?:\s|$)/i)?.[1];
  const delay = Number(seconds);
  return Number.isFinite(delay) && delay > 0 ? delay * 1_000 : undefined;
}

function distinctSampleCount(
  requests: readonly { sampleId?: string }[],
  indexes: readonly number[],
): number {
  return new Set(indexes.flatMap((index) => requests[index]?.sampleId ?? [])).size;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? String(value);
}

function selectedDurations(
  observations: readonly ValidationObservation[],
  indexes: readonly number[],
): number[] {
  return indexes.flatMap((index) => {
    const duration = observations[index]?.durationMs;
    return typeof duration === "number" && Number.isFinite(duration) && duration >= 0
      ? [duration]
      : [];
  });
}

function median(values: readonly number[]): number | undefined {
  if (values.length === 0) return undefined;
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1]! + sorted[middle]!) / 2 : sorted[middle];
}

function pointerChecks(
  observation: ValidationObservation | undefined,
  pointers: readonly string[],
): ProofCheck[] {
  return pointers.map((pointer) => {
    const selected = observation ? jsonPointer(observation.body, pointer) : { found: false };
    return check(selected.found, `response contains ${pointer}`, selected.value);
  });
}

function selectedValue(
  observations: readonly ValidationObservation[],
  selector: { requestIndex: number; jsonPointer: string },
): { found: boolean; value?: unknown } {
  const observation = observations[selector.requestIndex];
  return observation ? jsonPointer(observation.body, selector.jsonPointer) : { found: false };
}

function jsonPointer(value: unknown, pointer: string): { found: boolean; value?: unknown } {
  if (pointer === "") return { found: true, value };
  if (!pointer.startsWith("/")) return { found: false };
  let current = value;
  for (const encodedToken of pointer.slice(1).split("/")) {
    const token = encodedToken.replaceAll("~1", "/").replaceAll("~0", "~");
    if (Array.isArray(current)) {
      if (!/^(?:0|[1-9]\d*)$/.test(token)) return { found: false };
      const index = Number(token);
      if (index >= current.length) return { found: false };
      current = current[index];
    } else if (current !== null && typeof current === "object") {
      if (!Object.hasOwn(current, token)) return { found: false };
      current = (current as Record<string, unknown>)[token];
    } else {
      return { found: false };
    }
  }
  return { found: true, value: current };
}

function check(passed: boolean, description: string, actual?: unknown): ProofCheck {
  return { description, passed, ...(actual === undefined ? {} : { actual }) };
}

function isScalar(value: unknown): boolean {
  return value !== null && ["string", "number", "boolean"].includes(typeof value);
}

function sameValue(left: unknown, right: unknown): boolean {
  return typeof left === typeof right && left === right;
}

function isSuccess(status: number): boolean {
  return status >= 200 && status < 300;
}

function endpointMatchesRequest(endpoint: string, requestPath: string): boolean {
  try {
    const endpointSegments = new URL(endpoint, "http://proof.invalid").pathname.split("/");
    const requestSegments = new URL(requestPath, "http://proof.invalid").pathname.split("/");
    return (
      endpointSegments.length === requestSegments.length &&
      endpointSegments.every(
        (segment, index) =>
          /^(?:<[^>]+>|\{[^}]+\}|:[A-Za-z_$][\w$]*)$/.test(decodeURIComponent(segment)) ||
          segment === requestSegments[index],
      )
    );
  } catch {
    return false;
  }
}
