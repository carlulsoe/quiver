import type {
  Finding,
  FindingCategory,
  ProofCheck,
  ProofPredicate,
  ProofResult,
  ValidationObservation,
} from "./state.ts";

const compatiblePredicates: Record<FindingCategory, readonly ProofPredicate["type"][]> = {
  "broken-object-authorization": ["cross-principal-access", "unauthenticated-success"],
  "broken-function-authorization": ["cross-principal-access", "unauthenticated-success"],
  "excessive-data-exposure": ["cross-principal-data-exposure", "internal-field-exposure"],
  "sensitive-data-exposure": ["cross-principal-data-exposure", "internal-field-exposure"],
  "security-misconfiguration": ["unauthenticated-success"],
  other: ["unauthenticated-success"],
};

export function evaluateProof(
  finding: Pick<Finding, "category" | "endpoint" | "proof" | "reproduction">,
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
      finding.reproduction.some(({ path }) => endpointMatchesRequest(finding.endpoint, path)),
      "affected endpoint matches a reproduction request",
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
          request !== undefined && !request.authenticated,
          "request was sent without authentication",
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
