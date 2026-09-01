import type {
  Finding,
  FindingCategory,
  ProofCheck,
  ProofArtifacts,
  ProofPredicate,
  ProofResult,
  RequestMutation,
  ValidationObservation,
} from "./state.ts";
import { hasPotentialAuthenticationHeaders } from "./scoped-target.ts";
import { browserPolicyPath, type ProofPolicy } from "./target-profile.ts";
import { impactSafetyChecks } from "./impact.ts";
import type { ImpactLevel } from "./state.ts";
import { endpointMatchesRequest } from "./endpoint.ts";
import { actorIds, type ActorId } from "./sessions.ts";

/** Code-owned compatibility is the first vulnerability-specific validation boundary. */
export const compatiblePredicates: Record<FindingCategory, readonly ProofPredicate["type"][]> = {
  "broken-object-authorization": ["cross-principal-access", "unauthenticated-success"],
  "broken-function-authorization": ["cross-principal-access", "unauthenticated-success"],
  "authentication-bypass": [],
  "excessive-data-exposure": [
    "cross-principal-data-exposure",
    "internal-field-exposure",
    "canary-retrieval",
  ],
  "sensitive-data-exposure": [
    "cross-principal-data-exposure",
    "internal-field-exposure",
    "canary-retrieval",
  ],
  "cross-site-scripting": ["browser-visible-effect"],
  "sql-injection": ["sql-semantic-differential"],
  "command-injection": ["command-execution-challenge"],
  "server-side-request-forgery": ["oast-callback"],
  "path-traversal": ["canary-retrieval"],
  "open-redirect": [],
  "cross-site-request-forgery": [],
  "business-logic": ["state-transition"],
  "security-misconfiguration": ["unauthenticated-success"],
  other: [],
};

export interface ProofEvaluationContext {
  policies?: readonly ProofPolicy[];
  artifacts?: ProofArtifacts;
  stateResetAvailable?: boolean;
  maximumImpactLevel?: ImpactLevel;
}

export function evaluateProof(
  finding: Pick<
    Finding,
    "category" | "endpoint" | "method" | "impactLevel" | "proof" | "reproduction"
  >,
  observations: readonly ValidationObservation[],
  context: ProofEvaluationContext = {},
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
    check(
      observations.every(
        (observation, index) => observation.actorId === finding.reproduction[index]?.actorId,
      ),
      "every replay observation used its declared actor session",
    ),
  ];
  if (context.maximumImpactLevel) {
    checks.push(...impactSafetyChecks(finding, context.maximumImpactLevel));
  }

  switch (finding.proof.type) {
    case "cross-principal-access": {
      const actor = selectedValue(observations, finding.proof.actor);
      const owner = selectedValue(observations, finding.proof.resourceOwner);
      const access = observations[finding.proof.accessRequestIndex];
      checks.push(
        check(
          finding.reproduction[finding.proof.actor.requestIndex]?.actorId !== actorIds.anonymous,
          "actor identity was established in a named actor session",
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
          finding.reproduction[finding.proof.accessRequestIndex]?.actorId ===
            finding.reproduction[finding.proof.actor.requestIndex]?.actorId &&
            finding.reproduction[finding.proof.accessRequestIndex]?.actorId !== actorIds.anonymous,
          "cross-principal access used the identified actor session",
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
            request.actorId === actorIds.anonymous &&
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
          finding.reproduction[finding.proof.actor.requestIndex]?.actorId !== actorIds.anonymous,
          "actor identity was established in a named actor session",
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
          finding.reproduction[finding.proof.responseRequestIndex]?.actorId ===
            finding.reproduction[finding.proof.actor.requestIndex]?.actorId &&
            finding.reproduction[finding.proof.responseRequestIndex]?.actorId !==
              actorIds.anonymous,
          "cross-principal data was observed in the identified actor session",
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
    case "sql-semantic-differential": {
      const proof = finding.proof;
      const policy = policyFor(context.policies, proof.policyId, "sql-semantic-differential");
      const controlRequest = finding.reproduction[proof.controlRequestIndex];
      const probeRequest = finding.reproduction[proof.probeRequestIndex];
      const controlObservation = observations[proof.controlRequestIndex];
      const probeObservation = observations[proof.probeRequestIndex];
      const controlResult = policy
        ? selectedAt(observations, proof.controlRequestIndex, policy.response.jsonPointer)
        : { found: false };
      const probeResult = policy
        ? selectedAt(observations, proof.probeRequestIndex, policy.response.jsonPointer)
        : { found: false };
      checks.push(
        check(
          policy?.category === finding.category,
          "target policy authorizes this SQL semantic differential",
        ),
        check(
          policy !== undefined &&
            finding.reproduction.length === 2 &&
            proof.controlRequestIndex === 0 &&
            proof.probeRequestIndex === 1,
          "SQL proof is one closed adjacent control-probe pair",
        ),
        check(
          policy !== undefined &&
            [controlRequest, probeRequest].every(
              (request) =>
                request !== undefined &&
                (request.method ?? "GET") === policy.method &&
                endpointMatchesRequest(policy.endpoint, request.path) &&
                affectedOperationMatches(finding, request),
            ),
          "SQL control and probe match the policy-bound affected operation",
        ),
        check(
          policy !== undefined &&
            requestMutationValue(controlRequest, policy.mutation) ===
              policy.mutation.controlValue &&
            requestMutationValue(probeRequest, policy.mutation) === policy.mutation.probeValue,
          "SQL requests use the target-owned control and probe predicates",
        ),
        check(
          policy !== undefined &&
            requestsShareMutationShape(controlRequest, probeRequest, policy.mutation),
          "SQL control and probe differ only by the policy-owned mutation",
        ),
        check(
          controlObservation !== undefined &&
            probeObservation !== undefined &&
            isSuccess(controlObservation.status) &&
            isSuccess(probeObservation.status),
          "SQL control and probe both returned successful responses",
        ),
        check(
          policy !== undefined &&
            controlResult.found &&
            sameValue(controlResult.value, policy.response.controlValue),
          "SQL control produced the target-owned semantic result",
          controlResult.value,
        ),
        check(
          policy !== undefined &&
            probeResult.found &&
            sameValue(probeResult.value, policy.response.probeValue),
          "SQL probe produced the target-owned semantic result",
          probeResult.value,
        ),
      );
      break;
    }
    case "command-execution-challenge": {
      const proof = finding.proof;
      const policy = policyFor(context.policies, proof.policyId, "command-execution-challenge");
      const request = finding.reproduction[proof.requestIndex];
      const observation = observations[proof.requestIndex];
      const selected = policy
        ? selectedAt(observations, proof.requestIndex, policy.outputJsonPointer)
        : { found: false };
      const expectedOutput = policy ? commandChallengeOutput(policy, proof.challenge) : undefined;
      checks.push(
        check(
          policy?.category === finding.category,
          "target policy authorizes this command-execution challenge",
        ),
        check(
          policy !== undefined &&
            Number.isSafeInteger(proof.challenge) &&
            proof.challenge >= policy.challengeMinimum &&
            proof.challenge <= policy.challengeMaximum &&
            expectedOutput !== undefined,
          "command challenge is a bounded policy-owned arithmetic input",
          proof.challenge,
        ),
        check(
          policy !== undefined &&
            finding.reproduction.length === 1 &&
            proof.requestIndex === 0 &&
            request !== undefined &&
            (request.method ?? "GET") === policy.method &&
            endpointMatchesRequest(policy.endpoint, request.path) &&
            affectedOperationMatches(finding, request),
          "command challenge is one policy-bound affected operation",
        ),
        check(
          policy !== undefined &&
            challengeRequestMatches(request, policy.challenge, String(proof.challenge)),
          "request uses the target-owned command template",
        ),
        check(
          observation !== undefined && isSuccess(observation.status),
          "command challenge returned a successful response",
          observation?.status,
        ),
        check(
          selected.found &&
            typeof selected.value === "string" &&
            expectedOutput !== undefined &&
            selected.value.includes(expectedOutput),
          "response contains the computed command-execution result",
          selected.value,
        ),
        check(
          request !== undefined &&
            expectedOutput !== undefined &&
            !requestContains(request, expectedOutput),
          "computed command result was not present in the request",
          expectedOutput,
        ),
      );
      break;
    }
    case "canary-retrieval": {
      const policy = policyFor(context.policies, finding.proof.policyId, "canary");
      const observation = observations[finding.proof.requestIndex];
      const selected = observation
        ? jsonPointer(observation.body, finding.proof.jsonPointer)
        : { found: false };
      const canaryValue = typeof selected.value === "string" ? selected.value : undefined;
      const request = finding.reproduction[finding.proof.requestIndex];
      checks.push(
        check(policy?.category === finding.category, "target policy authorizes this canary proof"),
        check(
          policy?.source === "immutable-fixture" &&
            finding.proof.jsonPointer === policy.jsonPointer &&
            finding.reproduction.length === 1 &&
            request !== undefined &&
            ["GET", "HEAD"].includes(request.method ?? "GET") &&
            request.body === undefined &&
            Object.keys(request.headers ?? {}).length === 0 &&
            new URL(request.path, "http://proof.invalid").search === "",
          "canary comes from an immutable fixture through one bodyless headerless read",
        ),
        check(
          policy !== undefined &&
            request !== undefined &&
            (request.method ?? "GET") === policy.method &&
            endpointMatchesRequest(policy.endpoint, request.path) &&
            affectedOperationMatches(finding, request),
          "canary retrieval request matches the policy and affected operation",
        ),
        check(selected.found && typeof selected.value === "string", "canary value was retrieved"),
        check(
          policy !== undefined &&
            request !== undefined &&
            canaryValue !== undefined &&
            !finding.reproduction.some((candidate) => requestContains(candidate, canaryValue)) &&
            verifyCanary(policy, canaryValue),
          "retrieved value passes the verifier-only canary contract and was not reflected",
          selected.value,
        ),
      );
      break;
    }
    case "state-transition": {
      const policy = policyFor(context.policies, finding.proof.policyId, "state-transition");
      const before = policy
        ? selectedAt(observations, finding.proof.beforeRequestIndex, policy.jsonPointer)
        : { found: false };
      const after = policy
        ? selectedAt(observations, finding.proof.afterRequestIndex, policy.jsonPointer)
        : { found: false };
      const beforeObservation = observations[finding.proof.beforeRequestIndex];
      const transitionObservation = observations[finding.proof.transitionRequestIndex];
      const afterObservation = observations[finding.proof.afterRequestIndex];
      const transition = finding.reproduction[finding.proof.transitionRequestIndex];
      checks.push(
        check(policy?.category === finding.category, "target policy authorizes this state proof"),
        check(
          policy !== undefined &&
            ["POST", "PUT", "PATCH"].includes(policy.method) &&
            ["GET", "HEAD"].includes(policy.readMethod),
          "state policy separates an explicit mutating operation from read-only state checks",
        ),
        check(
          context.stateResetAvailable === true,
          "target provides a fresh-state preparation hook for validation",
        ),
        check(
          finding.reproduction.length === 3 &&
            finding.proof.beforeRequestIndex === 0 &&
            finding.proof.transitionRequestIndex === 1 &&
            finding.proof.afterRequestIndex === 2,
          "state proof is a closed adjacent read-transition-read reproduction",
        ),
        check(
          policy !== undefined &&
            transition !== undefined &&
            (transition.method ?? "GET") === policy.method &&
            endpointMatchesRequest(policy.endpoint, transition.path) &&
            affectedOperationMatches(finding, transition),
          "declared transition request matches the protected operation",
        ),
        check(
          policy !== undefined &&
            [finding.proof.beforeRequestIndex, finding.proof.afterRequestIndex].every((index) => {
              const request = finding.reproduction[index];
              return (
                request !== undefined &&
                (request.method ?? "GET") === policy.readMethod &&
                endpointMatchesRequest(policy.readEndpoint, request.path)
              );
            }) &&
            sameConcreteRequest(
              finding.reproduction[finding.proof.beforeRequestIndex],
              finding.reproduction[finding.proof.afterRequestIndex],
            ),
          "before and after requests read the same policy-bound resource",
        ),
        check(
          beforeObservation !== undefined &&
            transitionObservation !== undefined &&
            afterObservation !== undefined &&
            isSuccess(beforeObservation.status) &&
            isSuccess(transitionObservation.status) &&
            isSuccess(afterObservation.status),
          "before, transition, and after operations all completed successfully",
        ),
        check(
          before.found && sameValue(before.value, policy?.before),
          "protected state starts at policy value",
          before.value,
        ),
        check(
          after.found && sameValue(after.value, policy?.after),
          "protected state reaches policy value",
          after.value,
        ),
      );
      break;
    }
    case "browser-visible-effect": {
      const proof = finding.proof;
      const policy = policyFor(context.policies, proof.policyId, "browser-effect");
      const pattern = policy ? safeRegex(policy.markerPattern) : undefined;
      const artifact = context.artifacts?.browserEffects.find(
        ({ probeId }) => probeId === proof.probeId,
      );
      checks.push(
        check(policy?.category === finding.category, "target policy authorizes this browser proof"),
        check(
          affectedOperationMatches(finding, finding.reproduction[proof.requestIndex]),
          "browser payload request matches the affected operation",
        ),
        check(
          policy !== undefined &&
            canonicalJson(proof.challenge) === canonicalJson(policy.challenge),
          "browser challenge uses the target-owned mutation and executable payload template",
        ),
        check(
          policy !== undefined && proof.pageActorId === policy.pageActorId,
          "browser page authentication matches the target policy",
        ),
        check(
          policy !== undefined && proof.collectorRequestBudget === policy.requestBudget,
          "browser collector request budget matches the target policy",
        ),
        check(
          canonicalJson(proof.pageChallenge) === canonicalJson(policy?.pageChallenge),
          "browser navigation challenge matches the target policy",
        ),
        check(
          proof.pageChallenge === undefined ||
            (finding.method === "GET" &&
              proof.requestIndex === 0 &&
              finding.reproduction.length === 1 &&
              proof.pagePath === finding.reproduction[proof.requestIndex]?.path &&
              challengePathMatches(proof.pagePath, proof.pageChallenge, proof.marker)),
          "reflected browser challenge is the exact affected GET request",
        ),
        check(
          challengeRequestMatches(
            finding.reproduction[proof.requestIndex],
            proof.challenge,
            proof.marker,
          ),
          "issued browser marker is bound to the declared request mutation",
        ),
        check(
          artifact !== undefined &&
            policy !== undefined &&
            policy.effect === "dialog" &&
            proof.kind === policy.effect &&
            artifact.kind === policy.effect &&
            browserPolicyPath(policy, proof.marker) === proof.pagePath &&
            artifact.path === proof.pagePath,
          "fresh browser artifact matches the policy effect and page",
        ),
        check(
          artifact?.value === proof.marker && pattern !== undefined && pattern.test(proof.marker),
          "browser effect contains the policy-approved marker",
          artifact?.value,
        ),
      );
      break;
    }
    case "oast-callback": {
      const proof = finding.proof;
      const policy = policyFor(context.policies, proof.policyId, "oast");
      const artifact = context.artifacts?.oastCallbacks.find(
        ({ probeId, token }) => probeId === proof.probeId && token === proof.token,
      );
      const request = finding.reproduction[proof.requestIndex];
      checks.push(
        check(policy?.category === finding.category, "target policy authorizes this OAST proof"),
        check(
          policy !== undefined &&
            canonicalJson(proof.challenge) === canonicalJson(policy.challenge),
          "OAST challenge uses the target-owned request mutation",
        ),
        check(
          policy !== undefined &&
            request !== undefined &&
            (request.method ?? "GET") === policy.method &&
            endpointMatchesRequest(policy.endpoint, request.path) &&
            affectedOperationMatches(finding, request),
          "OAST probe request matches the policy and affected operation",
        ),
        check(
          request !== undefined &&
            proof.callbackUrl.includes(proof.token) &&
            challengeRequestMatches(request, proof.challenge, proof.callbackUrl),
          "issued OAST callback URL is bound to the declared request mutation",
        ),
        check(
          artifact !== undefined && artifact.protocol === policy?.protocol,
          "fresh target callback reached the issued OAST probe",
          artifact?.path,
        ),
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

function policyFor<K extends ProofPolicy["kind"]>(
  policies: readonly ProofPolicy[] | undefined,
  id: string,
  kind: K,
): Extract<ProofPolicy, { kind: K }> | undefined {
  return policies?.find(
    (policy): policy is Extract<ProofPolicy, { kind: K }> =>
      policy.id === id && policy.kind === kind,
  );
}

function safeRegex(pattern: string): RegExp | undefined {
  if (pattern.length > 256) return undefined;
  try {
    return new RegExp(pattern);
  } catch {
    return undefined;
  }
}

function verifyCanary(policy: Extract<ProofPolicy, { kind: "canary" }>, value: string): boolean {
  try {
    return policy.verify(value);
  } catch {
    return false;
  }
}

function commandChallengeOutput(
  policy: Extract<ProofPolicy, { kind: "command-execution-challenge" }>,
  challenge: number,
): string | undefined {
  const result = challenge * policy.multiplier + policy.addend;
  return Number.isSafeInteger(result) ? `${policy.outputPrefix}${result}` : undefined;
}

function challengeRequestMatches(
  request: ProofRequest | undefined,
  challenge: { location: "query" | "json-body"; parameter: string; template: string },
  value: string,
): boolean {
  return (
    challenge.template.split("{{challenge}}").length === 2 &&
    requestMutationValue(request, challenge) === challenge.template.replace("{{challenge}}", value)
  );
}

function challengePathMatches(
  path: string,
  challenge: { location: "query" | "json-body"; parameter: string; template: string },
  value: string,
): boolean {
  return (
    challenge.location === "query" &&
    challengeRequestMatches({ path, actorId: "anonymous" }, challenge, value)
  );
}

function selectedAt(
  observations: readonly ValidationObservation[],
  requestIndex: number,
  pointer: string,
): { found: boolean; value?: unknown } {
  const observation = observations[requestIndex];
  return observation ? jsonPointer(observation.body, pointer) : { found: false };
}

function requestContains(request: ProofRequest, value: string): boolean {
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

function controlledStrings(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(controlledStrings);
  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([name, entry]) => [name, ...controlledStrings(entry)]);
  }
  return [];
}

function sameConcreteRequest(
  left: Finding["reproduction"][number] | undefined,
  right: Finding["reproduction"][number] | undefined,
): boolean {
  if (!left || !right) return false;
  return (
    canonicalJson({ ...left, path: canonicalRequestPath(left.path), sampleId: undefined }) ===
    canonicalJson({ ...right, path: canonicalRequestPath(right.path), sampleId: undefined })
  );
}

function canonicalRequestPath(path: string): string {
  const url = new URL(path, "http://proof.invalid");
  url.searchParams.sort();
  return `${url.pathname}${url.search}`;
}

function decodeRequestText(value: string): string {
  try {
    return decodeURIComponent(value.replaceAll("+", " "));
  } catch {
    return value;
  }
}

type ProofRequest = {
  path: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  actorId: ActorId;
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
    left.actorId === right.actorId &&
    canonicalJson(normalizeHeaders(left.headers)) === canonicalJson(normalizeHeaders(right.headers))
  );
}

function requestMutationValue(
  request: Pick<ProofRequest, "path" | "body"> | undefined,
  mutation: Pick<RequestMutation, "location" | "parameter">,
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
