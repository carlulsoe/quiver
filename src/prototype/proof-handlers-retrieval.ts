import { endpointMatchesRequest } from "./endpoint.ts";
import type { ProofCheckHandler } from "./proof-types.ts";
import * as support from "./proof-support.ts";

export const canaryRetrievalHandler: ProofCheckHandler<"canary-retrieval"> = (
  finding,
  observations,
  checks,
  context,
) => {
  const policy = support.policyFor(context.policies, finding.proof.policyId, "canary");
  const observation = observations[finding.proof.requestIndex];
  const selected = observation
    ? support.jsonPointer(observation.body, finding.proof.jsonPointer)
    : { found: false };
  const canaryValue = support.stringValue(selected.value);
  const request = finding.reproduction[finding.proof.requestIndex];
  checks.push(
    support.check(
      policy?.category === finding.category,
      "target policy authorizes this canary proof",
    ),
    support.check(
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
    support.check(
      policy !== undefined &&
        request !== undefined &&
        (request.method ?? "GET") === policy.method &&
        endpointMatchesRequest(policy.endpoint, request.path) &&
        support.affectedOperationMatches(finding, request),
      "canary retrieval request matches the policy and affected operation",
    ),
    support.check(selected.found && canaryValue !== undefined, "canary value was retrieved"),
    support.check(
      policy !== undefined &&
        request !== undefined &&
        canaryValue !== undefined &&
        !finding.reproduction.some((candidate) =>
          support.requestContains(candidate, canaryValue),
        ) &&
        support.verifyCanary(policy, canaryValue),
      "retrieved value passes the verifier-only canary contract and was not reflected",
      support.selectedEvidence(finding.proof.jsonPointer, selected.value, observations),
    ),
  );
};
export const fileContentRetrievalHandler: ProofCheckHandler<"file-content-retrieval"> = (
  finding,
  observations,
  checks,
  context,
) => {
  const proof = finding.proof;
  const policy = support.policyFor(context.policies, proof.policyId, "file-content");
  const request = finding.reproduction[proof.requestIndex];
  const observation = observations[proof.requestIndex];
  const body = support.stringValue(observation?.body);
  const contentTypePattern = policy ? support.safeRegex(policy.contentTypePattern, "i") : undefined;
  checks.push(
    support.check(
      policy?.category === finding.category,
      "target policy authorizes this file proof",
    ),
    support.check(
      policy !== undefined &&
        finding.reproduction.length === 1 &&
        proof.requestIndex === 0 &&
        request !== undefined &&
        (request.method ?? "GET") === policy.method &&
        endpointMatchesRequest(policy.endpoint, request.path) &&
        support.affectedOperationMatches(finding, request),
      "file request is one policy-bound affected operation",
    ),
    support.check(
      policy !== undefined &&
        support.requestMutationValue(request, policy.request) === policy.request.value,
      "request contains the exact target-owned traversal value",
    ),
    support.check(
      observation !== undefined && support.isSuccess(observation.status) && body !== undefined,
      "file response is successful raw text rather than a parsed JSON canary",
      observation?.status,
    ),
    support.check(
      contentTypePattern !== undefined && contentTypePattern.test(observation?.contentType ?? ""),
      "file response media type matches the target policy",
      observation?.contentType,
    ),
    support.check(
      policy !== undefined &&
        policy.source === "immutable-fixture" &&
        request !== undefined &&
        body !== undefined &&
        !support.requestContains(request, body) &&
        support.verifyFileContent(policy, body),
      "raw body passes the verifier-only immutable-file contract and was not reflected",
    ),
  );
};
export const redirectDestinationHandler: ProofCheckHandler<"redirect-destination"> = (
  finding,
  observations,
  checks,
  context,
) => {
  const proof = finding.proof;
  const policy = support.policyFor(context.policies, proof.policyId, "redirect");
  const request = finding.reproduction[proof.requestIndex];
  const observation = observations[proof.requestIndex];
  checks.push(
    support.check(
      policy?.category === finding.category,
      "target policy authorizes this redirect proof",
    ),
    support.check(
      policy !== undefined && proof.destination === policy.destination,
      "redirect destination is the exact target-owned absolute URL",
      proof.destination,
    ),
    support.check(
      policy !== undefined &&
        finding.reproduction.length === 1 &&
        proof.requestIndex === 0 &&
        request !== undefined &&
        (request.method ?? "GET") === policy.method &&
        endpointMatchesRequest(policy.endpoint, request.path) &&
        support.affectedOperationMatches(finding, request),
      "redirect request is one policy-bound affected operation",
    ),
    support.check(
      policy !== undefined &&
        support.challengeRequestMatches(request, policy.challenge, policy.destination),
      "request binds the exact redirect destination to the policy parameter",
    ),
    support.check(
      observation !== undefined && observation.status >= 300 && observation.status < 400,
      "response is an HTTP redirect",
      observation?.status,
    ),
    support.check(
      observation?.redirected === false,
      "automatic redirect following was disabled",
      observation?.redirected,
    ),
    support.check(
      observation?.redirectLocation === proof.destination,
      "Location exactly equals the declared redirect destination",
      observation?.redirectLocation,
    ),
  );
};
