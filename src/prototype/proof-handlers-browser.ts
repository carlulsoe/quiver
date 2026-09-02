import { endpointMatchesRequest } from "./endpoint.ts";
import { browserPolicyPath } from "./target-profile.ts";
import type { ProofCheckHandler } from "./proof-types.ts";
import * as support from "./proof-support.ts";

export const browserVisibleEffectHandler: ProofCheckHandler<"browser-visible-effect"> = (
  finding,
  observations,
  checks,
  context,
) => {
  const proof = finding.proof;
  const policy = support.policyFor(context.policies, proof.policyId, "browser-effect");
  const pattern = policy ? support.safeRegex(policy.markerPattern) : undefined;
  const artifact = context.artifacts?.browserEffects.find(
    ({ probeId }) => probeId === proof.probeId,
  );
  const request = finding.reproduction[proof.requestIndex];
  const observation = observations[proof.requestIndex];
  checks.push(
    support.check(
      policy?.category === finding.category,
      "target policy authorizes this browser proof",
    ),
    support.check(
      policy !== undefined &&
        finding.reproduction.length === 1 &&
        proof.requestIndex === 0 &&
        request !== undefined &&
        (request.method ?? "GET") === policy.method &&
        endpointMatchesRequest(policy.endpoint, request.path) &&
        support.affectedOperationMatches(finding, request),
      "browser payload is one policy-bound affected operation",
    ),
    support.check(
      policy !== undefined &&
        support.canonicalJson(proof.challenge) === support.canonicalJson(policy.challenge),
      "browser challenge uses the target-owned mutation and executable payload template",
    ),
    support.check(
      policy !== undefined &&
        proof.pageActorId === policy.pageActorId &&
        request?.actorId === policy.submissionActorId,
      "browser submission and page actors match the target policy",
    ),
    support.check(
      policy !== undefined && proof.collectorRequestBudget === policy.requestBudget,
      "browser collector request budget matches the target policy",
    ),
    support.check(
      support.canonicalJson(proof.pageChallenge) === support.canonicalJson(policy?.pageChallenge),
      "browser navigation challenge matches the target policy",
    ),
    support.check(
      policy !== undefined &&
        ((policy.workflow === "stored" &&
          ["POST", "PUT", "PATCH"].includes(policy.method) &&
          proof.pageChallenge === undefined) ||
          (policy.workflow === "dom" &&
            finding.method === "GET" &&
            proof.pageChallenge?.location === "fragment" &&
            proof.pagePath === request?.path &&
            support.challengePathMatches(proof.pagePath, proof.pageChallenge, proof.marker) &&
            !support.responseContains(observation?.body, proof.marker))),
      "browser proof follows the policy's closed stored-write or fragment-only DOM workflow",
    ),
    support.check(
      support.challengeRequestMatches(
        finding.reproduction[proof.requestIndex],
        proof.challenge,
        proof.marker,
      ),
      "issued browser marker is bound to the declared request mutation",
    ),
    support.check(
      observation !== undefined && support.isSuccess(observation.status),
      "browser payload operation completed successfully",
      observation?.status,
    ),
    support.check(
      artifact !== undefined &&
        policy !== undefined &&
        policy.effect === "dialog" &&
        proof.kind === policy.effect &&
        artifact.kind === policy.effect &&
        browserPolicyPath(policy, proof.marker) === proof.pagePath &&
        artifact.path === proof.pagePath,
      "fresh browser artifact matches the policy effect and page",
    ),
    support.check(
      artifact?.value === proof.marker && pattern !== undefined && pattern.test(proof.marker),
      "browser effect contains the policy-approved marker",
      artifact?.value,
    ),
  );
};
export const oastCallbackHandler: ProofCheckHandler<"oast-callback"> = (
  finding,
  observations,
  checks,
  context,
) => {
  const proof = finding.proof;
  const policy = support.policyFor(context.policies, proof.policyId, "oast");
  const artifact = context.artifacts?.oastCallbacks.find(
    ({ probeId, token }) => probeId === proof.probeId && token === proof.token,
  );
  const request = finding.reproduction[proof.requestIndex];
  checks.push(
    support.check(
      policy?.category === finding.category,
      "target policy authorizes this OAST proof",
    ),
    support.check(
      policy !== undefined &&
        support.canonicalJson(proof.challenge) === support.canonicalJson(policy.challenge),
      "OAST challenge uses the target-owned request mutation",
    ),
    support.check(
      policy !== undefined &&
        request !== undefined &&
        (request.method ?? "GET") === policy.method &&
        endpointMatchesRequest(policy.endpoint, request.path) &&
        support.affectedOperationMatches(finding, request),
      "OAST probe request matches the policy and affected operation",
    ),
    support.check(
      request !== undefined &&
        proof.callbackUrl.includes(proof.token) &&
        support.challengeRequestMatches(request, proof.challenge, proof.callbackUrl),
      "issued OAST callback URL is bound to the declared request mutation",
    ),
    support.check(
      artifact !== undefined && artifact.protocol === policy?.protocol,
      "fresh target callback reached the issued OAST probe",
      artifact?.path,
    ),
  );
};
