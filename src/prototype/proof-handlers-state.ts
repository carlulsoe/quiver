import { endpointMatchesRequest } from "./endpoint.ts";
import { actorIds } from "./sessions.ts";
import type { ProofCheckHandler } from "./proof-types.ts";
import * as support from "./proof-support.ts";

export const stateTransitionHandler: ProofCheckHandler<"state-transition"> = (
  finding,
  observations,
  checks,
  context,
) => {
  const policy = support.policyFor(context.policies, finding.proof.policyId, "state-transition");
  const before = policy
    ? support.selectedAt(observations, finding.proof.beforeRequestIndex, policy.jsonPointer)
    : { found: false };
  const after = policy
    ? support.selectedAt(observations, finding.proof.afterRequestIndex, policy.jsonPointer)
    : { found: false };
  const beforeObservation = observations[finding.proof.beforeRequestIndex];
  const transitionObservation = observations[finding.proof.transitionRequestIndex];
  const afterObservation = observations[finding.proof.afterRequestIndex];
  const transition = finding.reproduction[finding.proof.transitionRequestIndex];
  checks.push(
    support.check(
      policy?.category === finding.category,
      "target policy authorizes this state proof",
    ),
    support.check(
      policy !== undefined &&
        ["POST", "PUT", "PATCH"].includes(policy.method) &&
        ["GET", "HEAD"].includes(policy.readMethod),
      "state policy separates an explicit mutating operation from read-only state checks",
    ),
    support.check(
      context.stateResetAvailable === true,
      "target provides a fresh-state preparation hook for validation",
    ),
    support.check(
      finding.reproduction.length === 3 &&
        finding.proof.beforeRequestIndex === 0 &&
        finding.proof.transitionRequestIndex === 1 &&
        finding.proof.afterRequestIndex === 2,
      "state proof is a closed adjacent read-transition-read reproduction",
    ),
    support.check(
      policy !== undefined &&
        transition !== undefined &&
        (transition.method ?? "GET") === policy.method &&
        endpointMatchesRequest(policy.endpoint, transition.path) &&
        support.affectedOperationMatches(finding, transition),
      "declared transition request matches the protected operation",
    ),
    support.check(
      policy !== undefined &&
        [finding.proof.beforeRequestIndex, finding.proof.afterRequestIndex].every((index) => {
          const request = finding.reproduction[index];
          return (
            request !== undefined &&
            (request.method ?? "GET") === policy.readMethod &&
            endpointMatchesRequest(policy.readEndpoint, request.path)
          );
        }) &&
        support.sameConcreteRequest(
          finding.reproduction[finding.proof.beforeRequestIndex],
          finding.reproduction[finding.proof.afterRequestIndex],
        ),
      "before and after requests read the same policy-bound resource",
    ),
    support.check(
      beforeObservation !== undefined &&
        transitionObservation !== undefined &&
        afterObservation !== undefined &&
        support.isSuccess(beforeObservation.status) &&
        support.isSuccess(transitionObservation.status) &&
        support.isSuccess(afterObservation.status),
      "before, transition, and after operations all completed successfully",
    ),
    support.check(
      before.found && support.sameValue(before.value, policy?.before),
      "protected state starts at policy value",
      support.selectedEvidence(policy?.jsonPointer ?? "", before.value, observations),
    ),
    support.check(
      after.found && support.sameValue(after.value, policy?.after),
      "protected state reaches policy value",
      support.selectedEvidence(policy?.jsonPointer ?? "", after.value, observations),
    ),
  );
};
export const browserStateTransitionHandler: ProofCheckHandler<"browser-state-transition"> = (
  finding,
  observations,
  checks,
  context,
) => {
  const proof = finding.proof;
  const policy = support.policyFor(context.policies, proof.policyId, "browser-state-transition");
  const before = policy
    ? support.selectedAt(observations, proof.beforeRequestIndex, policy.jsonPointer)
    : { found: false };
  const after = policy
    ? support.selectedAt(observations, proof.afterRequestIndex, policy.jsonPointer)
    : { found: false };
  const beforeObservation = observations[proof.beforeRequestIndex];
  const afterObservation = observations[proof.afterRequestIndex];
  const artifact = context.artifacts?.browserStateTransitions.find(
    (candidate) =>
      candidate.policyId === policy?.id &&
      candidate.sourceOrigin === policy.sourceOrigin &&
      candidate.sourcePath === policy.sourcePath &&
      candidate.targetPath === policy.endpoint &&
      candidate.method === policy.method,
  );
  checks.push(
    support.check(
      policy?.category === finding.category,
      "target policy authorizes this CSRF proof",
    ),
    support.check(
      context.stateResetAvailable === true,
      "target provides a fresh-state preparation hook for CSRF validation",
    ),
    support.check(
      policy !== undefined &&
        finding.reproduction.length === 2 &&
        proof.beforeRequestIndex === 0 &&
        proof.afterRequestIndex === 1 &&
        proof.pageActorId === policy.pageActorId &&
        proof.pageActorId !== actorIds.anonymous &&
        proof.collectorRequestBudget === policy.requestBudget,
      "CSRF proof is one authenticated policy-page transition between two reads",
    ),
    support.check(
      policy !== undefined &&
        finding.method === policy.method &&
        endpointMatchesRequest(finding.endpoint, policy.endpoint) &&
        support.isExactOrigin(policy.sourceOrigin),
      "affected mutation and exact source origin match the target policy",
    ),
    support.check(
      policy !== undefined &&
        [proof.beforeRequestIndex, proof.afterRequestIndex].every((index) => {
          const request = finding.reproduction[index];
          return (
            request !== undefined &&
            request.actorId === policy.pageActorId &&
            (request.method ?? "GET") === policy.readMethod &&
            endpointMatchesRequest(policy.readEndpoint, request.path)
          );
        }) &&
        support.sameConcreteRequest(
          finding.reproduction[proof.beforeRequestIndex],
          finding.reproduction[proof.afterRequestIndex],
        ),
      "before and after requests read the same policy-bound state as the browser actor",
    ),
    support.check(
      beforeObservation !== undefined &&
        afterObservation !== undefined &&
        support.isSuccess(beforeObservation.status) &&
        support.isSuccess(afterObservation.status),
      "before and after state reads completed successfully",
    ),
    support.check(
      artifact !== undefined && support.isCompletedStateTransition(artifact.status),
      "fresh browser artifact records the exact cross-origin mutation",
      artifact?.status,
    ),
    support.check(
      before.found && support.sameValue(before.value, policy?.before),
      "protected state starts at the policy value",
      support.selectedEvidence(policy?.jsonPointer ?? "", before.value, observations),
    ),
    support.check(
      after.found && support.sameValue(after.value, policy?.after),
      "protected state reaches the policy value",
      support.selectedEvidence(policy?.jsonPointer ?? "", after.value, observations),
    ),
  );
};
