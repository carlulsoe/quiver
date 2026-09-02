import { hasPotentialAuthenticationHeaders } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import type { ProofCheckHandler } from "./proof-types.ts";
import * as support from "./proof-support.ts";

export const crossPrincipalAccessHandler: ProofCheckHandler<"cross-principal-access"> = (
  finding,
  observations,
  checks,
) => {
  const actor = support.selectedValue(observations, finding.proof.actor);
  const owner = support.selectedValue(observations, finding.proof.resourceOwner);
  const access = observations[finding.proof.accessRequestIndex];
  checks.push(
    support.check(
      finding.reproduction[finding.proof.actor.requestIndex]?.actorId !== actorIds.anonymous,
      "actor identity was established in a named actor session",
    ),
    support.check(
      actor.found && support.isScalar(actor.value),
      "actor identity exists",
      actor.value,
    ),
    support.check(
      owner.found && support.isScalar(owner.value),
      "resource-owner identity exists",
      owner.value,
    ),
    support.check(
      actor.found && owner.found && !support.sameValue(actor.value, owner.value),
      "actor and resource owner are different principals",
      actor.found && owner.found ? `${String(actor.value)} != ${String(owner.value)}` : undefined,
    ),
    support.check(
      access !== undefined && support.isSuccess(access.status),
      "cross-principal request returned a successful response",
      access?.status,
    ),
    support.check(
      finding.reproduction[finding.proof.accessRequestIndex]?.actorId ===
        finding.reproduction[finding.proof.actor.requestIndex]?.actorId &&
        finding.reproduction[finding.proof.accessRequestIndex]?.actorId !== actorIds.anonymous,
      "cross-principal access used the identified actor session",
    ),
    ...support.pointerChecks(access, finding.proof.evidencePointers),
  );
};
export const authenticationBypassHandler: ProofCheckHandler<"authentication-bypass"> = (
  finding,
  observations,
  checks,
  context,
) => {
  const proof = finding.proof;
  const authenticatedRequest = finding.reproduction[proof.authenticatedRequestIndex];
  const anonymousRequest = finding.reproduction[proof.anonymousRequestIndex];
  const authenticatedObservation = observations[proof.authenticatedRequestIndex];
  const anonymousObservation = observations[proof.anonymousRequestIndex];
  const operation = support.protectedOperationFor(
    context.protectedOperations,
    authenticatedRequest,
  );
  const anonymousOperation = support.protectedOperationFor(
    context.protectedOperations,
    anonymousRequest,
  );
  const authenticatedIdentity = support.identityFor(
    context.identities,
    authenticatedRequest?.actorId,
  );
  const anonymousIdentity = support.identityFor(context.identities, anonymousRequest?.actorId);
  checks.push(
    support.check(
      finding.reproduction.length === 2 &&
        proof.authenticatedRequestIndex !== proof.anonymousRequestIndex,
      "authentication bypass is one closed authenticated-anonymous request pair",
    ),
    support.check(
      authenticatedRequest !== undefined &&
        authenticatedRequest.actorId !== actorIds.anonymous &&
        anonymousRequest?.actorId === actorIds.anonymous,
      "control is authenticated and bypass probe is anonymous",
    ),
    support.check(
      authenticatedIdentity !== undefined &&
        authenticatedIdentity.role !== "anonymous" &&
        anonymousIdentity?.role === "anonymous",
      "authenticated and anonymous actors are declared by the target manifest",
    ),
    support.check(
      operation !== undefined &&
        operation === anonymousOperation &&
        authenticatedRequest !== undefined &&
        operation.authorizedActors.includes(authenticatedRequest.actorId) &&
        !operation.authorizedActors.includes(actorIds.anonymous),
      "target policy requires authentication for the affected operation",
    ),
    support.check(
      support.affectedOperationMatches(finding, authenticatedRequest) &&
        support.affectedOperationMatches(finding, anonymousRequest),
      "authenticated control and anonymous probe match the affected operation",
    ),
    support.check(
      support.sameRequestAcrossActors(authenticatedRequest, anonymousRequest),
      "authenticated control and anonymous probe differ only by actor session",
    ),
    support.check(
      !hasPotentialAuthenticationHeaders(authenticatedRequest?.headers) &&
        !hasPotentialAuthenticationHeaders(anonymousRequest?.headers),
      "authentication differential relies only on declared actor sessions",
    ),
    support.check(
      authenticatedObservation !== undefined && support.isSuccess(authenticatedObservation.status),
      "authenticated control returned a successful response",
      authenticatedObservation?.status,
    ),
    support.check(
      anonymousObservation !== undefined && support.isSuccess(anonymousObservation.status),
      "anonymous bypass probe returned a successful response",
      anonymousObservation?.status,
    ),
    ...support.differentialPointerChecks(
      authenticatedObservation,
      anonymousObservation,
      proof.evidencePointers,
      "authenticated control",
      "anonymous bypass probe",
    ),
  );
};
