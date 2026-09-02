import { hasPotentialAuthenticationHeaders } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import type { ProofCheckHandler } from "./proof-types.ts";
import * as support from "./proof-support.ts";

export const rolePrivilegeDifferentialHandler: ProofCheckHandler<"role-privilege-differential"> = (
  finding,
  observations,
  checks,
  context,
) => {
  const proof = finding.proof;
  const authorizedRequest = finding.reproduction[proof.authorizedRequestIndex];
  const lessPrivilegedRequest = finding.reproduction[proof.lessPrivilegedRequestIndex];
  const authorizedObservation = observations[proof.authorizedRequestIndex];
  const lessPrivilegedObservation = observations[proof.lessPrivilegedRequestIndex];
  const authorizedIdentity = support.identityFor(context.identities, authorizedRequest?.actorId);
  const lessPrivilegedIdentity = support.identityFor(
    context.identities,
    lessPrivilegedRequest?.actorId,
  );
  const operation = support.protectedOperationFor(context.protectedOperations, authorizedRequest);
  const lessPrivilegedOperation = support.protectedOperationFor(
    context.protectedOperations,
    lessPrivilegedRequest,
  );
  const method = authorizedRequest?.method ?? "GET";
  checks.push(
    support.check(
      finding.reproduction.length === 2 &&
        proof.authorizedRequestIndex !== proof.lessPrivilegedRequestIndex,
      "role differential is one closed authorized-less-privileged request pair",
    ),
    support.check(
      authorizedRequest !== undefined &&
        lessPrivilegedRequest !== undefined &&
        authorizedRequest.actorId !== actorIds.anonymous &&
        lessPrivilegedRequest.actorId !== actorIds.anonymous &&
        authorizedRequest.actorId !== lessPrivilegedRequest.actorId,
      "role differential uses two distinct authenticated actors",
    ),
    support.check(
      authorizedIdentity !== undefined &&
        lessPrivilegedIdentity !== undefined &&
        support.roleRank(authorizedIdentity.role) > support.roleRank(lessPrivilegedIdentity.role),
      "control actor has a more privileged declared role than the probe actor",
      authorizedIdentity && lessPrivilegedIdentity
        ? `${authorizedIdentity.role} > ${lessPrivilegedIdentity.role}`
        : undefined,
    ),
    support.check(
      operation !== undefined &&
        operation === lessPrivilegedOperation &&
        authorizedRequest !== undefined &&
        lessPrivilegedRequest !== undefined &&
        operation.authorizedActors.includes(authorizedRequest.actorId) &&
        !operation.authorizedActors.includes(lessPrivilegedRequest.actorId),
      "target policy authorizes the control actor but not the less-privileged actor",
    ),
    support.check(
      support.affectedOperationMatches(finding, authorizedRequest) &&
        support.affectedOperationMatches(finding, lessPrivilegedRequest),
      "authorized control and less-privileged probe match the affected operation",
    ),
    support.check(
      support.sameRequestAcrossActors(authorizedRequest, lessPrivilegedRequest),
      "authorized control and less-privileged probe differ only by actor session",
    ),
    support.check(
      !hasPotentialAuthenticationHeaders(authorizedRequest?.headers) &&
        !hasPotentialAuthenticationHeaders(lessPrivilegedRequest?.headers),
      "role differential relies only on declared actor sessions",
    ),
    support.check(
      finding.category !== "business-logic" || ["POST", "PUT", "PATCH"].includes(method),
      "cross-role business action uses a state-changing method",
      method,
    ),
    support.check(
      authorizedObservation !== undefined && support.isSuccess(authorizedObservation.status),
      "authorized control returned a successful response",
      authorizedObservation?.status,
    ),
    support.check(
      lessPrivilegedObservation !== undefined &&
        support.isSuccess(lessPrivilegedObservation.status),
      "less-privileged probe returned a successful response",
      lessPrivilegedObservation?.status,
    ),
    ...support.differentialPointerChecks(
      authorizedObservation,
      lessPrivilegedObservation,
      proof.evidencePointers,
      "authorized control",
      "less-privileged probe",
    ),
  );
};
