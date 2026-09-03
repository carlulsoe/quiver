import { hasPotentialAuthenticationHeaders } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import type { ProofCheckHandler } from "./proof-types.ts";
import * as support from "./proof-support.ts";

export const unauthenticatedSuccessHandler: ProofCheckHandler<"unauthenticated-success"> = (
  finding,
  observations,
  checks,
) => {
  const observation = observations[finding.proof.requestIndex];
  const request = finding.reproduction[finding.proof.requestIndex];
  checks.push(
    support.check(
      support.affectedOperationMatches(finding, request),
      "unauthenticated request matches the affected operation",
    ),
    support.check(
      request !== undefined &&
        request.actorId === actorIds.anonymous &&
        ["GET", "HEAD"].includes(request.method ?? "GET") &&
        request.body === undefined &&
        !hasPotentialAuthenticationHeaders(request.headers),
      "bodyless GET/HEAD request was sent without authentication",
    ),
    support.check(
      observation !== undefined && support.isSuccess(observation.status),
      "unauthenticated request returned a successful response",
      observation?.status,
    ),
    ...support.pointerChecks(observation, finding.proof.evidencePointers),
  );
};
export const crossPrincipalDataExposureHandler: ProofCheckHandler<
  "cross-principal-data-exposure"
> = (finding, observations, checks) => {
  const actor = support.selectedValue(observations, finding.proof.actor);
  const subject = support.selectedValue(observations, finding.proof.exposedSubject);
  const observation = observations[finding.proof.responseRequestIndex];
  const responseRequest = finding.reproduction[finding.proof.responseRequestIndex];
  checks.push(
    support.check(
      finding.reproduction[finding.proof.actor.requestIndex]?.actorId !== actorIds.anonymous,
      "actor identity was established in a named actor session",
    ),
    support.check(
      actor.found && support.isScalar(actor.value),
      "actor identity exists",
      support.selectedEvidence(finding.proof.actor.jsonPointer, actor.value),
    ),
    support.check(
      subject.found && support.isScalar(subject.value),
      "exposed-subject identity exists",
      support.selectedEvidence(finding.proof.exposedSubject.jsonPointer, subject.value),
    ),
    support.check(
      actor.found && subject.found && !support.sameValue(actor.value, subject.value),
      "actor and exposed subject are different principals",
      actor.found && subject.found
        ? `${String(support.selectedEvidence(finding.proof.actor.jsonPointer, actor.value))} != ${String(support.selectedEvidence(finding.proof.exposedSubject.jsonPointer, subject.value))}`
        : undefined,
    ),
    support.check(
      observation !== undefined && support.isSuccess(observation.status),
      "cross-principal data response returned successfully",
      observation?.status,
    ),
    support.check(
      support.affectedOperationMatches(finding, responseRequest),
      "cross-principal data response matches the affected operation",
    ),
    support.check(
      finding.reproduction[finding.proof.responseRequestIndex]?.actorId ===
        finding.reproduction[finding.proof.actor.requestIndex]?.actorId &&
        finding.reproduction[finding.proof.responseRequestIndex]?.actorId !== actorIds.anonymous,
      "cross-principal data was observed in the identified actor session",
    ),
    ...support.pointerChecks(observation, finding.proof.evidencePointers),
  );
};
export const internalFieldExposureHandler: ProofCheckHandler<"internal-field-exposure"> = (
  finding,
  observations,
  checks,
) => {
  const observation = observations[finding.proof.requestIndex];
  const request = finding.reproduction[finding.proof.requestIndex];
  checks.push(
    support.check(
      support.affectedOperationMatches(finding, request),
      "internal-field evidence response matches the affected operation",
    ),
    support.check(
      observation !== undefined && support.isSuccess(observation.status),
      "evidence response returned a successful response",
      observation?.status,
    ),
    support.check(
      finding.proof.evidencePointers.length > 0,
      "at least one exposed field was declared",
    ),
    ...support.pointerChecks(observation, finding.proof.evidencePointers),
  );
};
export const responseDifferentialHandler: ProofCheckHandler<"response-differential"> = () =>
  undefined;
export const timingDifferentialHandler: ProofCheckHandler<"timing-differential"> = (
  finding,
  observations,
  checks,
) => {
  const controlDurations = support.selectedDurations(
    observations,
    finding.proof.controlRequestIndexes,
  );
  const probeDurations = support.selectedDurations(observations, finding.proof.probeRequestIndexes);
  const controlMedian = support.median(controlDurations);
  const probeMedian = support.median(probeDurations);
  const delta =
    controlMedian === undefined || probeMedian === undefined
      ? undefined
      : probeMedian - controlMedian;
  checks.push(
    support.check(
      support.distinctSampleCount(finding.reproduction, finding.proof.controlRequestIndexes) >= 3,
      "control timing requests use three distinct sample identifiers",
    ),
    support.check(
      support.distinctSampleCount(finding.reproduction, finding.proof.probeRequestIndexes) >= 3,
      "probe timing requests use three distinct sample identifiers",
    ),
    support.check(
      support.distinctSampleCount(finding.reproduction, [
        ...finding.proof.controlRequestIndexes,
        ...finding.proof.probeRequestIndexes,
      ]) >= 6,
      "control and probe sample identifiers are disjoint",
    ),
    support.check(
      new Set(finding.proof.controlRequestIndexes).size >= 3,
      "at least three distinct control samples were replayed",
      controlDurations,
    ),
    support.check(
      new Set(finding.proof.probeRequestIndexes).size >= 3,
      "at least three distinct probe samples were replayed",
      probeDurations,
    ),
    support.check(
      controlDurations.length === finding.proof.controlRequestIndexes.length,
      "every control sample has timing evidence",
      controlDurations,
    ),
    support.check(
      probeDurations.length === finding.proof.probeRequestIndexes.length,
      "every probe sample has timing evidence",
      probeDurations,
    ),
    support.check(
      delta !== undefined && delta >= finding.proof.minimumDeltaMs,
      `probe support.median is at least ${finding.proof.minimumDeltaMs}ms slower than control support.median`,
      delta,
    ),
    ...support.timingDifferentialSecurityChecks(finding, observations),
  );
};
