import type { Finding, ProofCheck, ValidationObservation } from "./state.ts";
import { affectedOperationMatches } from "./proof-operation.ts";
import { requestsShareMutationContract } from "./proof-request-comparison.ts";
import { requestMutationValue } from "./proof-request-mutation.ts";
import { check } from "./proof-json.ts";

export function timingDifferentialSecurityChecks(
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
        requestsShareMutationContract(controls[0], request, proof.mutation),
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

export function sqlDelayMs(value: string): number | undefined {
  const seconds = value.match(/\b(?:sleep|pg_sleep)\s*\(\s*(\d+(?:\.\d+)?)\s*\)/i)?.[1];
  const waitfor = value.match(/\bwaitfor\s+delay\s+['"]\d{1,2}:\d{2}:(\d{2})['"]/i)?.[1];
  const delay = Number(seconds ?? waitfor);
  return Number.isFinite(delay) && delay > 0 ? delay * 1_000 : undefined;
}

export function commandDelayMs(value: string): number | undefined {
  const seconds = value.match(/(?:;|&&|\|\||\||\r|\n)\s*sleep\s+(\d+(?:\.\d+)?)(?:\s|$)/i)?.[1];
  const delay = Number(seconds);
  return Number.isFinite(delay) && delay > 0 ? delay * 1_000 : undefined;
}

export function distinctSampleCount(
  requests: readonly { sampleId?: string }[],
  indexes: readonly number[],
): number {
  return new Set(indexes.flatMap((index) => requests[index]?.sampleId ?? [])).size;
}

export function selectedDurations(
  observations: readonly ValidationObservation[],
  indexes: readonly number[],
): number[] {
  return indexes.flatMap((index) => {
    const duration = observations[index]?.durationMs;
    return duration !== undefined && Number.isFinite(duration) && duration >= 0 ? [duration] : [];
  });
}

export function median(values: readonly number[]): number | undefined {
  if (values.length === 0) return undefined;
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1]! + sorted[middle]!) / 2 : sorted[middle];
}
