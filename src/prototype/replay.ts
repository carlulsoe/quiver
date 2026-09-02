import type { ScopedTarget } from "./scoped-target.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import type { Finding, ProofArtifacts, ValidationObservation } from "./state.ts";
import { requiredImpactLevel } from "./impact.ts";
import type { ProofPolicy } from "./target-profile.ts";
import { prepareFreshChallenge } from "./replay-challenge.ts";

export interface ReplayResult {
  fingerprint: string;
  replayedFinding: Finding;
  observations: ValidationObservation[];
  artifacts: ProofArtifacts;
}

export class ReplayBudgetExceededError extends Error {
  override readonly name = "ReplayBudgetExceededError";
}

export function replayRequestBudget(finding: Pick<Finding, "proof" | "reproduction">): number {
  return (
    finding.reproduction.length +
    (finding.proof.type === "browser-visible-effect" ||
    finding.proof.type === "browser-state-transition"
      ? finding.proof.collectorRequestBudget
      : 0)
  );
}

export async function replayFinding(
  target: ScopedTarget,
  finding: Finding,
  artifactStore?: ProofArtifactStore,
  policies: readonly ProofPolicy[] = [],
): Promise<ReplayResult> {
  const replayedFinding = prepareFreshChallenge(finding, artifactStore, policies);
  const browserStateProof =
    replayedFinding.proof.type === "browser-state-transition" ? replayedFinding.proof : undefined;
  const browserStatePolicy = browserStateProof
    ? policies.find(
        (candidate) =>
          candidate.kind === "browser-state-transition" &&
          candidate.id === browserStateProof.policyId,
      )
    : undefined;
  if (
    browserStateProof &&
    (browserStatePolicy?.kind !== "browser-state-transition" ||
      replayedFinding.reproduction.length !== 2 ||
      browserStateProof.beforeRequestIndex !== 0 ||
      browserStateProof.afterRequestIndex !== 1 ||
      browserStateProof.pageActorId !== browserStatePolicy.pageActorId ||
      browserStateProof.collectorRequestBudget !== browserStatePolicy.requestBudget)
  ) {
    throw new Error("Invalid browser-state-transition replay contract");
  }
  target.assertImpactLevel(requiredImpactLevel(replayedFinding));
  const requiredRequests = replayRequestBudget(replayedFinding);
  if (target.remainingRequests < requiredRequests) {
    throw new ReplayBudgetExceededError(
      `Validation requires ${requiredRequests} requests but only ${target.remainingRequests} remain`,
    );
  }
  const checkpoint = artifactStore?.checkpoint();
  const observations: ValidationObservation[] = [];
  for (const request of replayedFinding.reproduction) {
    const observation = await target.request({
      path: request.path,
      method: request.method,
      headers: request.headers,
      body: request.body,
      actorId: request.actorId,
    });
    const replayObservation: ValidationObservation = {
      method: observation.method ?? request.method ?? "GET",
      status: observation.status,
      path: observation.path,
      actorId: request.actorId,
      body: observation.body,
      truncated: observation.truncated ?? false,
      durationMs: observation.durationMs,
    };
    if (observation.contentType !== undefined)
      replayObservation.contentType = observation.contentType;
    if (observation.redirectLocation !== undefined)
      replayObservation.redirectLocation = observation.redirectLocation;
    if (observation.redirected !== undefined) replayObservation.redirected = observation.redirected;
    if (request.sampleId !== undefined) replayObservation.sampleId = request.sampleId;
    observations.push(replayObservation);
    if (replayedFinding.proof.type === "browser-state-transition" && observations.length === 1) {
      if (browserStatePolicy?.kind !== "browser-state-transition") {
        throw new Error("Invalid browser-state-transition replay contract");
      }
      const evidence = await target.observeBrowserStateTransition({
        policyId: browserStatePolicy.id,
        sourceOrigin: browserStatePolicy.sourceOrigin,
        sourcePath: browserStatePolicy.sourcePath,
        targetPath: browserStatePolicy.endpoint,
        method: browserStatePolicy.method,
        actorId: browserStatePolicy.pageActorId,
        requestBudget: browserStatePolicy.requestBudget,
      });
      if (evidence) artifactStore?.recordBrowserStateTransition(evidence);
    }
  }
  if (replayedFinding.proof.type === "browser-visible-effect" && artifactStore) {
    const evidence = await target.observeBrowserEffect({
      probeId: replayedFinding.proof.probeId,
      marker: replayedFinding.proof.marker,
      path: replayedFinding.proof.pagePath,
      kind: replayedFinding.proof.kind,
      actorId: replayedFinding.proof.pageActorId,
      requestBudget: replayedFinding.proof.collectorRequestBudget,
    });
    if (evidence) artifactStore.recordBrowserEffect(evidence);
  }
  if (replayedFinding.proof.type === "oast-callback" && artifactStore && checkpoint) {
    await artifactStore.waitForOastCallback(
      replayedFinding.proof.probeId,
      replayedFinding.proof.token,
      2_000,
    );
  }
  return {
    fingerprint: finding.fingerprint,
    replayedFinding,
    observations,
    artifacts:
      artifactStore && checkpoint
        ? artifactStore.artifactsSince(checkpoint)
        : { browserEffects: [], browserStateTransitions: [], oastCallbacks: [] },
  };
}
