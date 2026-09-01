import type { ScopedTarget } from "./scoped-target.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import type { Finding, ProofArtifacts, ValidationObservation } from "./state.ts";
import { requiredImpactLevel } from "./impact.ts";
import { endpointMatchesRequest } from "./endpoint.ts";
import { browserPolicyPath, type ProofPolicy } from "./target-profile.ts";

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
    (finding.proof.type === "browser-visible-effect" ? finding.proof.collectorRequestBudget : 0)
  );
}

export async function replayFinding(
  target: ScopedTarget,
  finding: Finding,
  artifactStore?: ProofArtifactStore,
  policies: readonly ProofPolicy[] = [],
): Promise<ReplayResult> {
  const replayedFinding = prepareFreshChallenge(finding, artifactStore, policies);
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
    observations.push({
      method: observation.method ?? request.method ?? "GET",
      status: observation.status,
      path: observation.path,
      actorId: request.actorId,
      body: observation.body,
      truncated: observation.truncated ?? false,
      durationMs: observation.durationMs,
      sampleId: request.sampleId,
    });
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
        : { browserEffects: [], oastCallbacks: [] },
  };
}

function prepareFreshChallenge(
  finding: Finding,
  store: ProofArtifactStore | undefined,
  policies: readonly ProofPolicy[],
): Finding {
  if (!store || !["browser-visible-effect", "oast-callback"].includes(finding.proof.type)) {
    return finding;
  }
  if (finding.proof.type === "browser-visible-effect") {
    const proof = finding.proof;
    const policy = policies.find(
      (candidate) => candidate.kind === "browser-effect" && candidate.id === proof.policyId,
    );
    if (policy?.kind !== "browser-effect") throw new Error("Unknown browser-effect proof policy");
    assertAffectedRequestIndex(finding, proof.requestIndex);
    const probe = store.issueBrowserProbe();
    return replaceChallenge(finding, proof.requestIndex, policy.challenge, probe.marker, {
      ...proof,
      probeId: probe.probeId,
      marker: probe.marker,
      challenge: policy.challenge,
      pagePath: browserPolicyPath(policy, probe.marker),
      pageActorId: policy.pageActorId,
      pageChallenge: policy.pageChallenge,
      collectorRequestBudget: policy.requestBudget,
    });
  }
  if (finding.proof.type !== "oast-callback") return finding;
  const proof = finding.proof;
  const policy = policies.find(
    (candidate) => candidate.kind === "oast" && candidate.id === proof.policyId,
  );
  if (policy?.kind !== "oast") throw new Error("Unknown OAST proof policy");
  assertAffectedRequestIndex(finding, proof.requestIndex);
  const probe = store.issueOastProbe();
  return replaceChallenge(finding, proof.requestIndex, policy.challenge, probe.url, {
    ...proof,
    probeId: probe.probeId,
    token: probe.token,
    callbackUrl: probe.url,
    challenge: policy.challenge,
  });
}

function assertAffectedRequestIndex(finding: Finding, requestIndex: number): void {
  const request = finding.reproduction[requestIndex];
  if (
    !request ||
    (request.method ?? "GET") !== (finding.method ?? "GET") ||
    !endpointMatchesRequest(finding.endpoint, request.path)
  ) {
    throw new Error("Proof challenge request is not the affected finding operation");
  }
}

function replaceChallenge(
  finding: Finding,
  requestIndex: number,
  challenge: { location: "query" | "json-body"; parameter: string; template: string },
  value: string,
  proof: Finding["proof"],
): Finding {
  const request = finding.reproduction[requestIndex];
  if (!request || challenge.template.split("{{challenge}}").length !== 2) return finding;
  const replacement = challenge.template.replace("{{challenge}}", value);
  const nextRequest = { ...request };
  if (challenge.location === "query") {
    const url = new URL(request.path, "http://proof.invalid");
    if (url.searchParams.getAll(challenge.parameter).length !== 1) return finding;
    url.searchParams.set(challenge.parameter, replacement);
    nextRequest.path = `${url.pathname}${url.search}${url.hash}`;
  } else {
    try {
      const body: unknown = JSON.parse(request.body ?? "");
      if (!body || Array.isArray(body) || typeof body !== "object") return finding;
      nextRequest.body = JSON.stringify({
        ...(body as Record<string, unknown>),
        [challenge.parameter]: replacement,
      });
    } catch {
      return finding;
    }
  }
  return {
    ...finding,
    proof,
    reproduction: finding.reproduction.map((candidate, index) =>
      index === requestIndex ? nextRequest : candidate,
    ),
  };
}
