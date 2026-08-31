import type { ScopedTarget } from "./scoped-target.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import type { Finding, ProofArtifacts, ValidationObservation } from "./state.ts";

export interface ReplayResult {
  fingerprint: string;
  replayedFinding: Finding;
  observations: ValidationObservation[];
  artifacts: ProofArtifacts;
}

export async function replayFinding(
  target: ScopedTarget,
  finding: Finding,
  artifactStore?: ProofArtifactStore,
): Promise<ReplayResult> {
  const replayedFinding = prepareFreshChallenge(finding, artifactStore);
  const requiredRequests =
    replayedFinding.reproduction.length +
    (replayedFinding.proof.type === "browser-visible-effect"
      ? replayedFinding.proof.collectorRequestBudget
      : 0);
  if (target.remainingRequests < requiredRequests) {
    throw new Error(
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
      authenticated: request.authenticated,
    });
    observations.push({
      method: observation.method ?? request.method ?? "GET",
      status: observation.status,
      path: observation.path,
      authenticated: request.authenticated,
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
      authenticated: replayedFinding.proof.pageAuthenticated,
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

function prepareFreshChallenge(finding: Finding, store: ProofArtifactStore | undefined): Finding {
  if (!store || !["browser-visible-effect", "oast-callback"].includes(finding.proof.type)) {
    return finding;
  }
  if (finding.proof.type === "browser-visible-effect") {
    const proof = finding.proof;
    const probe = store.issueBrowserProbe();
    return replaceChallenge(finding, proof.requestIndex, proof.challenge, probe.marker, {
      ...proof,
      probeId: probe.probeId,
      marker: probe.marker,
      pagePath: proof.pageChallenge
        ? replacePathChallenge(proof.pagePath, proof.pageChallenge, probe.marker)
        : proof.pagePath,
    });
  }
  if (finding.proof.type !== "oast-callback") return finding;
  const proof = finding.proof;
  const probe = store.issueOastProbe();
  return replaceChallenge(finding, proof.requestIndex, proof.challenge, probe.url, {
    ...proof,
    probeId: probe.probeId,
    token: probe.token,
    callbackUrl: probe.url,
  });
}

function replacePathChallenge(
  path: string,
  challenge: { location: "query" | "json-body"; parameter: string; template: string },
  value: string,
): string {
  if (challenge.location !== "query" || challenge.template.split("{{challenge}}").length !== 2) {
    return path;
  }
  const url = new URL(path, "http://proof.invalid");
  if (url.searchParams.getAll(challenge.parameter).length !== 1) return path;
  url.searchParams.set(challenge.parameter, challenge.template.replace("{{challenge}}", value));
  return `${url.pathname}${url.search}${url.hash}`;
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
