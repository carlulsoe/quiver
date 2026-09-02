import { record, safeParse, string, unknown } from "valibot";
import { endpointMatchesRequest } from "./endpoint.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import type { Finding } from "./state.ts";
import { browserPolicyPath, type ProofPolicy } from "./target-profile.ts";

export function prepareFreshChallenge(
  finding: Finding,
  store: ProofArtifactStore | undefined,
  policies: readonly ProofPolicy[],
): Finding {
  if (!store || !["browser-visible-effect", "oast-callback"].includes(finding.proof.type))
    return finding;
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
  )
    throw new Error("Proof challenge request is not the affected finding operation");
}

function replaceChallenge(
  finding: Finding,
  requestIndex: number,
  challenge: { location: "query" | "json-body" | "fragment"; parameter: string; template: string },
  value: string,
  proof: Finding["proof"],
): Finding {
  const request = finding.reproduction[requestIndex];
  if (!request || challenge.template.split("{{challenge}}").length !== 2) return finding;
  const replacement = challenge.template.replace("{{challenge}}", value);
  const nextRequest = { ...request };
  if (challenge.location === "query" || challenge.location === "fragment") {
    const url = new URL(request.path, "http://proof.invalid");
    const parameters =
      challenge.location === "query" ? url.searchParams : new URLSearchParams(url.hash.slice(1));
    if (parameters.getAll(challenge.parameter).length !== 1) return finding;
    parameters.set(challenge.parameter, replacement);
    if (challenge.location === "fragment") url.hash = parameters.toString();
    nextRequest.path = `${url.pathname}${url.search}${url.hash}`;
  } else {
    try {
      const parsed = safeParse(record(string(), unknown()), JSON.parse(request.body ?? ""));
      if (!parsed.success) return finding;
      nextRequest.body = JSON.stringify({ ...parsed.output, [challenge.parameter]: replacement });
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
