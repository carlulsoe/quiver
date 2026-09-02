import { evaluateProof, type ProofEvaluationContext } from "./proof.ts";
import type { Finding, ProofPredicate, ValidationObservation } from "./state.ts";
import type { ProofPolicy } from "./target-profile.ts";

export function policyFinding(
  category: Finding["category"],
  endpoint: string,
  method: Finding["method"],
  reproduction: Finding["reproduction"],
  proof: ProofPredicate,
): Finding {
  return {
    fingerprint: `${category}:${method ?? "GET"}:${endpoint}`,
    agentId: "explorer-1",
    title: "Policy-backed proof",
    category,
    severity: "high",
    cwe: "CWE-1",
    endpoint,
    method,
    resource: "synthetic",
    rationale: "A target-owned proof contract was satisfied.",
    impact: "Synthetic impact.",
    mitigation: "Enforce the declared contract.",
    reproduction,
    proof,
  };
}

export function observation<Body>(
  path: string,
  body: Body,
  method: ValidationObservation["method"] = "GET",
): ValidationObservation {
  return {
    path,
    method,
    status: 200,
    actorId:
      path.startsWith("/settings") || path.startsWith("/comments") || path.startsWith("/preview")
        ? "ordinary-user"
        : "anonymous",
    body,
    truncated: false,
  };
}

export function evaluateWithPolicy(
  finding: Finding,
  observations: ValidationObservation[],
  policy: ProofPolicy,
  context: Omit<ProofEvaluationContext, "policies"> = {},
) {
  return evaluateProof(finding, observations, { ...context, policies: [policy] });
}
