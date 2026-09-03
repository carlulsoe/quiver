import { compatiblePredicates } from "./proof-compatibility.ts";
import { proofCheckHandlers } from "./proof-handlers.ts";
import { check } from "./proof-json.ts";
import { affectedOperationIsRepresented } from "./proof-operation.ts";
import { redactCredentialsWithContext } from "./security/redaction.ts";
import type { ProofEvaluationContext, ProofEvaluationFinding, ProofType } from "./proof-types.ts";
import { impactSafetyChecks } from "./impact.ts";
import type { Finding, ProofCheck, ProofResult, ValidationObservation } from "./state.ts";

export function evaluateProof(
  finding: Pick<
    Finding,
    "category" | "endpoint" | "method" | "impactLevel" | "proof" | "reproduction"
  >,
  observations: readonly ValidationObservation[],
  context: ProofEvaluationContext = {},
): ProofResult {
  const checks: ProofCheck[] = [
    check(
      predicateIsCompatible(finding.category, finding.proof.type),
      `predicate ${finding.proof.type} is compatible with ${finding.category}`,
    ),
    check(
      observations.length === finding.reproduction.length,
      "every reproduction request was replayed",
      `${observations.length}/${finding.reproduction.length}`,
    ),
    check(
      affectedOperationIsRepresented(finding, context.policies),
      "affected operation matches a reproduction request",
    ),
    check(!observations.some(({ truncated }) => truncated), "proof responses were not truncated"),
    check(
      observations.every(
        (observation, index) => observation.actorId === finding.reproduction[index]?.actorId,
      ),
      "every replay observation used its declared actor session",
    ),
  ];
  if (context.maximumImpactLevel) {
    checks.push(...impactSafetyChecks(finding, context.maximumImpactLevel));
  }

  evaluatePredicate(finding, observations, checks, context);

  const passed = checks.every((item) => item.passed);
  const result: ProofResult = {
    predicate: finding.proof.type,
    ...(finding.proof.type === "oast-callback"
      ? { classification: "server-side-request-forgery" as const }
      : finding.proof.type === "command-execution-challenge"
        ? { classification: "command-execution" as const }
        : {}),
    passed,
    summary: passed
      ? `Deterministic ${finding.proof.type} predicate passed ${checks.length}/${checks.length} checks.`
      : `Deterministic ${finding.proof.type} predicate failed ${checks.filter((item) => !item.passed).length}/${checks.length} checks.`,
    checks,
  };
  return redactCredentialsWithContext(result, { finding, observations });
}

function predicateIsCompatible(
  category: Finding["category"],
  predicate: Finding["proof"]["type"],
): boolean {
  return compatiblePredicates[category].some((candidate) => candidate === predicate);
}

function evaluatePredicate<K extends ProofType>(
  finding: ProofEvaluationFinding<K>,
  observations: readonly ValidationObservation[],
  checks: ProofCheck[],
  context: ProofEvaluationContext,
): void {
  const handler = proofCheckHandlers[finding.proof.type];
  handler(finding, observations, checks, context);
}
