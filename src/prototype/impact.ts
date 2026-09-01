import { deriveImpactLevel, type Finding, type ImpactLevel, type ProofCheck } from "./state.ts";

const ranks: Record<ImpactLevel, number> = {
  observation: 0,
  bounded: 1,
  "state-change": 2,
};

export function requiredImpactLevel(finding: Pick<Finding, "proof" | "reproduction">): ImpactLevel {
  return deriveImpactLevel(finding);
}

export function impactSafetyChecks(
  finding: Pick<Finding, "impactLevel" | "proof" | "reproduction">,
  maximum: ImpactLevel,
): ProofCheck[] {
  const required = requiredImpactLevel(finding);
  return [
    {
      description: `declared impact level matches the code-derived ${required} level`,
      passed: finding.impactLevel === required,
      actual: finding.impactLevel,
    },
    {
      description: `impact level stays within the target's ${maximum} ceiling`,
      passed: ranks[required] <= ranks[maximum],
      actual: required,
    },
    {
      description: "impact demonstration never uses DELETE",
      passed: finding.reproduction.every(({ method = "GET" }) => method !== "DELETE"),
    },
  ];
}

export function impactAtMost(level: ImpactLevel, maximum: ImpactLevel): boolean {
  return ranks[level] <= ranks[maximum];
}
