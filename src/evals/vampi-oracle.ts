import { normalizeEndpoint, type Finding } from "../prototype/state.ts";

export interface VampiOracleResult {
  vulnerableOnly: string[];
  secureAlso: string[];
  secureOnly: string[];
  vulnerableOnlyCount: number;
  secureAlsoCount: number;
  secureOnlyCount: number;
}

type OracleFinding = Pick<Finding, "category" | "endpoint" | "method">;

export function compareVampiPair(
  vulnerableFindings: readonly OracleFinding[],
  secureFindings: readonly OracleFinding[],
): VampiOracleResult {
  const vulnerable = new Set(vulnerableFindings.map(fingerprint));
  const secure = new Set(secureFindings.map(fingerprint));
  const vulnerableOnly = [...vulnerable].filter((value) => !secure.has(value)).sort();
  const secureAlso = [...vulnerable].filter((value) => secure.has(value)).sort();
  const secureOnly = [...secure].filter((value) => !vulnerable.has(value)).sort();
  return {
    vulnerableOnly,
    secureAlso,
    secureOnly,
    vulnerableOnlyCount: vulnerableOnly.length,
    secureAlsoCount: secureAlso.length,
    secureOnlyCount: secureOnly.length,
  };
}

function fingerprint(finding: OracleFinding): string {
  return `${finding.category}:${finding.method ?? "GET"}:${normalizeEndpoint(finding.endpoint)}`;
}
