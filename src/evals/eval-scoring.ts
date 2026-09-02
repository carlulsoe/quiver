import { toJsonValue, type JsonValue } from "vitest-evals";
import { normalizeEndpoint } from "../prototype/endpoint.ts";
import type { Finding } from "../prototype/state.ts";
import { scoreCrapiReadOnlyBenchmark } from "./crapi-benchmark.ts";
import type {
  CoverageKind,
  EvalFinding,
  ScoreKind,
  SecurityEvalProfileId,
} from "./security-eval.ts";
import { scoreVulnerableAppBenchmark } from "./vulnerableapp-benchmark.ts";

export interface NormalizedScore {
  kind: ScoreKind;
  coverage: number;
  coverageKind: CoverageKind;
  precision: number;
  truePositiveCount: number;
  falsePositiveCount: number;
  missedCount: number;
  unscoredCount: number;
  requestsPerTruePositive: number | null;
  matchedIds: string[];
  missedIds: string[];
  details: Record<string, JsonValue>;
}

export async function scoreProfile(
  profileId: SecurityEvalProfileId,
  target: URL,
  confirmed: readonly Finding[],
  requestsUsed: number,
  operationCoverage: number,
): Promise<NormalizedScore> {
  if (profileId === "crapi") {
    const result = scoreCrapiReadOnlyBenchmark({ confirmedFindings: [...confirmed], requestsUsed });
    return {
      kind: "crapi-read-only",
      coverage: result.coverage,
      coverageKind: "benchmark",
      precision: result.precision,
      truePositiveCount: result.truePositiveCount,
      falsePositiveCount: result.falsePositiveCount,
      missedCount: result.missedCount,
      unscoredCount: result.unscoredCount,
      requestsPerTruePositive: result.requestsPerTruePositive,
      matchedIds: result.matchedBenchmarkIds,
      missedIds: result.missedBenchmarkIds,
      details: {
        falsePositiveFingerprints: result.falsePositiveFingerprints,
        unscoredFingerprints: result.unscoredFingerprints,
      },
    };
  }
  if (profileId === "vulnerableapp") {
    const result = await scoreVulnerableAppBenchmark({ target, confirmedFindings: confirmed });
    return {
      kind: "vulnerableapp-native",
      coverage: result.coverage,
      coverageKind: "benchmark",
      precision: result.precision,
      truePositiveCount: result.truePositiveCount,
      falsePositiveCount: result.falsePositiveCount,
      missedCount: result.missedCount,
      unscoredCount: 0,
      requestsPerTruePositive:
        result.truePositiveCount === 0 ? null : requestsUsed / result.truePositiveCount,
      matchedIds: [],
      missedIds: result.missedItems.map((_item, index) => `native-miss-${index + 1}`),
      details: {
        missedItems: toJsonValue(result.missedItems) ?? [],
        falsePositiveItems: toJsonValue(result.falsePositiveItems) ?? [],
      },
    };
  }
  if (profileId === "held-out") return scoreHeldOut(confirmed, requestsUsed);
  return emptyScore(profileId, operationCoverage);
}

function scoreHeldOut(confirmed: readonly Finding[], requestsUsed: number): NormalizedScore {
  const matchedCount = confirmed.filter(matchesHeldOutBenchmark).length;
  const truePositiveCount = Math.min(matchedCount, 1);
  const falsePositiveCount = confirmed.length - matchedCount;
  return {
    kind: "held-out-canary",
    coverage: truePositiveCount,
    coverageKind: "held-out-fixture",
    precision:
      confirmed.length === 0 ? 0 : truePositiveCount / (truePositiveCount + falsePositiveCount),
    truePositiveCount,
    falsePositiveCount,
    missedCount: 1 - truePositiveCount,
    unscoredCount: 0,
    requestsPerTruePositive: truePositiveCount === 0 ? null : requestsUsed / truePositiveCount,
    matchedIds: truePositiveCount === 0 ? [] : ["held-out-record-canary"],
    missedIds: truePositiveCount === 0 ? ["held-out-record-canary"] : [],
    details: {},
  };
}

function matchesHeldOutBenchmark(finding: Finding): boolean {
  if (
    finding.proof.type === "canary-retrieval" &&
    finding.proof.policyId === "held-out-record-canary"
  )
    return true;
  return (
    finding.category === "broken-object-authorization" &&
    finding.proof.type === "cross-principal-access" &&
    /^\/api\/[^/]+\/vaults\/\{id\}$/.test(normalizeEndpoint(finding.endpoint))
  );
}

export function emptyScore(
  profileId: SecurityEvalProfileId,
  operationCoverage: number,
): NormalizedScore {
  return {
    kind: profileId.startsWith("vampi-")
      ? "vampi-differential-pending"
      : profileId === "vulnerableapp"
        ? "vulnerableapp-native"
        : profileId === "held-out"
          ? "held-out-canary"
          : "crapi-read-only",
    coverage: operationCoverage,
    coverageKind: "operation",
    precision: 0,
    truePositiveCount: 0,
    falsePositiveCount: 0,
    missedCount: 0,
    unscoredCount: 0,
    requestsPerTruePositive: null,
    matchedIds: [],
    missedIds: [],
    details: {},
  };
}

export function evalFinding(finding: Finding): EvalFinding {
  return {
    category: finding.category,
    endpoint: finding.endpoint,
    method: finding.method ?? "GET",
    cwe: finding.cwe,
    proofType: finding.proof.type,
    proofPolicyId: "policyId" in finding.proof ? finding.proof.policyId : null,
  };
}
