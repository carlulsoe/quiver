import type { JsonValue } from "vitest-evals";
import type { FindingCategory } from "../prototype/state.ts";
import type { RestMethod } from "../prototype/scoped-target.ts";
import type { TargetProfileId } from "../targets/profiles.ts";
import { compareVampiPair } from "./vampi-oracle.ts";
import type { EvalFailure } from "./failure-classification.ts";

export const SECURITY_EVAL_PROFILE_IDS = [
  "crapi",
  "vampi-vulnerable",
  "vampi-secure",
  "vulnerableapp",
  "held-out",
] as const satisfies readonly TargetProfileId[];

export type SecurityEvalProfileId = (typeof SECURITY_EVAL_PROFILE_IDS)[number];
export type CoverageKind = "benchmark" | "held-out-fixture" | "operation";
export type ScoreKind =
  | "crapi-read-only"
  | "vampi-differential"
  | "vampi-differential-pending"
  | "vulnerableapp-native"
  | "held-out-canary";

export interface SecurityEvalInput {
  profileId: SecurityEvalProfileId;
  target?: string;
  requestBudget: number;
  explorerCount?: number;
  heldOutSeed?: string;
}

export interface EvalFinding extends Record<string, JsonValue> {
  category: FindingCategory;
  endpoint: string;
  method: RestMethod;
  cwe: string;
  proofType: string;
  proofPolicyId: string | null;
}

export interface SecurityEvalOutput extends Record<string, JsonValue> {
  profileId: SecurityEvalProfileId;
  target: string;
  model: string;
  phase: string;
  findingCount: number;
  confirmedCount: number;
  rejectedCount: number;
  unvalidatedCount: number;
  confirmedFingerprints: string[];
  confirmedFindings: EvalFinding[];
  coverage: number;
  coverageKind: CoverageKind;
  precision: number;
  validationCompleteness: number;
  durationMs: number;
  tokens: number;
  failures: string[];
  failureClassifications: EvalFailure[];
  failureCount: number;
  scoreKind: ScoreKind;
  scoreDetails: Record<string, JsonValue>;
  benchmarkTruePositiveCount: number;
  benchmarkFalsePositiveCount: number;
  benchmarkMissedCount: number;
  benchmarkUnscoredCount: number;
  benchmarkCoverage: number;
  benchmarkPrecision: number;
  requestsPerTruePositive: number | null;
  matchedBenchmarkIds: string[];
  missedBenchmarkIds: string[];
  requestsUsed: number;
  requestBudget: number;
  explorationRequests: number;
  validationRequests: number;
  agentFailures: number;
  operationCoverage: number;
  modelTokens: number;
  approximateModelCost: number;
  error: string | null;
  heldOutSeed: string | null;
}

interface DifferentialScore {
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

export function applyVampiDifferentialScoring(
  vulnerable: SecurityEvalOutput,
  secure: SecurityEvalOutput,
): void {
  if (vulnerable.profileId !== "vampi-vulnerable" || secure.profileId !== "vampi-secure") {
    throw new Error("VAmPI differential scoring requires vulnerable and secure outputs");
  }
  const oracle = compareVampiPair(vulnerable.confirmedFindings, secure.confirmedFindings);
  const details = {
    vulnerableOnly: oracle.vulnerableOnly,
    secureAlso: oracle.secureAlso,
    secureOnly: oracle.secureOnly,
  };
  const vulnerableClaims = oracle.vulnerableOnlyCount + oracle.secureAlsoCount;
  setScore(vulnerable, {
    kind: "vampi-differential",
    coverage: vulnerable.operationCoverage,
    coverageKind: "operation",
    precision: vulnerableClaims === 0 ? 0 : oracle.vulnerableOnlyCount / vulnerableClaims,
    truePositiveCount: oracle.vulnerableOnlyCount,
    falsePositiveCount: oracle.secureAlsoCount,
    missedCount: 0,
    unscoredCount: 0,
    requestsPerTruePositive:
      oracle.vulnerableOnlyCount === 0
        ? null
        : vulnerable.requestsUsed / oracle.vulnerableOnlyCount,
    matchedIds: oracle.vulnerableOnly,
    missedIds: [],
    details,
  });
  setScore(secure, {
    kind: "vampi-differential",
    coverage: secure.operationCoverage,
    coverageKind: "operation",
    precision: secure.confirmedCount === 0 ? 1 : 0,
    truePositiveCount: 0,
    falsePositiveCount: oracle.secureAlsoCount + oracle.secureOnlyCount,
    missedCount: 0,
    unscoredCount: 0,
    requestsPerTruePositive: null,
    matchedIds: [],
    missedIds: [],
    details,
  });
}

function setScore(output: SecurityEvalOutput, score: DifferentialScore): void {
  output.scoreKind = score.kind;
  output.scoreDetails = score.details;
  output.coverage = score.coverage;
  output.coverageKind = score.coverageKind;
  output.precision = score.precision;
  output.benchmarkTruePositiveCount = score.truePositiveCount;
  output.benchmarkFalsePositiveCount = score.falsePositiveCount;
  output.benchmarkMissedCount = score.missedCount;
  output.benchmarkUnscoredCount = score.unscoredCount;
  output.benchmarkCoverage = score.coverage;
  output.benchmarkPrecision = score.precision;
  output.requestsPerTruePositive = score.requestsPerTruePositive;
  output.matchedBenchmarkIds = score.matchedIds;
  output.missedBenchmarkIds = score.missedIds;
}
