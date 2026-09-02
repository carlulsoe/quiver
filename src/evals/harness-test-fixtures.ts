import type { CampaignRun } from "../prototype/runner.ts";
import {
  createCampaignBudget,
  createCampaignState,
  reduceCampaign,
  type CampaignState,
  type FindingInput,
} from "../prototype/state.ts";
import type { EvalFinding, SecurityEvalOutput, SecurityEvalProfileId } from "./harness.ts";

export function finding(category: EvalFinding["category"], endpoint: string): EvalFinding {
  return {
    category,
    endpoint,
    method: "GET",
    cwe: "CWE-200",
    proofType: "internal-field-exposure",
    proofPolicyId: null,
  };
}

export function output(
  profileId: SecurityEvalProfileId,
  confirmedFindings: EvalFinding[],
): SecurityEvalOutput {
  return {
    profileId,
    target: "http://127.0.0.1/",
    model: "test-model",
    phase: "complete",
    findingCount: confirmedFindings.length,
    confirmedCount: confirmedFindings.length,
    rejectedCount: 0,
    unvalidatedCount: 0,
    confirmedFingerprints: [],
    confirmedFindings,
    coverage: 0.75,
    coverageKind: "operation",
    precision: 0,
    validationCompleteness: 1,
    durationMs: 1_000,
    tokens: 100,
    failures: [],
    failureClassifications: [],
    failureCount: 0,
    scoreKind: "vampi-differential-pending",
    scoreDetails: {},
    benchmarkTruePositiveCount: 0,
    benchmarkFalsePositiveCount: 0,
    benchmarkMissedCount: 0,
    benchmarkUnscoredCount: 0,
    benchmarkCoverage: 0.75,
    benchmarkPrecision: 0,
    requestsPerTruePositive: null,
    matchedBenchmarkIds: [],
    missedBenchmarkIds: [],
    requestsUsed: 20,
    requestBudget: 42,
    explorationRequests: 15,
    validationRequests: 5,
    agentFailures: 0,
    operationCoverage: 0.75,
    modelTokens: 100,
    approximateModelCost: 0.01,
    error: null,
    heldOutSeed: null,
  };
}

export function heldOutFinding(): FindingInput {
  return {
    agentId: "explorer-1",
    title: "Cross-principal record",
    category: "sensitive-data-exposure",
    severity: "high",
    cwe: "CWE-200",
    endpoint: "/api/random/vaults/{id}",
    method: "GET",
    resource: "foreign vault",
    rationale: "The response contains another principal's canary.",
    impact: "A user can read another user's record.",
    mitigation: "Enforce ownership.",
    reproduction: [{ path: "/api/random/vaults/foreign", actorId: "ordinary-user" }],
    proof: {
      type: "canary-retrieval",
      policyId: "held-out-record-canary",
      requestIndex: 0,
      jsonPointer: "/record/canary",
    },
  };
}

export function nativeFinding(): FindingInput {
  return {
    ...heldOutFinding(),
    endpoint: "/VulnerableApp/example",
    cwe: "CWE-200",
    proof: { type: "internal-field-exposure", requestIndex: 0, evidencePointers: ["/secret"] },
  };
}

export function heldOutBolaFinding(): FindingInput {
  return {
    ...heldOutFinding(),
    title: "Cross-principal vault access",
    category: "broken-object-authorization",
    cwe: "CWE-639",
    reproduction: [
      { path: "/api/random/session", actorId: "ordinary-user" },
      { path: "/api/random/vaults/foreign", actorId: "ordinary-user" },
    ],
    proof: {
      type: "cross-principal-access",
      actor: { requestIndex: 0, jsonPointer: "/principal/id" },
      resourceOwner: { requestIndex: 1, jsonPointer: "/owner/id" },
      accessRequestIndex: 1,
      evidencePointers: ["/record/canary"],
    },
  };
}

export function campaignRun(input: FindingInput | FindingInput[]): CampaignRun {
  const findings = Array.isArray(input) ? input : [input];
  let state: CampaignState = createCampaignState(
    "http://127.0.0.1:8899/",
    createCampaignBudget(30),
    1,
  );
  state = reduceCampaign(state, { type: "phase", phase: "exploring" });
  state = reduceCampaign(state, {
    type: "operations-discovered",
    operations: findings.map((finding) => ({ method: "GET", path: finding.endpoint })),
  });
  for (const finding of findings) {
    state = reduceCampaign(state, {
      type: "request-tested",
      request: {
        agentId: "explorer-1",
        path: finding.endpoint,
        method: "GET",
        actorId: "ordinary-user",
        status: 200,
      },
    });
    state = reduceCampaign(state, { type: "finding", finding });
  }
  state = reduceCampaign(state, { type: "phase", phase: "validating" });
  for (const finding of state.findings) state = confirmFinding(state, finding);
  state = reduceCampaign(state, { type: "phase", phase: "complete" });
  return {
    profileId: "held-out",
    model: "test-model",
    durationMs: 2_500,
    usage: {
      input: 200,
      output: 121,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 321,
      cost: { input: 0.1, output: 0.2, cacheRead: 0, cacheWrite: 0, total: 0.3 },
    },
    missionUsage: [],
    state,
    events: [],
  };
}

function confirmFinding(
  state: CampaignState,
  finding: CampaignState["findings"][number],
): CampaignState {
  return reduceCampaign(state, {
    type: "validation",
    validation: {
      fingerprint: finding.fingerprint,
      status: "confirmed",
      evidence: "proof matched",
      proof: { predicate: finding.proof.type, passed: true, summary: "proof matched", checks: [] },
      observations: [],
      reviewer: { assessment: "supported", evidence: "replay matched" },
    },
  });
}
