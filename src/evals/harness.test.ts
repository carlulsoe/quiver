import { describe, expect, it, vi } from "vitest";
import type { CampaignRun } from "../prototype/runner.ts";
import {
  createCampaignBudget,
  createCampaignState,
  reduceCampaign,
  type CampaignState,
  type FindingInput,
} from "../prototype/state.ts";
import {
  applyVampiDifferentialScoring,
  createSecurityEvalOutput,
  type EvalFinding,
  type SecurityEvalOutput,
  type SecurityEvalProfileId,
} from "./harness.ts";

describe("profile-agnostic eval scoring", () => {
  it("scores the held-out canary and records the uniform metrics", async () => {
    const run = campaignRun(heldOutFinding());

    const result = await createSecurityEvalOutput(
      "held-out",
      new URL("http://127.0.0.1:8899"),
      run,
    );

    expect(result).toMatchObject({
      profileId: "held-out",
      scoreKind: "held-out-canary",
      coverage: 1,
      precision: 1,
      validationCompleteness: 1,
      durationMs: 2_500,
      tokens: 321,
      failures: [],
    });
  });

  it("automatically invokes VulnerableApp's native scoring adapter", async () => {
    const transport = vi.fn(async () =>
      Response.json({
        coverage: 25,
        totalExpected: 8,
        detected: 2,
        missed: 6,
        unmatched: 1,
        missedItems: [{ url: "/missed" }],
        unmatchedItems: [{ url: "/unmatched" }],
      }),
    );
    vi.stubGlobal("fetch", transport);
    try {
      const result = await createSecurityEvalOutput(
        "vulnerableapp",
        new URL("http://127.0.0.1:9090/VulnerableApp/"),
        campaignRun(nativeFinding()),
      );

      expect(transport).toHaveBeenCalledOnce();
      expect(result).toMatchObject({
        scoreKind: "vulnerableapp-native",
        coverage: 0.25,
        precision: 2 / 3,
        benchmarkFalsePositiveCount: 1,
        scoreDetails: {
          missedItems: [{ url: "/missed" }],
          falsePositiveItems: [{ url: "/unmatched" }],
        },
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("applies the VAmPI differential adapter to both isolated mode outputs", () => {
    const shared = finding("sensitive-data-exposure", "/users/v1/_debug");
    const vulnerableOnly = finding("broken-object-authorization", "/books/v1/foreign-title");
    const vulnerable = output("vampi-vulnerable", [shared, vulnerableOnly]);
    const secure = output("vampi-secure", [shared]);

    applyVampiDifferentialScoring(vulnerable, secure);

    expect(vulnerable).toMatchObject({
      scoreKind: "vampi-differential",
      coverage: 0.75,
      precision: 0.5,
      benchmarkTruePositiveCount: 1,
      benchmarkFalsePositiveCount: 1,
      scoreDetails: {
        vulnerableOnly: ["broken-object-authorization:GET:/books/v1/foreign-title"],
        secureAlso: ["sensitive-data-exposure:GET:/users/v1/_debug"],
      },
    });
    expect(secure).toMatchObject({
      scoreKind: "vampi-differential",
      precision: 0,
      benchmarkFalsePositiveCount: 1,
    });
  });
});

function finding(category: EvalFinding["category"], endpoint: string): EvalFinding {
  return {
    category,
    endpoint,
    method: "GET",
    cwe: "CWE-200",
    proofType: "internal-field-exposure",
    proofPolicyId: null,
  };
}

function output(
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
  };
}

function heldOutFinding(): FindingInput {
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
    reproduction: [{ path: "/api/random/vaults/foreign", authenticated: true }],
    proof: {
      type: "canary-retrieval",
      policyId: "held-out-record-canary",
      requestIndex: 0,
      jsonPointer: "/record/canary",
    },
  };
}

function nativeFinding(): FindingInput {
  return {
    ...heldOutFinding(),
    endpoint: "/VulnerableApp/example",
    cwe: "CWE-200",
    proof: { type: "internal-field-exposure", requestIndex: 0, evidencePointers: ["/secret"] },
  };
}

function campaignRun(finding: FindingInput): CampaignRun {
  let state: CampaignState = createCampaignState(
    "http://127.0.0.1:8899/",
    createCampaignBudget(30),
    1,
  );
  state = reduceCampaign(state, { type: "phase", phase: "exploring" });
  state = reduceCampaign(state, {
    type: "operations-discovered",
    operations: [{ method: "GET", path: finding.endpoint }],
  });
  state = reduceCampaign(state, {
    type: "request-tested",
    request: {
      agentId: "explorer-1",
      path: finding.endpoint,
      method: "GET",
      authenticated: true,
      status: 200,
    },
  });
  state = reduceCampaign(state, { type: "finding", finding });
  state = reduceCampaign(state, { type: "phase", phase: "validating" });
  state = reduceCampaign(state, {
    type: "validation",
    validation: {
      fingerprint: state.findings[0]!.fingerprint,
      status: "confirmed",
      evidence: "canary matched",
      proof: {
        predicate: "canary-retrieval",
        passed: true,
        summary: "canary matched",
        checks: [],
      },
      observations: [],
      reviewer: { assessment: "supported", evidence: "replay matched" },
    },
  });
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
    state,
    events: [],
  };
}
