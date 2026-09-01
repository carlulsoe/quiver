import { createHarness, toJsonValue, type JsonValue, type TranscriptEvent } from "vitest-evals";
import { campaignOperationCoverage, type Finding } from "../prototype/state.ts";
import { normalizeEndpoint } from "../prototype/endpoint.ts";
import { runCampaign, type CampaignRun } from "../prototype/runner.ts";
import { getDefaultTarget, getTargetProfile } from "../targets/profiles.ts";
import { createHeldOutFixture } from "../targets/held-out-fixture.ts";
import { createHeldOutProfile } from "../targets/held-out.ts";
import { scoreCrapiReadOnlyBenchmark } from "./crapi-benchmark.ts";
import { classifyCampaignFailures } from "./failure-classification.ts";
import type {
  CoverageKind,
  EvalFinding,
  ScoreKind,
  SecurityEvalInput,
  SecurityEvalOutput,
  SecurityEvalProfileId,
} from "./security-eval.ts";
import { scoreVulnerableAppBenchmark } from "./vulnerableapp-benchmark.ts";

export { applyVampiDifferentialScoring, SECURITY_EVAL_PROFILE_IDS } from "./security-eval.ts";
export type {
  CoverageKind,
  EvalFinding,
  ScoreKind,
  SecurityEvalInput,
  SecurityEvalOutput,
  SecurityEvalProfileId,
} from "./security-eval.ts";

interface NormalizedScore {
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

export const securityHarness = createHarness<SecurityEvalInput, SecurityEvalOutput>({
  name: "bounded-security-campaign",
  run: async ({ input, setArtifact }) => {
    const fixture =
      input.profileId === "held-out" && input.heldOutSeed
        ? createHeldOutFixture(input.heldOutSeed)
        : undefined;
    const fixtureServer =
      fixture && !input.target
        ? Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: fixture.fetch })
        : undefined;
    const profile = fixture
      ? createHeldOutProfile(fixture.seed)
      : getTargetProfile(input.profileId);
    const target = new URL(input.target ?? fixtureServer?.url ?? getDefaultTarget(input.profileId));
    const transitions: string[] = [];
    try {
      const run = await runCampaign({
        target,
        profile,
        requestBudget: input.requestBudget,
        explorerCount: input.explorerCount,
        onState: (_state, action) => {
          if (action) transitions.push(action.type);
        },
      });
      const output = await createSecurityEvalOutput(input.profileId, target, run, {
        heldOutSeed: input.heldOutSeed,
      });

      setArtifact("findings", toJsonValue(run.state.findings) ?? []);
      setArtifact("validations", toJsonValue(run.state.validations) ?? []);
      setArtifact("transitions", transitions);
      setArtifact("runTrace", toJsonValue(run.events) ?? []);

      return {
        output,
        events: [
          { type: "message", role: "user", content: JSON.stringify(input) },
          ...transcriptEvents(run),
          { type: "message", role: "assistant", content: output },
        ],
        usage: { model: run.model, provider: "openrouter" },
      };
    } finally {
      fixtureServer?.stop(true);
    }
  },
});

export async function createSecurityEvalOutput(
  profileId: SecurityEvalProfileId,
  target: URL,
  run: CampaignRun,
  metadata: { heldOutSeed?: string } = {},
): Promise<SecurityEvalOutput> {
  const confirmedFingerprints = run.state.validations
    .filter((validation) => validation.status === "confirmed")
    .map((validation) => validation.fingerprint);
  const confirmedSet = new Set(confirmedFingerprints);
  const confirmed = run.state.findings.filter((finding) => confirmedSet.has(finding.fingerprint));
  const rejectedCount = run.state.validations.filter(
    (validation) => validation.status === "rejected",
  ).length;
  const unvalidatedCount = run.state.findings.length - run.state.validations.length;
  const operationCoverage = campaignOperationCoverage(run.state).coverage;
  const failures = run.state.agents
    .filter((agent) => agent.status === "failed")
    .map((agent) => `agent:${agent.id}`);
  if (run.state.error) failures.push(`campaign:${run.state.error}`);
  const failureClassifications = classifyCampaignFailures(run);

  let score: NormalizedScore;
  try {
    score = await scoreProfile(
      profileId,
      target,
      confirmed,
      run.state.requests.total,
      operationCoverage,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    failures.push(`scoring:${message}`);
    failureClassifications.push({ kind: "infrastructure", source: "scoring", message });
    score = emptyScore(profileId, operationCoverage);
  }

  return {
    profileId,
    target: target.href,
    model: run.model,
    phase: run.state.phase,
    findingCount: run.state.findings.length,
    confirmedCount: confirmed.length,
    rejectedCount,
    unvalidatedCount,
    confirmedFingerprints,
    confirmedFindings: confirmed.map(evalFinding),
    coverage: score.coverage,
    coverageKind: score.coverageKind,
    precision: score.precision,
    validationCompleteness:
      run.state.findings.length === 0
        ? 1
        : run.state.validations.length / run.state.findings.length,
    durationMs: run.durationMs,
    tokens: run.usage.totalTokens,
    failures,
    failureClassifications,
    failureCount: failures.length,
    scoreKind: score.kind,
    scoreDetails: score.details,
    benchmarkTruePositiveCount: score.truePositiveCount,
    benchmarkFalsePositiveCount: score.falsePositiveCount,
    benchmarkMissedCount: score.missedCount,
    benchmarkUnscoredCount: score.unscoredCount,
    benchmarkCoverage: score.coverage,
    benchmarkPrecision: score.precision,
    requestsPerTruePositive: score.requestsPerTruePositive,
    matchedBenchmarkIds: score.matchedIds,
    missedBenchmarkIds: score.missedIds,
    requestsUsed: run.state.requests.total,
    requestBudget: run.state.budget.total,
    explorationRequests: run.state.requests.exploration,
    validationRequests: run.state.requests.validation,
    agentFailures: run.state.agents.filter((agent) => agent.status === "failed").length,
    operationCoverage,
    modelTokens: run.usage.totalTokens,
    approximateModelCost: run.usage.cost.total,
    error: run.state.error ?? null,
    heldOutSeed: metadata.heldOutSeed ?? null,
  };
}

async function scoreProfile(
  profileId: SecurityEvalProfileId,
  target: URL,
  confirmed: readonly Finding[],
  requestsUsed: number,
  operationCoverage: number,
): Promise<NormalizedScore> {
  if (profileId === "crapi") {
    const result = scoreCrapiReadOnlyBenchmark({
      confirmedFindings: [...confirmed],
      requestsUsed,
    });
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
  const matchedFindings = confirmed.filter(matchesHeldOutBenchmark);
  const truePositiveCount = Math.min(matchedFindings.length, 1);
  const falsePositiveCount = confirmed.length - matchedFindings.length;
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
  ) {
    return true;
  }
  return (
    finding.category === "broken-object-authorization" &&
    finding.proof.type === "cross-principal-access" &&
    /^\/api\/[^/]+\/vaults\/\{id\}$/.test(normalizeEndpoint(finding.endpoint))
  );
}

function emptyScore(profileId: SecurityEvalProfileId, operationCoverage: number): NormalizedScore {
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

function evalFinding(finding: Finding): EvalFinding {
  return {
    category: finding.category,
    endpoint: finding.endpoint,
    method: finding.method ?? "GET",
    cwe: finding.cwe,
    proofType: finding.proof.type,
    proofPolicyId: "policyId" in finding.proof ? finding.proof.policyId : null,
  };
}

function transcriptEvents(run: CampaignRun): TranscriptEvent[] {
  const toolNames = new Map<string, string>();
  const events: TranscriptEvent[] = [];
  for (const event of run.events) {
    const toolCallId = event.data.toolCallId;
    if (typeof toolCallId !== "string") continue;
    if (event.type === "tool-call") {
      const toolName = event.data.toolName;
      if (typeof toolName !== "string") continue;
      toolNames.set(toolCallId, toolName);
      const inputValue = toJsonValue(event.data.input);
      events.push({
        type: "tool_call",
        id: toolCallId,
        name: toolName,
        arguments:
          inputValue && typeof inputValue === "object" && !Array.isArray(inputValue)
            ? inputValue
            : { value: inputValue ?? null },
        metadata: { agentId: String(event.data.agentId) },
      });
    } else if (event.type === "tool-output") {
      events.push({
        type: "tool_result",
        toolCallId,
        name: toolNames.get(toolCallId),
        content: toJsonValue(event.data.output),
        durationMs: typeof event.data.durationMs === "number" ? event.data.durationMs : undefined,
        metadata: { agentId: String(event.data.agentId) },
      });
    } else if (event.type === "tool-error") {
      events.push({
        type: "tool_result",
        toolCallId,
        name: toolNames.get(toolCallId),
        error: { name: "ToolError", message: String(event.data.error) },
        durationMs: typeof event.data.durationMs === "number" ? event.data.durationMs : undefined,
        metadata: { agentId: String(event.data.agentId) },
      });
    }
  }
  return events;
}
