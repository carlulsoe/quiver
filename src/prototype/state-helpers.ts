import { emptyCampaignHistory } from "./campaign-history.ts";
import { normalizeEndpoint } from "./endpoint.ts";
import type {
  CampaignJob,
  CampaignRuntimeState,
  CampaignState,
  DiscoveredOperation,
  ExploitChainInput,
  FindingInput,
  ImpactLevel,
} from "./state-types.ts";

export function validationJobId(fingerprint: string): string {
  return `validation:${fingerprint}`;
}
export function exploitChainJobId(fingerprint: string): string {
  return `exploit-chain:${fingerprint}`;
}

export function campaignJob(
  kind: CampaignJob["kind"],
  fingerprint: string,
  impactLevel: ImpactLevel,
): CampaignJob {
  return {
    id: kind === "validation" ? validationJobId(fingerprint) : exploitChainJobId(fingerprint),
    kind,
    fingerprint,
    impactLevel,
    status: "queued",
    attempts: 0,
    mutationStarted: false,
  };
}

export function completeJob(runtime: CampaignRuntimeState, id: string): CampaignRuntimeState {
  return {
    ...runtime,
    jobs: runtime.jobs.map((job) =>
      job.id === id
        ? { ...job, status: "completed", mutationStarted: false, error: undefined }
        : job,
    ),
  };
}

export function withRuntimeState(state: CampaignState): CampaignState {
  const runtime = state.runtime ?? {
    control: "running" as const,
    consecutiveFailures: 0,
    disruptiveResponses: 0,
    jobs: [
      ...state.findings
        .filter(
          (finding) =>
            !state.validations.some((validation) => validation.fingerprint === finding.fingerprint),
        )
        .map((finding) =>
          campaignJob(
            "validation",
            finding.fingerprint,
            finding.impactLevel ?? deriveImpactLevel(finding),
          ),
        ),
      ...state.exploitChains
        .filter(
          (chain) =>
            !state.exploitChainValidations.some(
              (validation) => validation.fingerprint === chain.fingerprint,
            ),
        )
        .map((chain) => campaignJob("exploit-chain", chain.fingerprint, chain.impactLevel)),
    ],
  };
  return {
    ...state,
    runtime: {
      ...runtime,
      jobs: runtime.jobs.map((job) => ({ ...job, mutationStarted: job.mutationStarted ?? false })),
    },
    history: state.history ?? emptyCampaignHistory(),
  };
}

export function fingerprintExploitChain(chain: Pick<ExploitChainInput, "steps">): string {
  return `exploit-chain:${chain.steps.map((step) => `${step.length}:${step}`).join("")}`;
}
export function fingerprintFinding(
  finding: Pick<FindingInput, "category" | "endpoint" | "method">,
): string {
  return `${finding.category}:${finding.method ?? "GET"}:${normalizeEndpoint(finding.endpoint)}`;
}
export function deriveImpactLevel(
  finding: Pick<FindingInput, "proof" | "reproduction">,
): ImpactLevel {
  if (
    ["state-transition", "browser-state-transition"].includes(finding.proof.type) ||
    finding.reproduction.some(({ method = "GET" }) => !["GET", "HEAD", "OPTIONS"].includes(method))
  )
    return "state-change";
  return ["browser-visible-effect", "oast-callback", "command-execution-challenge"].includes(
    finding.proof.type,
  )
    ? "bounded"
    : "observation";
}
export function normalizeFindingInput<T extends FindingInput>(
  finding: T,
): T & { impactLevel: ImpactLevel } {
  return { ...finding, impactLevel: finding.impactLevel ?? deriveImpactLevel(finding) };
}
export function operationKey(operation: Pick<DiscoveredOperation, "method" | "path">): string {
  return `${operation.method} ${normalizeEndpoint(operation.path)}`;
}
export interface CampaignOperationCoverage {
  discovered: number;
  tested: number;
  coverage: number;
}
export function campaignOperationCoverage(state: CampaignState): CampaignOperationCoverage {
  const discovered = new Set(
    state.discoveredOperations.length > 0
      ? state.discoveredOperations.map(operationKey)
      : state.discoveredRoutes.map((path) => operationKey({ method: "GET", path })),
  );
  const tested = new Set(
    state.testedRequests
      .map(({ path, method }) => operationKey({ method: method ?? "GET", path }))
      .filter((operation) => discovered.has(operation)),
  ).size;
  return {
    discovered: discovered.size,
    tested,
    coverage: discovered.size === 0 ? 0 : tested / discovered.size,
  };
}
export const campaignRouteCoverage = campaignOperationCoverage;
