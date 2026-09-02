import { normalizeEndpoint } from "./endpoint.ts";
import type { RestMethod } from "./scoped-target.ts";
import type { CoordinatorSnapshot } from "./adaptive-coordinator.ts";
import type { ActorId } from "./sessions.ts";

export { normalizeEndpoint } from "./endpoint.ts";

export type AgentStatus = "queued" | "running" | "finished" | "failed";
export type FindingCategory =
  | "broken-object-authorization"
  | "broken-function-authorization"
  | "authentication-bypass"
  | "excessive-data-exposure"
  | "sensitive-data-exposure"
  | "cross-site-scripting"
  | "sql-injection"
  | "command-injection"
  | "server-side-request-forgery"
  | "path-traversal"
  | "open-redirect"
  | "cross-site-request-forgery"
  | "business-logic"
  | "security-misconfiguration"
  | "other";

export type FindingSeverity = "low" | "medium" | "high" | "critical";
export type ImpactLevel = "observation" | "bounded" | "state-change";

export interface CampaignAgent {
  id: string;
  role: "explorer" | "specialist" | "validator";
  status: AgentStatus;
  summary?: string;
}

export interface ReproductionRequest {
  path: string;
  method?: RestMethod;
  headers?: Record<string, string>;
  body?: string;
  actorId: ActorId;
  /** Distinguishes intentional repeated samples from ledger-deduplicated requests. */
  sampleId?: string;
}

export interface JsonEvidenceSelector {
  requestIndex: number;
  jsonPointer: string;
}

export interface RequestMutation {
  location: "query" | "json-body";
  parameter: string;
  controlValue: string;
  probeValue: string;
}

export interface ChallengeMutation {
  location: "query" | "json-body";
  parameter: string;
  template: string;
}

export interface BrowserEffectEvidence {
  probeId: string;
  path: string;
  kind: "dialog";
  value: string;
}

export interface OastCallbackEvidence {
  probeId: string;
  token: string;
  protocol: "http";
  method: string;
  path: string;
  observedAt: string;
}

export interface ProofArtifacts {
  browserEffects: BrowserEffectEvidence[];
  oastCallbacks: OastCallbackEvidence[];
}

export type ProofPredicate =
  | {
      type: "cross-principal-access";
      actor: JsonEvidenceSelector;
      resourceOwner: JsonEvidenceSelector;
      accessRequestIndex: number;
      evidencePointers: string[];
    }
  | {
      type: "authentication-bypass";
      authenticatedRequestIndex: number;
      anonymousRequestIndex: number;
      evidencePointers: string[];
    }
  | {
      type: "role-privilege-differential";
      authorizedRequestIndex: number;
      lessPrivilegedRequestIndex: number;
      evidencePointers: string[];
    }
  | {
      type: "unauthenticated-success";
      requestIndex: number;
      evidencePointers: string[];
    }
  | {
      type: "cross-principal-data-exposure";
      actor: JsonEvidenceSelector;
      exposedSubject: JsonEvidenceSelector;
      responseRequestIndex: number;
      evidencePointers: string[];
    }
  | {
      type: "internal-field-exposure";
      requestIndex: number;
      evidencePointers: string[];
    }
  | {
      /** Supporting-only evidence; no category may use this as authoritative proof. */
      type: "response-differential";
      controlRequestIndex: number;
      probeRequestIndex: number;
      comparison: "status" | "body" | "json-value";
      expectation: "equal" | "different";
      jsonPointer?: string;
      mutation: RequestMutation;
    }
  | {
      /** Supporting-only evidence; no category may use this as authoritative proof. */
      type: "timing-differential";
      controlRequestIndexes: number[];
      probeRequestIndexes: number[];
      minimumDeltaMs: number;
      mutation: RequestMutation;
    }
  | {
      type: "sql-semantic-differential";
      policyId: string;
      controlRequestIndex: number;
      probeRequestIndex: number;
    }
  | {
      type: "command-execution-challenge";
      policyId: string;
      requestIndex: number;
      challenge: number;
    }
  | {
      type: "canary-retrieval";
      policyId: string;
      requestIndex: number;
      jsonPointer: string;
    }
  | {
      type: "state-transition";
      policyId: string;
      transitionRequestIndex: number;
      beforeRequestIndex: number;
      afterRequestIndex: number;
    }
  | {
      type: "browser-visible-effect";
      policyId: string;
      probeId: string;
      marker: string;
      requestIndex: number;
      pagePath: string;
      kind: "dialog";
      challenge: ChallengeMutation;
      pageActorId: ActorId;
      pageChallenge?: ChallengeMutation;
      collectorRequestBudget: number;
    }
  | {
      type: "oast-callback";
      policyId: string;
      probeId: string;
      token: string;
      requestIndex: number;
      callbackUrl: string;
      challenge: ChallengeMutation;
    };

export interface FindingInput {
  agentId: string;
  title: string;
  category: FindingCategory;
  severity: FindingSeverity;
  cwe: string;
  endpoint: string;
  method?: RestMethod;
  resource: string;
  rationale: string;
  impact: string;
  mitigation: string;
  /** Required at the agent boundary; optional here for backwards-compatible imported reports. */
  impactLevel?: ImpactLevel;
  reproduction: ReproductionRequest[];
  proof: ProofPredicate;
}

export interface Finding extends FindingInput {
  fingerprint: string;
}

export interface FindingValidation {
  fingerprint: string;
  status: "confirmed" | "rejected";
  evidence: string;
  proof: ProofResult;
  observations: ValidationObservation[];
  artifacts?: ProofArtifacts;
  reproduction?: ReproductionRequest[];
  replayedProof?: ProofPredicate;
  reviewer: {
    assessment: "supported" | "unsupported";
    evidence: string;
  };
}

export interface ExploitChainLink {
  from: JsonEvidenceSelector & { fingerprint: string };
  to: {
    fingerprint: string;
    requestIndex: number;
    location: "query" | "json-body" | "header";
    parameter: string;
  };
}

export interface ExploitChainInput {
  agentId: string;
  title: string;
  impactLevel: ImpactLevel;
  steps: string[];
  links: ExploitChainLink[];
}

export interface ExploitChain extends ExploitChainInput {
  fingerprint: string;
}

export interface ExploitChainValidation {
  fingerprint: string;
  status: "confirmed" | "rejected";
  summary: string;
  checks: ProofCheck[];
}

export interface ProofCheck {
  description: string;
  passed: boolean;
  actual?: unknown;
}

export interface ProofResult {
  predicate: ProofPredicate["type"];
  passed: boolean;
  summary: string;
  checks: ProofCheck[];
}

export interface ValidationObservation {
  method?: RestMethod;
  status: number;
  path: string;
  actorId: ActorId;
  body: unknown;
  truncated: boolean;
  durationMs?: number;
  sampleId?: string;
}

export interface CampaignBudget {
  total: number;
  exploration: number;
  validation: number;
}

export interface TestedRequest {
  agentId: string;
  path: string;
  method?: RestMethod;
  actorId: ActorId;
  status: number;
}

export interface DiscoveredOperation {
  method: string;
  path: string;
}

export interface CampaignState {
  target: string;
  phase: "starting" | "exploring" | "validating" | "complete" | "failed";
  budget: CampaignBudget;
  requests: { total: number; exploration: number; validation: number };
  agents: CampaignAgent[];
  testedRequests: TestedRequest[];
  discoveredRoutes: string[];
  discoveredOperations: DiscoveredOperation[];
  findings: Finding[];
  validations: FindingValidation[];
  coordination: CoordinatorSnapshot;
  exploitChains: ExploitChain[];
  exploitChainValidations: ExploitChainValidation[];
  error?: string;
}

export function createCampaignBudget(total: number): CampaignBudget {
  if (!Number.isInteger(total) || total < 3) {
    throw new Error("Campaign request budget must be an integer of at least 3");
  }
  const validation = Math.ceil(total / 3);
  return { total, exploration: total - validation, validation };
}

export type CampaignAction =
  | { type: "phase"; phase: CampaignState["phase"] }
  | { type: "agent"; id: string; status: AgentStatus; summary?: string }
  | { type: "agent-spawned"; id: string; role: CampaignAgent["role"] }
  | { type: "coordinator-snapshot"; snapshot: CoordinatorSnapshot }
  | { type: "request"; phase: "exploration" | "validation" }
  | { type: "reclaim-exploration-budget" }
  | { type: "request-tested"; request: TestedRequest }
  | { type: "routes-discovered"; routes: string[] }
  | { type: "operations-discovered"; operations: DiscoveredOperation[] }
  | { type: "finding"; finding: FindingInput }
  | { type: "validation"; validation: FindingValidation }
  | { type: "exploit-chain"; chain: ExploitChainInput }
  | { type: "exploit-chain-validation"; validation: ExploitChainValidation }
  | { type: "failed"; error: string };

const nextPhases: Record<CampaignState["phase"], CampaignState["phase"][]> = {
  starting: ["exploring", "failed"],
  exploring: ["validating", "failed"],
  validating: ["complete", "failed"],
  complete: [],
  failed: [],
};

export function createCampaignState(
  target: string,
  budget: CampaignBudget,
  explorerCount = 2,
): CampaignState {
  if (budget.exploration + budget.validation !== budget.total) {
    throw new Error("Exploration and validation budgets must equal the total budget");
  }
  return {
    target,
    phase: "starting",
    budget,
    requests: { total: 0, exploration: 0, validation: 0 },
    agents: [
      ...Array.from({ length: explorerCount }, (_, index): CampaignAgent => ({
        id: `explorer-${index + 1}`,
        role: "explorer",
        status: "queued",
      })),
      { id: "validator", role: "validator", status: "queued" },
    ],
    testedRequests: [],
    discoveredRoutes: [],
    discoveredOperations: [],
    findings: [],
    validations: [],
    coordination: emptyCoordinatorSnapshot(budget.exploration),
    exploitChains: [],
    exploitChainValidations: [],
  };
}

export function reduceCampaign(state: CampaignState, action: CampaignAction): CampaignState {
  if (state.phase === "complete" || state.phase === "failed") return state;

  switch (action.type) {
    case "phase":
      return action.phase !== state.phase && nextPhases[state.phase].includes(action.phase)
        ? { ...state, phase: action.phase }
        : state;
    case "request":
      return {
        ...state,
        requests: {
          total: state.requests.total + 1,
          exploration: state.requests.exploration + (action.phase === "exploration" ? 1 : 0),
          validation: state.requests.validation + (action.phase === "validation" ? 1 : 0),
        },
      };
    case "reclaim-exploration-budget": {
      const unused = Math.max(0, state.budget.exploration - state.requests.exploration);
      return unused === 0
        ? state
        : {
            ...state,
            budget: {
              total: state.budget.total,
              exploration: state.budget.exploration - unused,
              validation: state.budget.validation + unused,
            },
          };
    }
    case "agent":
      return {
        ...state,
        agents: state.agents.map((agent) =>
          agent.id === action.id
            ? { ...agent, status: action.status, summary: action.summary ?? agent.summary }
            : agent,
        ),
      };
    case "agent-spawned":
      return state.agents.some(({ id }) => id === action.id)
        ? state
        : {
            ...state,
            agents: [...state.agents, { id: action.id, role: action.role, status: "queued" }],
          };
    case "coordinator-snapshot":
      return { ...state, coordination: action.snapshot };
    case "request-tested":
      return {
        ...state,
        testedRequests: [...state.testedRequests, action.request],
      };
    case "routes-discovered":
      return {
        ...state,
        discoveredRoutes: [...new Set([...state.discoveredRoutes, ...action.routes])],
      };
    case "operations-discovered": {
      const operations = new Map(
        [...state.discoveredOperations, ...action.operations].map((operation) => [
          operationKey(operation),
          operation,
        ]),
      );
      return { ...state, discoveredOperations: [...operations.values()] };
    }
    case "finding": {
      const normalized = normalizeFindingInput(action.finding);
      const finding = { ...normalized, fingerprint: fingerprintFinding(normalized) };
      return state.findings.some((existing) => existing.fingerprint === finding.fingerprint)
        ? state
        : { ...state, findings: [...state.findings, finding] };
    }
    case "validation":
      return state.validations.some(
        (validation) => validation.fingerprint === action.validation.fingerprint,
      )
        ? state
        : { ...state, validations: [...state.validations, action.validation] };
    case "exploit-chain": {
      const chain = { ...action.chain, fingerprint: fingerprintExploitChain(action.chain) };
      return state.exploitChains.some((existing) => existing.fingerprint === chain.fingerprint)
        ? state
        : { ...state, exploitChains: [...state.exploitChains, chain] };
    }
    case "exploit-chain-validation":
      return state.exploitChainValidations.some(
        (validation) => validation.fingerprint === action.validation.fingerprint,
      )
        ? state
        : {
            ...state,
            exploitChainValidations: [...state.exploitChainValidations, action.validation],
          };
    case "failed":
      return { ...state, phase: "failed", error: action.error };
  }
}

function emptyCoordinatorSnapshot(requestBudget: number): CoordinatorSnapshot {
  return {
    revision: 0,
    coverage: {
      discoveredOperations: 0,
      testedOperations: 0,
      operationCoverage: 0,
      testedAccessModes: 0,
      totalAccessModes: 0,
      accessModeCoverage: 0,
    },
    hypotheses: [],
    debriefs: [],
    specialists: [],
    validationQueue: [],
    budget: {
      total: requestBudget,
      consumed: 0,
      allocated: 0,
      available: requestBudget,
      workers: {},
    },
  };
}

export function fingerprintExploitChain(chain: Pick<ExploitChainInput, "steps">): string {
  return `exploit-chain:${chain.steps.map((step) => `${step.length}:${step}`).join("")}`;
}

export function fingerprintFinding(
  finding: Pick<FindingInput, "category" | "endpoint" | "method">,
): string {
  const method = finding.method ?? "GET";
  return `${finding.category}:${method}:${normalizeEndpoint(finding.endpoint)}`;
}

export function deriveImpactLevel(
  finding: Pick<FindingInput, "proof" | "reproduction">,
): ImpactLevel {
  if (
    finding.proof.type === "state-transition" ||
    finding.reproduction.some(({ method = "GET" }) => !["GET", "HEAD", "OPTIONS"].includes(method))
  ) {
    return "state-change";
  }
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

export function campaignOperationCoverage(state: CampaignState): {
  discovered: number;
  tested: number;
  coverage: number;
} {
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

/** @deprecated Use campaignOperationCoverage. */
export const campaignRouteCoverage = campaignOperationCoverage;

function operationKey(operation: Pick<DiscoveredOperation, "method" | "path">): string {
  return `${operation.method} ${normalizeEndpoint(operation.path)}`;
}
