import { normalizeEndpoint } from "./endpoint.ts";

export { normalizeEndpoint } from "./endpoint.ts";

export type AgentStatus = "queued" | "running" | "finished" | "failed";
export type FindingCategory =
  | "broken-object-authorization"
  | "broken-function-authorization"
  | "excessive-data-exposure"
  | "sensitive-data-exposure"
  | "security-misconfiguration"
  | "other";

export type FindingSeverity = "low" | "medium" | "high" | "critical";

export interface CampaignAgent {
  id: string;
  role: "explorer" | "validator";
  status: AgentStatus;
  summary?: string;
}

export interface ReproductionRequest {
  path: string;
  authenticated: boolean;
}

export interface JsonEvidenceSelector {
  requestIndex: number;
  jsonPointer: string;
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
    };

export interface FindingInput {
  agentId: string;
  title: string;
  category: FindingCategory;
  severity: FindingSeverity;
  cwe: string;
  endpoint: string;
  resource: string;
  rationale: string;
  impact: string;
  mitigation: string;
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
  reviewer: {
    assessment: "supported" | "unsupported";
    evidence: string;
  };
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
  status: number;
  path: string;
  authenticated: boolean;
  body: unknown;
  truncated: boolean;
}

export interface CampaignBudget {
  total: number;
  exploration: number;
  validation: number;
}

export interface TestedRequest {
  agentId: string;
  path: string;
  authenticated: boolean;
  status: number;
}

export interface CampaignState {
  target: string;
  phase: "starting" | "exploring" | "validating" | "complete" | "failed";
  budget: CampaignBudget;
  requests: { total: number; exploration: number; validation: number };
  agents: CampaignAgent[];
  testedRequests: TestedRequest[];
  discoveredRoutes: string[];
  findings: Finding[];
  validations: FindingValidation[];
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
  | { type: "request"; phase: "exploration" | "validation" }
  | { type: "reclaim-exploration-budget" }
  | { type: "request-tested"; request: TestedRequest }
  | { type: "routes-discovered"; routes: string[] }
  | { type: "finding"; finding: FindingInput }
  | { type: "validation"; validation: FindingValidation }
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
    findings: [],
    validations: [],
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
    case "finding": {
      const finding = { ...action.finding, fingerprint: fingerprintFinding(action.finding) };
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
    case "failed":
      return { ...state, phase: "failed", error: action.error };
  }
}

export function fingerprintFinding(finding: Pick<FindingInput, "category" | "endpoint">): string {
  return `${finding.category}:GET:${normalizeEndpoint(finding.endpoint)}`;
}

export function campaignRouteCoverage(state: CampaignState): {
  discovered: number;
  tested: number;
  coverage: number;
} {
  const discovered = new Set(state.discoveredRoutes.map(normalizeEndpoint));
  const tested = new Set(
    state.testedRequests
      .map(({ path }) => normalizeEndpoint(path))
      .filter((path) => discovered.has(path)),
  ).size;
  return {
    discovered: discovered.size,
    tested,
    coverage: discovered.size === 0 ? 0 : tested / discovered.size,
  };
}
