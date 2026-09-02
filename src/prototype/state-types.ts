import type { CoordinatorSnapshot } from "./adaptive-coordinator.ts";
import type { CampaignHistory } from "./campaign-history.ts";
import type { RestMethod } from "./scoped-target.ts";
import type { ActorId } from "./sessions.ts";
import type {
  ProofArtifacts,
  ProofCheck,
  ProofPredicate,
  ProofResult,
  ValidationObservation,
} from "./state-proof-types.ts";

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
  sampleId?: string;
}
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
  reviewer: { assessment: "supported" | "unsupported"; evidence: string };
}
export interface ExploitChainLink {
  from: import("./state-proof-types.ts").JsonEvidenceSelector & { fingerprint: string };
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
export type CampaignControlStatus = "running" | "paused" | "cancelled" | "halted";
export type CampaignJobStatus = "queued" | "running" | "completed" | "failed" | "interrupted";
export interface CampaignJob {
  id: string;
  kind: "validation" | "exploit-chain";
  fingerprint: string;
  impactLevel: ImpactLevel;
  status: CampaignJobStatus;
  attempts: number;
  mutationStarted: boolean;
  error?: string;
}
export interface CampaignRuntimeState {
  control: CampaignControlStatus;
  controlReason?: string;
  consecutiveFailures: number;
  disruptiveResponses: number;
  jobs: CampaignJob[];
}
export interface CampaignIdentity {
  schemaVersion: 2;
  profileId: string;
  configurationFingerprint: string;
  resumable: boolean;
}
export interface CampaignState {
  target: string;
  identity?: CampaignIdentity;
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
  runtime: CampaignRuntimeState;
  history: CampaignHistory;
  error?: string;
}
