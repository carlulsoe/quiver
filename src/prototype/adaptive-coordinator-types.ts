import type { ActorId } from "./sessions.ts";
import type { DiscoveredOperation, Finding, FindingValidation, TestedRequest } from "./state.ts";

export type SpecialistKind =
  | "authorization"
  | "authentication"
  | "data-exposure"
  | "request-semantics";

export type HypothesisStatus = "queued" | "testing" | "supported" | "rejected";

export interface CoordinatedTask {
  route: string;
  method: string;
  actorId: ActorId;
  source: "uncovered-surface" | "incoming-evidence" | "worker-hypothesis";
  reason: string;
  hypothesisId?: string;
}

export interface CoordinatorHypothesis {
  id: string;
  title: string;
  method: string;
  route: string;
  specialty: SpecialistKind;
  status: HypothesisStatus;
  confidence: number;
  rationale: string;
  nextStep: string;
  proposedBy: string;
  assignedAgentId?: string;
  evidenceSignals: string[];
}

export interface HypothesisInput {
  title: string;
  method?: string;
  route: string;
  specialty: SpecialistKind;
  confidence: number;
  rationale: string;
  nextStep: string;
}

export interface WorkerDebriefInput {
  summary: string;
  exhausted: boolean;
  hypotheses?: readonly HypothesisInput[];
}

export interface WorkerDebrief extends WorkerDebriefInput {
  agentId: string;
  hypotheses: HypothesisInput[];
}

export interface WorkerBudget {
  allocated: number;
  used: number;
  remaining: number;
}

export interface WorkAssignment {
  agentId: string;
  tasks: CoordinatedTask[];
  uncoveredRouteCount: number;
  evidenceSignals: string[];
  hypotheses: CoordinatorHypothesis[];
  specialty?: SpecialistKind;
  budget: WorkerBudget;
}

export interface SpecialistPlan {
  agentId: string;
  specialty: SpecialistKind;
  focus: string;
  hypothesisIds: string[];
  requestBudget: number;
}

export interface CoordinatorCoverage {
  discoveredOperations: number;
  testedOperations: number;
  operationCoverage: number;
  testedAccessModes: number;
  totalAccessModes: number;
  accessModeCoverage: number;
}

export interface CoordinatorBudget {
  total: number | null;
  consumed: number;
  allocated: number;
  available: number | null;
  workers: Record<string, WorkerBudget>;
}

export interface ValidationQueueItem {
  fingerprint: string;
  status: "queued" | "validating" | "complete";
  validatorId?: string;
  outcome?: "confirmed" | "rejected";
}

export interface CoordinatorSnapshot {
  revision: number;
  coverage: CoordinatorCoverage;
  hypotheses: CoordinatorHypothesis[];
  debriefs: WorkerDebrief[];
  specialists: SpecialistPlan[];
  validationQueue: ValidationQueueItem[];
  budget: CoordinatorBudget;
}

export interface AdaptiveCoordinatorOptions {
  actorIds?: readonly ActorId[];
  requestBudget?: number;
  expectedWorkers?: number;
  onChange?: (snapshot: CoordinatorSnapshot) => void;
  restore?: {
    snapshot: CoordinatorSnapshot;
    operations: readonly DiscoveredOperation[];
    testedRequests: readonly TestedRequest[];
    findings: readonly Finding[];
    validations: readonly FindingValidation[];
    explorationRequests: number;
  };
}

export interface Candidate extends CoordinatedTask {
  key: string;
  priority: number;
}

export interface MutableWorkerBudget {
  allocated: number;
  used: number;
}
