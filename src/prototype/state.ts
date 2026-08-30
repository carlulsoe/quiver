export type AgentStatus = "queued" | "running" | "finished" | "failed";

export interface PrototypeAgent {
  id: string;
  role: "explorer" | "validator";
  status: AgentStatus;
  summary?: string;
}

export interface Candidate {
  agentId: string;
  vehicleId: string;
  sourcePath: string;
  locationPath: string;
  rationale: string;
}

export interface Validation {
  status: "confirmed" | "rejected";
  vehicleId: string;
  evidence: string;
}

export interface PrototypeState {
  target: string;
  phase: "starting" | "exploring" | "validating" | "complete" | "failed";
  requestBudget: number;
  requestsUsed: number;
  agents: PrototypeAgent[];
  candidates: Candidate[];
  validation?: Validation;
  error?: string;
}

export type PrototypeAction =
  | { type: "phase"; phase: PrototypeState["phase"] }
  | { type: "agent"; id: string; status: AgentStatus; summary?: string }
  | { type: "request" }
  | { type: "candidate"; candidate: Candidate }
  | { type: "validated"; validation: Validation }
  | { type: "failed"; error: string };

export function createState(
  target: string,
  requestBudget: number,
  explorerCount = 2,
): PrototypeState {
  return {
    target,
    phase: "starting",
    requestBudget,
    requestsUsed: 0,
    agents: [
      ...Array.from({ length: explorerCount }, (_, index): PrototypeAgent => ({
        id: `explorer-${index + 1}`,
        role: "explorer",
        status: "queued",
      })),
      { id: "validator", role: "validator", status: "queued" },
    ],
    candidates: [],
  };
}

export function reduce(state: PrototypeState, action: PrototypeAction): PrototypeState {
  switch (action.type) {
    case "phase":
      return { ...state, phase: action.phase };
    case "request":
      return { ...state, requestsUsed: state.requestsUsed + 1 };
    case "agent":
      return {
        ...state,
        agents: state.agents.map((agent) =>
          agent.id === action.id
            ? { ...agent, status: action.status, summary: action.summary ?? agent.summary }
            : agent,
        ),
      };
    case "candidate":
      return {
        ...state,
        candidates: state.candidates.some(
          (candidate) => candidate.vehicleId === action.candidate.vehicleId,
        )
          ? state.candidates
          : [...state.candidates, action.candidate],
      };
    case "validated":
      return { ...state, validation: action.validation };
    case "failed":
      return { ...state, phase: "failed", error: action.error };
  }
}
