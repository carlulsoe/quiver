import type { CoordinatorSnapshot } from "./adaptive-coordinator.ts";
import type { MissionUsage, RunEvent } from "./campaign-history.ts";
import type {
  AgentStatus,
  CampaignAgent,
  CampaignState,
  DiscoveredOperation,
  ExploitChainInput,
  ExploitChainValidation,
  FindingInput,
  FindingValidation,
  TestedRequest,
} from "./state-types.ts";

export type CampaignReducerAction =
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

export type RuntimeReducerAction =
  | { type: "pause"; reason?: string }
  | { type: "resume" }
  | { type: "cancel"; reason?: string }
  | { type: "halt"; reason: string }
  | { type: "recover" }
  | { type: "job-started"; id: string }
  | { type: "job-mutation-started"; id: string }
  | { type: "job-failed"; id: string; error: string; retryable: boolean }
  | { type: "runtime-success" }
  | { type: "runtime-failure"; disruptive?: boolean }
  | { type: "run-event"; event: RunEvent }
  | { type: "mission-started"; mission: MissionUsage }
  | { type: "mission-updated"; index: number; mission: MissionUsage }
  | { type: "history-elapsed"; durationMs: number };

export type CampaignAction = CampaignReducerAction | RuntimeReducerAction;

type CampaignActionOwnerTable = {
  [Type in CampaignAction["type"]]: Extract<RuntimeReducerAction, { type: Type }> extends never
    ? "campaign"
    : "runtime";
};

export const campaignActionOwners = {
  phase: "campaign",
  agent: "campaign",
  "agent-spawned": "campaign",
  "coordinator-snapshot": "campaign",
  request: "campaign",
  "reclaim-exploration-budget": "campaign",
  "request-tested": "campaign",
  "routes-discovered": "campaign",
  "operations-discovered": "campaign",
  finding: "campaign",
  validation: "campaign",
  "exploit-chain": "campaign",
  "exploit-chain-validation": "campaign",
  failed: "campaign",
  pause: "runtime",
  resume: "runtime",
  cancel: "runtime",
  halt: "runtime",
  recover: "runtime",
  "job-started": "runtime",
  "job-mutation-started": "runtime",
  "job-failed": "runtime",
  "runtime-success": "runtime",
  "runtime-failure": "runtime",
  "run-event": "runtime",
  "mission-started": "runtime",
  "mission-updated": "runtime",
  "history-elapsed": "runtime",
} as const satisfies CampaignActionOwnerTable;

export function isRuntimeReducerAction(action: CampaignAction): action is RuntimeReducerAction {
  return campaignActionOwners[action.type] === "runtime";
}
