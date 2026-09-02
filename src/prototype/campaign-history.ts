import type { PromptUsage } from "@flue/runtime";
import type { MissionRequirements } from "./model-routing.ts";

export interface MissionUsage {
  missionId: string;
  role: "explorer" | "specialist" | "validator";
  requirements: MissionRequirements;
  attemptedModels: string[];
  model?: string;
  usage: PromptUsage;
}

export interface RunEvent {
  sequence: number;
  elapsedMs: number;
  type: "state" | "request" | "model-route" | "tool-call" | "tool-output" | "tool-error";
  data: RunEventData;
}

export interface RunEventData {
  action?: string;
  phase?: string;
  agentId?: string;
  requestsUsed?: number;
  testedRequestCount?: number;
  findingCount?: number;
  validationCount?: number;
  exploitChainCount?: number;
  toolCallId?: string;
  toolName?: string;
  input?: object | string;
  output?: string;
  error?: string;
  durationMs?: number;
  missionId?: string;
  role?: string;
  model?: string;
  attempt?: number;
  requirements?: MissionRequirements;
  path?: string;
  author?: string;
  method?: string;
}

export interface CampaignHistory {
  durationMs: number;
  usage: PromptUsage;
  missionUsage: MissionUsage[];
  events: RunEvent[];
}

export function emptyPromptUsage(): PromptUsage {
  return {
    input: 0,
    output: 0,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens: 0,
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
  };
}

export function emptyCampaignHistory(): CampaignHistory {
  return { durationMs: 0, usage: emptyPromptUsage(), missionUsage: [], events: [] };
}

export function aggregateMissionUsage(missions: readonly MissionUsage[]): PromptUsage {
  const total = emptyPromptUsage();
  for (const mission of missions) addPromptUsage(total, mission.usage);
  return total;
}

export function addPromptUsage(total: PromptUsage, value: PromptUsage): void {
  total.input += value.input;
  total.output += value.output;
  total.cacheRead += value.cacheRead;
  total.cacheWrite += value.cacheWrite;
  total.totalTokens += value.totalTokens;
  total.cost.input += value.cost.input;
  total.cost.output += value.cost.output;
  total.cost.cacheRead += value.cost.cacheRead;
  total.cost.cacheWrite += value.cost.cacheWrite;
  total.cost.total += value.cost.total;
}
