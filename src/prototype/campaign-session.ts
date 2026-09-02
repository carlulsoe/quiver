import type { ConversationStreamChunk, PromptUsage } from "@flue/runtime";
import {
  addPromptUsage,
  emptyPromptUsage,
  type MissionUsage,
  type RunEvent,
} from "./campaign-history.ts";
import { assertCampaignIdentity, createCampaignIdentity } from "./campaign-identity.ts";
import { InMemoryCampaignStore, type CampaignStore } from "./campaign-store.ts";
import type { ModelRoute, RoutedModel } from "./model-routing.ts";
import { redactCredentials } from "./security/redaction.ts";
import {
  createCampaignBudget,
  createCampaignState,
  type CampaignAction,
  type CampaignState,
} from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";

export interface CampaignSessionOptions {
  target: URL;
  profile: TargetProfile;
  requestBudget: number;
  explorerCount: number;
  openApi?: unknown;
  context?: string;
  campaignId?: string;
  campaignStore?: CampaignStore;
  onState?: (state: CampaignState, action?: CampaignAction) => void;
}

/** Owns durable campaign state and its cumulative reporting history. */
export class CampaignSession {
  readonly campaignId: string;
  readonly events: RunEvent[];
  readonly usage: PromptUsage;
  readonly missionUsage: MissionUsage[];
  #state: CampaignState;
  #startedAt = performance.now();
  #historyBaseMs: number;
  #store: CampaignStore;
  #onState: CampaignSessionOptions["onState"];

  constructor(options: CampaignSessionOptions) {
    this.campaignId = options.campaignId ?? options.profile.id;
    this.#onState = options.onState;
    const identity = createCampaignIdentity({
      target: options.target,
      profile: options.profile,
      requestBudget: options.requestBudget,
      explorerCount: options.explorerCount,
      openApi: options.openApi,
      context: options.context,
    });
    const initialState = () =>
      createCampaignState(
        `${options.target.origin}${options.target.pathname}${options.target.search}`,
        createCampaignBudget(options.requestBudget),
        options.explorerCount,
        identity,
      );
    this.#store = options.campaignStore ?? new InMemoryCampaignStore();
    let resuming = true;
    try {
      this.#state = this.#store.load(this.campaignId);
    } catch (error) {
      if (!(error instanceof Error) || error.message !== `Unknown campaign ${this.campaignId}`) {
        throw error;
      }
      resuming = false;
      this.#state = this.#store.create(this.campaignId, initialState());
    }
    assertCampaignTarget(this.#state, this.campaignId, options.target);
    assertCampaignIdentity(this.#state.identity, identity, this.campaignId, resuming);
    this.#historyBaseMs = this.#state.history.durationMs;
    this.events = structuredClone(this.#state.history.events);
    this.usage = structuredClone(this.#state.history.usage);
    this.missionUsage = structuredClone(this.#state.history.missionUsage);
  }

  get state(): CampaignState {
    return this.#state;
  }

  checkpoint(): CampaignState {
    return this.#store.checkpoint();
  }

  recover(): void {
    if (
      this.#state.agents.some(({ status }) => status === "running") ||
      this.#state.runtime.jobs.some(({ status }) => status === "running")
    ) {
      this.dispatch({ type: "recover" });
    }
    if (this.#state.phase !== "complete" && this.#state.phase !== "failed") {
      while (this.#state.requests.exploration < this.#state.coordination.budget.consumed) {
        this.dispatch({ type: "request", phase: "exploration" });
      }
    }
    this.#onState?.(this.#state);
  }

  dispatch(action: CampaignAction): void {
    this.#store.apply(action);
    this.#state = this.#store.checkpoint();
    this.record("state", {
      action: action.type,
      phase: this.#state.phase,
      requestsUsed: this.#state.requests.total,
      testedRequestCount: this.#state.testedRequests.length,
      findingCount: this.#state.findings.length,
      validationCount: this.#state.validations.length,
      exploitChainCount: this.#state.exploitChains.length,
    });
    this.#onState?.(this.#state, action);
  }

  record(type: RunEvent["type"], data: Record<string, unknown>): void {
    const event: RunEvent = {
      sequence: (this.events.at(-1)?.sequence ?? 0) + 1,
      elapsedMs: this.elapsedMs(),
      type,
      data: redactCredentials(data),
    };
    this.events.push(event);
    this.applyHistory({ type: "run-event", event });
  }

  captureAgentEvent(agentId: string, chunk: ConversationStreamChunk): void {
    if (chunk.type === "tool-input") {
      this.record("tool-call", {
        agentId,
        toolCallId: chunk.toolCallId,
        toolName: chunk.toolName,
        input: durableToolInput(chunk.input),
      });
    } else if (chunk.type === "tool-output") {
      this.record("tool-output", {
        agentId,
        toolCallId: chunk.toolCallId,
        output: "[tool output omitted from durable history]",
        durationMs: chunk.durationMs,
      });
    } else if (chunk.type === "tool-output-error") {
      this.record("tool-error", {
        agentId,
        toolCallId: chunk.toolCallId,
        error: "[tool error detail omitted from durable history]",
        durationMs: chunk.durationMs,
      });
    }
  }

  beginMission(missionId: string, role: MissionUsage["role"], route: ModelRoute): MissionUsage {
    const mission: MissionUsage = {
      missionId,
      role,
      requirements: {
        ...route.requirements,
        capabilities: [...route.requirements.capabilities],
      },
      attemptedModels: [],
      usage: emptyPromptUsage(),
    };
    this.missionUsage.push(mission);
    this.applyHistory({ type: "mission-started", mission });
    return mission;
  }

  recordModelAttempt(mission: MissionUsage, model: RoutedModel): void {
    mission.attemptedModels.push(model.model);
    this.syncMission(mission);
    this.record("model-route", {
      missionId: mission.missionId,
      role: mission.role,
      model: model.model,
      attempt: mission.attemptedModels.length,
      requirements: mission.requirements,
    });
  }

  captureUsage(metadata: Record<string, unknown> | undefined, mission: MissionUsage): void {
    const value = metadata?.quiverUsage;
    if (!isPromptUsage(value)) return;
    addPromptUsage(this.usage, value);
    addPromptUsage(mission.usage, value);
    if (typeof metadata?.quiverModel === "string") mission.model = metadata.quiverModel;
    this.syncMission(mission);
  }

  finishHistory(): void {
    this.applyHistory({ type: "history-elapsed", durationMs: this.elapsedMs() });
  }

  private elapsedMs(): number {
    return this.#historyBaseMs + Math.round(performance.now() - this.#startedAt);
  }

  private syncMission(mission: MissionUsage): void {
    const index = this.missionUsage.indexOf(mission);
    if (index >= 0) this.applyHistory({ type: "mission-updated", index, mission });
  }

  private applyHistory(action: CampaignAction): void {
    this.#store.apply(action);
    this.#state = this.#store.checkpoint();
  }
}

function durableToolInput(input: unknown): unknown {
  return input !== null && typeof input === "object"
    ? redactCredentials(input)
    : "[tool input omitted from durable history]";
}

function assertCampaignTarget(state: CampaignState, campaignId: string, target: URL): void {
  const expectedTarget = `${target.origin}${target.pathname}${target.search}`;
  if (state.target !== expectedTarget) {
    throw new Error(`Campaign ${campaignId} targets ${state.target}, not ${expectedTarget}`);
  }
}

function isPromptUsage(value: unknown): value is PromptUsage {
  if (!value || typeof value !== "object") return false;
  const usage = value as Partial<PromptUsage>;
  return (
    typeof usage.input === "number" &&
    typeof usage.output === "number" &&
    typeof usage.cacheRead === "number" &&
    typeof usage.cacheWrite === "number" &&
    typeof usage.totalTokens === "number" &&
    !!usage.cost &&
    typeof usage.cost.input === "number" &&
    typeof usage.cost.output === "number" &&
    typeof usage.cost.cacheRead === "number" &&
    typeof usage.cost.cacheWrite === "number" &&
    typeof usage.cost.total === "number"
  );
}
