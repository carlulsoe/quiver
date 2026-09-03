import type { ConversationStreamChunk, PromptUsage } from "@flue/runtime";
import {
  addPromptUsage,
  emptyPromptUsage,
  type MissionUsage,
  type RunEvent,
  type RunEventData,
} from "./campaign-history.ts";
import { assertCampaignIdentity, createCampaignIdentity } from "./campaign-identity.ts";
import type { CampaignSessionOptions } from "./campaign-session-options.ts";
import { synchronizeCampaignControl } from "./campaign-control-snapshot.ts";
import { InMemoryCampaignStore, type CampaignStore } from "./campaign-store.ts";
import type { ModelRoute, RoutedModel } from "./model-routing.ts";
import {
  createCampaignBudget,
  createCampaignState,
  reduceCampaign,
  type CampaignAction,
  type CampaignControlStatus,
  type CampaignState,
} from "./state.ts";
import {
  agentStreamEvent,
  assertCampaignTarget,
  createRunEvent,
  parsePromptMetadata,
} from "./campaign-session-support.ts";

export type { CampaignSessionOptions } from "./campaign-session-options.ts";

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
    this.#state = synchronizeCampaignControl(this.#state, this.#store.controlSnapshot());
    return this.#state;
  }

  checkpoint(): CampaignState {
    return this.#store.checkpoint();
  }

  controlStatus(): CampaignControlStatus {
    return this.#store.controlStatus();
  }

  recover(): void {
    this.#state = synchronizeCampaignControl(this.#state, this.#store.controlSnapshot());
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
    this.#state = synchronizeCampaignControl(this.#state, this.#store.controlSnapshot());
    const next = reduceCampaign(this.#state, action);
    const event = createRunEvent(this.events.at(-1)?.sequence ?? 0, this.elapsedMs(), "state", {
      action: action.type,
      phase: next.phase,
      requestsUsed: next.requests.total,
      testedRequestCount: next.testedRequests.length,
      findingCount: next.findings.length,
      validationCount: next.validations.length,
      exploitChainCount: next.exploitChains.length,
    });
    const historyAction = { type: "run-event", event } as const;
    const result = this.#store.applyBatch([action, historyAction]);
    this.#state = reduceCampaign(next, historyAction);
    this.#state = synchronizeCampaignControl(this.#state, result);
    this.events.push(event);
    this.#onState?.(this.#state, action);
  }

  record(type: RunEvent["type"], data: RunEventData): void {
    this.#state = synchronizeCampaignControl(this.#state, this.#store.controlSnapshot());
    const event = createRunEvent(this.events.at(-1)?.sequence ?? 0, this.elapsedMs(), type, data);
    const action = { type: "run-event", event } as const;
    const result = this.#store.apply(action);
    this.#state = reduceCampaign(this.#state, action);
    this.#state = synchronizeCampaignControl(this.#state, result);
    this.events.push(event);
  }

  captureAgentEvent(agentId: string, chunk: ConversationStreamChunk): void {
    const event = agentStreamEvent(agentId, chunk);
    if (event) this.record(event.type, event.data);
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

  captureUsage<Metadata>(metadata: Metadata, mission: MissionUsage): void {
    const parsed = parsePromptMetadata(metadata);
    if (!parsed) return;
    addPromptUsage(this.usage, parsed.quiverUsage);
    addPromptUsage(mission.usage, parsed.quiverUsage);
    if (parsed.quiverModel) mission.model = parsed.quiverModel;
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
    this.#state = synchronizeCampaignControl(this.#state, this.#store.controlSnapshot());
    const result = this.#store.apply(action);
    this.#state = reduceCampaign(this.#state, action);
    this.#state = synchronizeCampaignControl(this.#state, result);
  }
}
