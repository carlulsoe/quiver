import { closeSync } from "node:fs";
import { resolve } from "node:path";
import {
  snapshotCampaignControl,
  type CampaignControlSnapshot,
} from "./campaign-control-snapshot.ts";
import { replayCampaignLog, type DurableCampaign } from "./campaign-store-replay.ts";
import { assertCampaignId, type CampaignStore } from "./campaign-store.ts";
import type {
  CampaignStoreStatistics,
  JsonlCampaignStoreOptions,
} from "./campaign-store-jsonl-types.ts";
import {
  acquireLogLock,
  appendDurably,
  createStateRecord,
  isCheckpointBoundary,
  openDurableLog,
  type DurableAppend,
  type JsonlRecord,
  type JsonlStateRecord,
} from "./campaign-store-log.ts";
import {
  reduceCampaign,
  withRuntimeState,
  type CampaignAction,
  type CampaignControlStatus,
  type CampaignState,
} from "./state.ts";

export const DEFAULT_CHECKPOINT_ACTION_INTERVAL = 32;

export type {
  CampaignStoreStatistics,
  JsonlCampaignStoreOptions,
} from "./campaign-store-jsonl-types.ts";

export class JsonlCampaignStore implements CampaignStore {
  readonly path: string;
  readonly #lockDescriptor: number;
  readonly #logDescriptor: number;
  readonly #campaigns: Map<string, DurableCampaign>;
  readonly #checkpointActionInterval: number;
  readonly #durableAppend: DurableAppend;
  readonly #statistics: CampaignStoreStatistics = {
    durableWrites: 0,
    records: 0,
    actionRecords: 0,
    checkpointRecords: 0,
    fullStateRecords: 0,
    bytes: 0,
  };
  #activeCampaignId?: string;
  #closed = false;
  constructor(
    path: string,
    campaigns: Iterable<readonly [string, CampaignState]> = [],
    options: JsonlCampaignStoreOptions = {},
  ) {
    this.path = resolve(path);
    this.#checkpointActionInterval =
      options.checkpointActionInterval ?? DEFAULT_CHECKPOINT_ACTION_INTERVAL;
    this.#durableAppend = options.durableAppend ?? appendDurably;
    if (
      !Number.isSafeInteger(this.#checkpointActionInterval) ||
      this.#checkpointActionInterval < 1
    ) {
      throw new Error("Checkpoint action interval must be a positive safe integer");
    }
    this.#lockDescriptor = acquireLogLock(`${this.path}.lock`);
    let logDescriptor: number | undefined;
    try {
      this.#campaigns = replayCampaignLog(this.path);
      logDescriptor = openDurableLog(this.path);
      this.#logDescriptor = logDescriptor;
      for (const [campaignId, state] of campaigns)
        if (!this.#campaigns.has(campaignId)) this.create(campaignId, state);
    } catch (error) {
      if (logDescriptor !== undefined) closeSync(logDescriptor);
      closeSync(this.#lockDescriptor);
      this.#closed = true;
      throw error;
    }
  }
  create(campaignId: string, state: CampaignState): CampaignState {
    this.#assertOpen();
    assertCampaignId(campaignId);
    if (this.#campaigns.has(campaignId)) throw new Error(`Campaign ${campaignId} already exists`);
    const durable: DurableCampaign = {
      state: structuredClone(withRuntimeState(state)),
      sequence: 0,
      actionsSinceCheckpoint: 0,
    };
    this.#appendState(campaignId, "created", durable);
    this.#campaigns.set(campaignId, durable);
    this.#activeCampaignId = campaignId;
    return structuredClone(durable.state);
  }
  load(campaignId: string): CampaignState {
    this.#assertOpen();
    const campaign = this.#campaigns.get(campaignId);
    if (!campaign) throw new Error(`Unknown campaign ${campaignId}`);
    this.#activeCampaignId = campaignId;
    return structuredClone(campaign.state);
  }
  apply(action: CampaignAction): CampaignControlSnapshot {
    return this.applyBatch([action]);
  }
  applyBatch(actions: readonly CampaignAction[]): CampaignControlSnapshot {
    this.#assertOpen();
    const [campaignId, campaign] = this.#requireActiveCampaign();
    if (actions.length === 0) return snapshotCampaignControl(campaign.state);
    let next = campaign.state;
    let sequence = campaign.sequence;
    let actionCount = campaign.actionsSinceCheckpoint;
    const records: JsonlRecord[] = [];
    for (const action of actions) {
      next = reduceCampaign(next, action);
      sequence += 1;
      records.push({ version: 1, campaignId, sequence, kind: "action", action });
      actionCount += 1;
      if (actionCount >= this.#checkpointActionInterval) {
        sequence += 1;
        records.push(createStateRecord(campaignId, sequence, "checkpoint", next));
        actionCount = 0;
      }
    }
    if (actionCount > 0 && actions.some(isCheckpointBoundary)) {
      sequence += 1;
      records.push(createStateRecord(campaignId, sequence, "checkpoint", next));
      actionCount = 0;
    }
    this.#append(records);
    campaign.state = next;
    campaign.sequence = sequence;
    campaign.actionsSinceCheckpoint = actionCount;
    return snapshotCampaignControl(next);
  }
  checkpoint(): CampaignState {
    this.#assertOpen();
    const [campaignId, campaign] = this.#requireActiveCampaign();
    if (campaign.actionsSinceCheckpoint > 0) this.#appendState(campaignId, "checkpoint", campaign);
    return structuredClone(campaign.state);
  }
  controlStatus(): CampaignControlStatus {
    this.#assertOpen();
    return this.#requireActiveCampaign()[1].state.runtime.control;
  }
  controlSnapshot(): CampaignControlSnapshot {
    this.#assertOpen();
    return snapshotCampaignControl(this.#requireActiveCampaign()[1].state);
  }
  statistics(): CampaignStoreStatistics {
    return { ...this.#statistics };
  }
  #appendState(
    campaignId: string,
    kind: JsonlStateRecord["kind"],
    campaign: DurableCampaign,
  ): void {
    const sequence = campaign.sequence + 1;
    this.#append([createStateRecord(campaignId, sequence, kind, campaign.state)]);
    campaign.sequence = sequence;
    campaign.actionsSinceCheckpoint = 0;
  }
  #append(records: readonly JsonlRecord[]): void {
    this.#statistics.bytes += this.#durableAppend(this.#logDescriptor, records);
    this.#statistics.durableWrites += 1;
    this.#statistics.records += records.length;
    this.#statistics.actionRecords += records.filter(({ kind }) => kind === "action").length;
    this.#statistics.checkpointRecords += records.filter(
      ({ kind }) => kind === "checkpoint",
    ).length;
    this.#statistics.fullStateRecords += records.filter(({ kind }) => kind !== "action").length;
  }
  #requireActiveCampaign(): [string, DurableCampaign] {
    if (!this.#activeCampaignId) throw new Error("Load a campaign before using the store");
    return [this.#activeCampaignId, this.#campaigns.get(this.#activeCampaignId)!];
  }
  close(): void {
    if (this.#closed) return;
    try {
      for (const [campaignId, campaign] of this.#campaigns) {
        if (campaign.actionsSinceCheckpoint > 0) {
          this.#appendState(campaignId, "checkpoint", campaign);
        }
      }
    } finally {
      this.#closed = true;
      closeSync(this.#logDescriptor);
      closeSync(this.#lockDescriptor);
    }
  }
  [Symbol.dispose](): void {
    this.close();
  }
  #assertOpen(): void {
    if (this.#closed) throw new Error("Campaign store is closed");
  }
}
