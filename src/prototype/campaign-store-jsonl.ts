import { closeSync, existsSync, readFileSync, truncateSync } from "node:fs";
import { resolve } from "node:path";
import { assertCampaignId, type CampaignStore } from "./campaign-store.ts";
import {
  acquireLogLock,
  appendDurably,
  assertRecord,
  assertStateChecksum,
  checksumState,
  type JsonlActionRecord,
  type JsonlRecord,
  type JsonlStateRecord,
} from "./campaign-store-log.ts";
import {
  reduceCampaign,
  withRuntimeState,
  type CampaignAction,
  type CampaignState,
} from "./state.ts";

interface DurableCampaign {
  state: CampaignState;
  sequence: number;
  dirty: boolean;
}

export class JsonlCampaignStore implements CampaignStore {
  readonly path: string;
  readonly #lockDescriptor: number;
  readonly #campaigns = new Map<string, DurableCampaign>();
  #activeCampaignId?: string;
  #closed = false;
  constructor(path: string, campaigns: Iterable<readonly [string, CampaignState]> = []) {
    this.path = resolve(path);
    this.#lockDescriptor = acquireLogLock(`${this.path}.lock`);
    try {
      this.#replay();
      for (const [campaignId, state] of campaigns)
        if (!this.#campaigns.has(campaignId)) this.create(campaignId, state);
    } catch (error) {
      this.close();
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
      dirty: false,
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
  apply(action: CampaignAction): void {
    this.#assertOpen();
    const [campaignId, campaign] = this.#requireActiveCampaign();
    const next = reduceCampaign(campaign.state, action);
    const record: JsonlActionRecord = {
      version: 1,
      campaignId,
      sequence: campaign.sequence + 1,
      kind: "action",
      action,
    };
    appendDurably(this.path, record);
    campaign.state = next;
    campaign.sequence = record.sequence;
    campaign.dirty = true;
  }
  checkpoint(): CampaignState {
    this.#assertOpen();
    const [campaignId, campaign] = this.#requireActiveCampaign();
    if (campaign.dirty) this.#appendState(campaignId, "checkpoint", campaign);
    return structuredClone(campaign.state);
  }
  #appendState(
    campaignId: string,
    kind: JsonlStateRecord["kind"],
    campaign: DurableCampaign,
  ): void {
    const sequence = campaign.sequence + 1;
    const state = structuredClone(campaign.state);
    appendDurably(this.path, {
      version: 1,
      campaignId,
      sequence,
      kind,
      state,
      checksum: checksumState(state),
    });
    campaign.sequence = sequence;
    campaign.dirty = false;
  }
  #replay(): void {
    if (!existsSync(this.path)) return;
    const contents = readFileSync(this.path);
    const completeLength =
      contents.at(-1) === 0x0a ? contents.length : contents.lastIndexOf(0x0a) + 1;
    const complete = contents.subarray(0, completeLength).toString("utf8");
    if (completeLength !== contents.length) truncateSync(this.path, completeLength);
    for (const [index, line] of complete.split("\n").entries()) {
      if (!line) continue;
      let record: JsonlRecord;
      try {
        record = JSON.parse(line) as JsonlRecord;
      } catch {
        throw new Error(`Invalid campaign JSONL record on line ${index + 1}`);
      }
      assertRecord(record, index + 1);
      this.#replayRecord(record);
    }
  }
  #replayRecord(record: JsonlRecord): void {
    const current = this.#campaigns.get(record.campaignId);
    const expected = (current?.sequence ?? 0) + 1;
    if (record.sequence !== expected)
      throw new Error(
        `Campaign ${record.campaignId} sequence ${record.sequence} is not ${expected}`,
      );
    if (record.kind === "created") {
      if (current) throw new Error(`Campaign ${record.campaignId} was created more than once`);
      assertStateChecksum(record);
      this.#campaigns.set(record.campaignId, {
        state: structuredClone(withRuntimeState(record.state)),
        sequence: record.sequence,
        dirty: false,
      });
      return;
    }
    if (!current) throw new Error(`Campaign ${record.campaignId} has no creation record`);
    if (record.kind === "action") current.state = reduceCampaign(current.state, record.action);
    else {
      assertStateChecksum(record);
      const checkpoint = withRuntimeState(record.state);
      if (checksumState(current.state) !== checksumState(checkpoint))
        throw new Error(`Campaign ${record.campaignId} checkpoint does not match its action log`);
      current.state = structuredClone(checkpoint);
      current.dirty = false;
    }
    current.sequence = record.sequence;
  }
  #requireActiveCampaign(): [string, DurableCampaign] {
    if (!this.#activeCampaignId) throw new Error("Load a campaign before using the store");
    return [this.#activeCampaignId, this.#campaigns.get(this.#activeCampaignId)!];
  }
  close(): void {
    if (!this.#closed) {
      this.#closed = true;
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
