import {
  reduceCampaign,
  withRuntimeState,
  type CampaignAction,
  type CampaignControlStatus,
  type CampaignState,
} from "./state.ts";
import {
  snapshotCampaignControl,
  type CampaignControlSnapshot,
} from "./campaign-control-snapshot.ts";

export type { CampaignControlSnapshot } from "./campaign-control-snapshot.ts";

export interface CampaignStore {
  create(campaignId: string, state: CampaignState): CampaignState;
  load(campaignId: string): CampaignState;
  apply(action: CampaignAction): CampaignControlSnapshot;
  applyBatch(actions: readonly CampaignAction[]): CampaignControlSnapshot;
  checkpoint(): CampaignState;
  controlStatus(): CampaignControlStatus;
  controlSnapshot(): CampaignControlSnapshot;
}

export class InMemoryCampaignStore implements CampaignStore {
  readonly #campaigns = new Map<string, CampaignState>();
  #activeCampaignId?: string;
  constructor(campaigns: Iterable<readonly [string, CampaignState]> = []) {
    for (const [id, state] of campaigns)
      this.#campaigns.set(id, structuredClone(withRuntimeState(state)));
  }
  create(campaignId: string, state: CampaignState): CampaignState {
    assertCampaignId(campaignId);
    if (this.#campaigns.has(campaignId)) throw new Error(`Campaign ${campaignId} already exists`);
    this.#campaigns.set(campaignId, structuredClone(withRuntimeState(state)));
    this.#activeCampaignId = campaignId;
    return this.checkpoint();
  }
  load(campaignId: string): CampaignState {
    if (!this.#campaigns.has(campaignId)) throw new Error(`Unknown campaign ${campaignId}`);
    this.#activeCampaignId = campaignId;
    return this.checkpoint();
  }
  apply(action: CampaignAction): CampaignControlSnapshot {
    return this.applyBatch([action]);
  }
  applyBatch(actions: readonly CampaignAction[]): CampaignControlSnapshot {
    const id = this.#requireActiveCampaign();
    let state = this.#campaigns.get(id)!;
    for (const action of actions) state = reduceCampaign(state, action);
    this.#campaigns.set(id, state);
    return snapshotCampaignControl(state);
  }
  checkpoint(): CampaignState {
    return structuredClone(this.#campaigns.get(this.#requireActiveCampaign())!);
  }
  controlStatus(): CampaignControlStatus {
    return this.#campaigns.get(this.#requireActiveCampaign())!.runtime.control;
  }
  controlSnapshot(): CampaignControlSnapshot {
    return snapshotCampaignControl(this.#campaigns.get(this.#requireActiveCampaign())!);
  }
  #requireActiveCampaign(): string {
    if (!this.#activeCampaignId) throw new Error("Load a campaign before using the store");
    return this.#activeCampaignId;
  }
}

export function assertCampaignId(campaignId: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(campaignId))
    throw new Error("Campaign id must be 1-128 safe filename characters");
}
export { JsonlCampaignStore } from "./campaign-store-jsonl.ts";
