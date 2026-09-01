import { reduceCampaign, type CampaignAction, type CampaignState } from "./state.ts";

/** Persistence seam for one active campaign at a time. */
export interface CampaignStore {
  load(campaignId: string): CampaignState;
  apply(action: CampaignAction): void;
  checkpoint(): CampaignState;
}

/** Current process-local campaign adapter. */
export class InMemoryCampaignStore implements CampaignStore {
  readonly #campaigns = new Map<string, CampaignState>();
  #activeCampaignId?: string;

  constructor(campaigns: Iterable<readonly [string, CampaignState]> = []) {
    for (const [campaignId, state] of campaigns) {
      this.#campaigns.set(campaignId, cloneState(state));
    }
  }

  load(campaignId: string): CampaignState {
    if (!this.#campaigns.has(campaignId)) {
      throw new Error(`Unknown campaign ${campaignId}`);
    }
    this.#activeCampaignId = campaignId;
    return this.checkpoint();
  }

  apply(action: CampaignAction): void {
    const campaignId = this.#requireActiveCampaign();
    const current = this.#campaigns.get(campaignId)!;
    this.#campaigns.set(campaignId, reduceCampaign(current, action));
  }

  checkpoint(): CampaignState {
    const campaignId = this.#requireActiveCampaign();
    return cloneState(this.#campaigns.get(campaignId)!);
  }

  #requireActiveCampaign(): string {
    if (!this.#activeCampaignId) throw new Error("Load a campaign before using the store");
    return this.#activeCampaignId;
  }
}

function cloneState(state: CampaignState): CampaignState {
  return structuredClone(state);
}
