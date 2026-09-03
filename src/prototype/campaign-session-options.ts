import type { CampaignStore } from "./campaign-store.ts";
import type { CampaignAction, CampaignState } from "./state.ts";
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
