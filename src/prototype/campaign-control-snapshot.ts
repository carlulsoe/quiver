import type { CampaignControlStatus, CampaignState } from "./state.ts";

export interface CampaignControlSnapshot {
  readonly control: CampaignControlStatus;
  readonly controlReason?: string;
}

export function snapshotCampaignControl(state: CampaignState): CampaignControlSnapshot {
  return Object.freeze({
    control: state.runtime.control,
    controlReason: state.runtime.controlReason,
  });
}

export function synchronizeCampaignControl(
  state: CampaignState,
  snapshot: CampaignControlSnapshot,
): CampaignState {
  if (
    state.runtime.control === snapshot.control &&
    state.runtime.controlReason === snapshot.controlReason
  ) {
    return state;
  }
  return {
    ...state,
    runtime: {
      ...state.runtime,
      control: snapshot.control,
      controlReason: snapshot.controlReason,
    },
  };
}
