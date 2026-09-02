import type { AdaptiveCoordinator } from "./adaptive-coordinator.ts";
import type { CampaignLedger } from "./campaign-ledger.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import type { ScopedTarget } from "./scoped-target.ts";
import type { CampaignAction } from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";
import type { BoundedToolAdapters } from "./tool-adapters.ts";
import type { VerificationEngine } from "./verification.ts";
import { createProofObservationTools } from "./agent-proof-tools.ts";
import { createSurfaceRequestTools } from "./agent-surface-tools.ts";

export function explorationTools(
  agentId: string,
  target: ScopedTarget,
  profile: TargetProfile,
  ledger: CampaignLedger,
  coordinator: AdaptiveCoordinator,
  artifacts: ProofArtifactStore,
  adapters: BoundedToolAdapters,
  verification: VerificationEngine,
  dispatch: (action: CampaignAction) => void,
) {
  return {
    ...createSurfaceRequestTools(
      agentId,
      target,
      profile,
      ledger,
      coordinator,
      artifacts,
      adapters,
      verification,
      dispatch,
    ),
    ...createProofObservationTools(agentId, ledger, coordinator, adapters),
  };
}
