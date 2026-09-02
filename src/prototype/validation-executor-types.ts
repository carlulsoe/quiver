import type { CampaignSession } from "./campaign-session.ts";
import type { ModelRouter } from "./model-routing.ts";
import type { RuntimeSafetyController } from "./runtime-safety.ts";
import type { TargetProfile } from "./target-profile.ts";
import type { VerificationEngine } from "./verification.ts";

export interface ValidationExecutorOptions {
  target: URL;
  profile: TargetProfile;
  session: CampaignSession;
  coordinator: ValidationCoordinator;
  modelRouter: ModelRouter;
  verification: VerificationEngine;
  runtimeSafety: RuntimeSafetyController;
}

export interface ValidationCoordinator {
  recordValidation(
    fingerprint: string,
    status: "confirmed" | "rejected",
    validatorId: string,
  ): void;
  claimValidation(validatorId: string, fingerprint: string): string | undefined;
  releaseValidation(fingerprint: string): void;
}
