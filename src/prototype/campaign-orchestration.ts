import { start } from "@flue/runtime/node";
import type { CampaignSession } from "./campaign-session.ts";
import { ExplorationExecutor } from "./exploration-executor.ts";
import type { ModelRouter } from "./model-routing.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import type { RuntimeSafetyController } from "./runtime-safety.ts";
import type { CampaignState } from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";
import { ValidationExecutor } from "./validation-executor.ts";
import type { VerificationEngine } from "./verification.ts";

export interface CampaignOrchestrationContext {
  target: URL;
  profile: TargetProfile;
  explorerCount: number;
  openApi?: unknown;
  context?: string;
  session: CampaignSession;
  modelRouter: ModelRouter;
  artifacts: ProofArtifactStore;
  verification: VerificationEngine;
  runtimeSafety: RuntimeSafetyController;
}

export interface CampaignOrchestration {
  startRuntime(): Promise<AsyncDisposable>;
  restoreAuthentication(resumedPhase: CampaignState["phase"]): Promise<void>;
  runExploration(): Promise<void>;
  drainValidation(): Promise<void>;
  reclaimExplorationBudget(): void;
  runPendingFindings(): Promise<void>;
  runExploitChains(): Promise<void>;
  assertAllJobsFinished(): void;
}

export type CampaignOrchestrationFactory = (
  context: CampaignOrchestrationContext,
) => CampaignOrchestration;

export const createCampaignOrchestration: CampaignOrchestrationFactory = (context) => {
  const exploration = new ExplorationExecutor({
    target: context.target,
    profile: context.profile,
    explorerCount: context.explorerCount,
    openApi: context.openApi,
    context: context.context,
    session: context.session,
    modelRouter: context.modelRouter,
    artifacts: context.artifacts,
    verification: context.verification,
    runtimeSafety: context.runtimeSafety,
  });
  const validation = new ValidationExecutor({
    target: context.target,
    profile: context.profile,
    session: context.session,
    coordinator: exploration.coordinator,
    modelRouter: context.modelRouter,
    verification: context.verification,
    runtimeSafety: context.runtimeSafety,
  });
  exploration.setValidationEnqueuer((fingerprint) => validation.enqueue(fingerprint));

  return {
    startRuntime: () =>
      start({ agents: [...exploration.agentDefinitions, validation.agentDefinition] }),
    restoreAuthentication: (resumedPhase) => validation.restoreAuthentication(resumedPhase),
    runExploration: () => exploration.run(),
    drainValidation: () => validation.drain(),
    reclaimExplorationBudget: () => validation.reclaimExplorationBudget(),
    runPendingFindings: () => validation.runPendingFindings(),
    runExploitChains: () => validation.runExploitChains(),
    assertAllJobsFinished: () => validation.assertAllJobsFinished(),
  };
};
