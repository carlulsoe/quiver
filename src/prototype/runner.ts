import type { PromptUsage } from "@flue/runtime";
import { start } from "@flue/runtime/node";
import type { MissionUsage, RunEvent } from "./campaign-history.ts";
import { CampaignSession } from "./campaign-session.ts";
import type { CampaignStore } from "./campaign-store.ts";
import { ExplorationExecutor } from "./exploration-executor.ts";
import { createModelRouter, type ModelRouter } from "./model-routing.ts";
import { ProofArtifactStore } from "./proof-artifacts.ts";
import { isRuntimeStopError } from "./runner-errors.ts";
import { RuntimeSafetyController } from "./runtime-safety.ts";
import type { CampaignAction, CampaignState } from "./state.ts";
import { assertValidTargetProfile, type TargetProfile } from "./target-profile.ts";
import { ValidationExecutor } from "./validation-executor.ts";
import { DefaultVerificationEngine } from "./verification.ts";

export interface RunCampaignOptions {
  target: URL;
  profile: TargetProfile;
  requestBudget?: number;
  explorerCount?: number;
  onState?: (state: CampaignState, action?: CampaignAction) => void;
  openApi?: unknown;
  context?: string;
  campaignId?: string;
  campaignStore?: CampaignStore;
  modelRouter?: ModelRouter;
}

export type { MissionUsage, RunEvent } from "./campaign-history.ts";

export interface CampaignRun {
  profileId: string;
  reproductionAuthentication?: TargetProfile["reproductionAuthentication"];
  model: string;
  durationMs: number;
  usage: PromptUsage;
  missionUsage: MissionUsage[];
  state: CampaignState;
  events: RunEvent[];
}

export async function runCampaign(options: RunCampaignOptions): Promise<CampaignRun> {
  assertValidTargetProfile(options.profile);
  await using artifacts = new ProofArtifactStore();
  const explorerCount = options.explorerCount ?? 2;
  const session = new CampaignSession({
    target: options.target,
    profile: options.profile,
    requestBudget: options.requestBudget ?? 30,
    explorerCount,
    openApi: options.openApi,
    context: options.context,
    campaignId: options.campaignId,
    campaignStore: options.campaignStore,
    onState: options.onState,
  });
  const dispatch = session.dispatch.bind(session);
  session.recover();
  if (isTerminal(session.state)) return finishCampaign(options, session, false);
  const resumedPhase = session.state.phase;
  const verification = new DefaultVerificationEngine(options.profile, artifacts);
  const modelRouter = options.modelRouter ?? createModelRouter();
  const runtimeSafety = new RuntimeSafetyController(options.profile.runtimeSafety, {
    controlStatus: () => session.checkpoint().runtime.control,
    initialConsecutiveFailures: session.state.runtime.consecutiveFailures,
    initialDisruptiveResponses: session.state.runtime.disruptiveResponses,
    onSuccess: () => dispatch({ type: "runtime-success" }),
    onFailure: (disruptive) => dispatch({ type: "runtime-failure", disruptive }),
    onHalt: (reason) => dispatch({ type: "halt", reason }),
  });
  try {
    const exploration = new ExplorationExecutor({
      target: options.target,
      profile: options.profile,
      explorerCount,
      openApi: options.openApi,
      context: options.context,
      session,
      modelRouter,
      artifacts,
      verification,
      runtimeSafety,
    });
    const validation = new ValidationExecutor({
      target: options.target,
      profile: options.profile,
      session,
      coordinator: exploration.coordinator,
      modelRouter,
      verification,
      runtimeSafety,
    });
    exploration.setValidationEnqueuer((fingerprint) => validation.enqueue(fingerprint));
    await using _campaignRuntime = await start({
      agents: [...exploration.agentDefinitions, validation.agentDefinition],
    });
    await validation.restoreAuthentication(resumedPhase);
    if (session.state.phase !== "validating") {
      await exploration.run();
      await validation.drain();
      validation.reclaimExplorationBudget();
    }
    await validation.runPendingFindings();
    await validation.runExploitChains();
    validation.assertAllJobsFinished();
    runtimeSafety.assertReady();
    dispatch({ type: "phase", phase: "complete" });
  } catch (error) {
    if (!isRuntimeStopError(error)) {
      dispatch({ type: "failed", error: error instanceof Error ? error.message : String(error) });
    }
  }
  return finishCampaign(options, session);
}

function isTerminal(state: CampaignState): boolean {
  return (
    state.phase === "complete" || state.phase === "failed" || state.runtime.control !== "running"
  );
}

function finishCampaign(
  options: RunCampaignOptions,
  session: CampaignSession,
  persistElapsed = true,
): CampaignRun {
  if (persistElapsed) session.finishHistory();
  return {
    profileId: options.profile.id,
    reproductionAuthentication: options.profile.reproductionAuthentication,
    model:
      session.missionUsage[0]?.model ?? session.missionUsage[0]?.attemptedModels[0] ?? "unrouted",
    durationMs: session.state.history.durationMs,
    usage: session.usage,
    missionUsage: session.missionUsage,
    state: session.state,
    events: session.events,
  };
}
