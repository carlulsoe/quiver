import { PersistentCoordinator } from "./adaptive-coordinator.ts";
import { createExplorerAgent } from "./agents.ts";
import { CampaignLedger } from "./campaign-ledger.ts";
import type { CampaignSession } from "./campaign-session.ts";
import { estimateTokens, routeTriageRequirements, type ModelRouter } from "./model-routing.ts";
import { RoutedMission } from "./mission-runtime.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import type { RuntimeSafetyController } from "./runtime-safety.ts";
import { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import type { TargetProfile } from "./target-profile.ts";
import { createBoundedToolAdapters } from "./tool-adapters.ts";
import type { VerificationEngine } from "./verification.ts";

export interface ExplorationExecutorOptions {
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
export interface ExplorationWorker {
  id: string;
  cursor: RoutedMission;
  definition: ReturnType<typeof createExplorerAgent>;
}

export function createExplorationResources(
  options: ExplorationExecutorOptions,
  enqueueValidation: (fingerprint: string) => void,
) {
  const { session, profile, explorerCount } = options;
  const dispatch = session.dispatch.bind(session);
  const coordinator = new PersistentCoordinator({
    actorIds: [actorIds.anonymous, ...(profile.actorIds ?? [])],
    requestBudget: session.state.budget.exploration,
    expectedWorkers: explorerCount,
    onChange: (snapshot) => dispatch({ type: "coordinator-snapshot", snapshot }),
    restore: {
      snapshot: session.state.coordination,
      operations: session.state.discoveredOperations,
      testedRequests: session.state.testedRequests,
      findings: session.state.findings,
      validations: session.state.validations,
      explorationRequests: session.state.requests.exploration,
    },
  });
  for (const job of session.state.runtime.jobs)
    if (job.kind === "validation" && job.status === "queued")
      coordinator.releaseValidation(job.fingerprint);
  dispatch({ type: "coordinator-snapshot", snapshot: coordinator.snapshot() });
  for (const plan of coordinator.snapshot().specialists)
    if (!session.state.agents.some(({ id }) => id === plan.agentId))
      dispatch({ type: "agent-spawned", id: plan.agentId, role: "specialist" });
  const target = new ScopedTarget({
    target: options.target,
    requestBudget: Math.max(
      0,
      session.state.budget.exploration - session.state.requests.exploration,
    ),
    allowedRequests: profile.allowedRequests,
    setupRequests: profile.setupRequests,
    deniedRequests: profile.deniedRequests,
    onRequest: (request) => {
      session.record("request", { phase: "exploration", ...request });
      dispatch({ type: "request", phase: "exploration" });
      coordinator.observeBudgetUse();
    },
    openApi: options.openApi,
    attackSurfaceOrigins: profile.attackSurfaceOrigins,
    maximumImpactLevel: profile.maximumImpactLevel ?? "observation",
    runtimeSafety: options.runtimeSafety,
  });
  const adapters = createBoundedToolAdapters({ target, profile, artifacts: options.artifacts });
  const ledger = new CampaignLedger({
    onTestedRequest: (request) => {
      coordinator.observeRequest(request);
      dispatch({ type: "request-tested", request });
    },
    onFinding: (finding) => {
      const fingerprint = coordinator.observeFinding(finding);
      dispatch({ type: "finding", finding });
      enqueueValidation(fingerprint);
    },
    onExploitChain: (chain) => dispatch({ type: "exploit-chain", chain }),
  });
  const contextTokens = estimateTokens({
    context: options.context,
    openApi: options.openApi,
    manifest: profile.manifest,
  });
  const focuses = [
    "broken authorization and cross-object access, using identifiers discovered in one response against other GET endpoints",
    "excessive or sensitive data exposure and security misconfiguration",
    "route-level authentication gaps and object-detail authorization controls not yet tested by the other explorers",
  ];
  const createWorker = (id: string, focus: string | (() => string)): ExplorationWorker => {
    const cursor = new RoutedMission(
      options.modelRouter.route(routeTriageRequirements(contextTokens)),
    );
    return {
      id,
      cursor,
      definition: createExplorerAgent(
        id,
        focus,
        target,
        profile,
        ledger,
        coordinator,
        options.artifacts,
        adapters,
        options.verification,
        dispatch,
        () => cursor.model,
        options.context,
      ),
    };
  };
  const explorers = Array.from({ length: explorerCount }, (_, index) =>
    createWorker(
      `explorer-${index + 1}`,
      focuses[index] ?? "the remaining REST attack surface not covered by other explorers",
    ),
  );
  const specialistLimit = Math.min(2, explorerCount);
  const specialists = Array.from({ length: specialistLimit }, (_, index) => {
    const id = `specialist-${index + 1}`;
    return createWorker(
      id,
      () => coordinator.focusFor(id) ?? "high-confidence hypotheses retained by the coordinator",
    );
  });
  return {
    coordinator,
    target,
    explorers,
    specialists,
    specialistLimit,
    contextTokens,
    agentDefinitions: [
      ...explorers.map(({ definition }) => definition),
      ...specialists.map(({ definition }) => definition),
    ],
  };
}

export function isBrowserBacked(profile: TargetProfile): boolean {
  return (
    profile.proofPolicies?.some(({ kind }) => kind === "browser-effect") === true ||
    profile.manifest?.identities.some(
      ({ authentication }) => authentication?.kind === "browser-login",
    ) === true
  );
}
export function specialistDefinition<T>(id: string, definitions: readonly T[]): T {
  const match = /^specialist-(\d+)$/.exec(id);
  const definition = definitions[match ? Number(match[1]) - 1 : -1];
  if (!definition) throw new Error(`No persisted specialist definition exists for ${id}`);
  return definition;
}
