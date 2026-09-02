import { randomInt } from "node:crypto";
import { endpointMatchesRequest } from "./endpoint.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import { evaluateProof } from "./proof.ts";
import { ReplayBudgetExceededError, replayFinding, replayRequestBudget } from "./replay.ts";
import type { ScopedTarget } from "./scoped-target.ts";
import { actorIds, type ActorId } from "./sessions.ts";
import type { Finding, FindingInput, ImpactLevel, ReproductionRequest } from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";
import { challengeFromRequest } from "./verification-challenge.ts";
import { verificationProofHandlerFor } from "./verification-handlers.ts";
import type {
  PreflightResult,
  VerificationContext,
  VerificationEngine,
  VerificationEngineOptions,
  VerificationReplay,
} from "./verification-types.ts";

export class DefaultVerificationEngine implements VerificationEngine {
  readonly #profile: TargetProfile;
  readonly #artifacts: ProofArtifactStore;
  readonly #issueIntegerChallenge: (minimum: number, maximum: number) => number;
  readonly #authentication = new WeakMap<ScopedTarget, Promise<void>>();

  constructor(
    profile: TargetProfile,
    artifacts: ProofArtifactStore,
    options: VerificationEngineOptions = {},
  ) {
    this.#profile = profile;
    this.#artifacts = artifacts;
    this.#issueIntegerChallenge =
      options.issueIntegerChallenge ?? ((minimum, maximum) => randomInt(minimum, maximum + 1));
  }

  preflight(submission: FindingInput, context: VerificationContext): PreflightResult {
    const proof = evaluateProof(submission, context.observations, {
      policies: this.#profile.proofPolicies,
      identities: this.#profile.manifest?.identities,
      protectedOperations: this.#profile.protectedOperations,
      artifacts: this.#artifacts.snapshot(),
      stateResetAvailable: this.#profile.prepareValidation !== undefined,
      maximumImpactLevel: this.#profile.maximumImpactLevel ?? "observation",
    });
    return { accepted: proof.passed, proof };
  }

  impactLevelFor(request: ReproductionRequest): ImpactLevel | undefined {
    return this.#profile.proofPolicies?.some((policy) => {
      if (
        policy.kind !== "command-execution-challenge" ||
        (request.method ?? "GET") !== policy.method ||
        !endpointMatchesRequest(policy.endpoint, request.path)
      ) {
        return false;
      }
      const challenge = challengeFromRequest(request, policy.challenge);
      return (
        challenge !== undefined &&
        challenge >= policy.challengeMinimum &&
        challenge <= policy.challengeMaximum
      );
    })
      ? "bounded"
      : undefined;
  }

  async replay(finding: Finding, target: ScopedTarget): Promise<VerificationReplay> {
    const proofHandler = verificationProofHandlerFor(finding);
    const challengedFinding = proofHandler.prepareFinding(finding, {
      profile: this.#profile,
      issueIntegerChallenge: this.#issueIntegerChallenge,
    });
    target.allowRequests([
      ...challengedFinding.reproduction.map(({ method = "GET", path }) => ({ method, path })),
      ...proofHandler.additionalAllowedRequests(challengedFinding, this.#profile),
    ]);
    await this.#prepareSessions(
      challengedFinding,
      proofHandler.additionalActorIds(challengedFinding),
      target,
    );

    const resetRequests = proofHandler.requiresStateReset
      ? (this.#profile.validationResetRequestBudget ?? 0)
      : 0;
    const requiredRequests = replayRequestBudget(challengedFinding) + resetRequests;
    if (target.remainingRequests < requiredRequests) {
      throw new ReplayBudgetExceededError(
        `Validation requires ${requiredRequests} requests but only ${target.remainingRequests} remain`,
      );
    }
    if (proofHandler.requiresStateReset && this.#profile.prepareValidation) {
      await target.runProfileSetup(() => this.#profile.prepareValidation!(target));
    }

    const replay = await replayFinding(
      target,
      challengedFinding,
      this.#artifacts,
      this.#profile.proofPolicies,
    );
    const proof = evaluateProof(replay.replayedFinding, replay.observations, {
      policies: this.#profile.proofPolicies,
      identities: this.#profile.manifest?.identities,
      protectedOperations: this.#profile.protectedOperations,
      artifacts: replay.artifacts,
      stateResetAvailable: this.#profile.prepareValidation !== undefined,
      maximumImpactLevel: this.#profile.maximumImpactLevel ?? "observation",
    });
    return { ...replay, proof };
  }

  async #prepareSessions(
    finding: Finding,
    additionalActorIds: readonly ActorId[],
    target: ScopedTarget,
  ): Promise<void> {
    const actorIdsUsed = new Set([
      ...finding.reproduction.map(({ actorId }) => actorId),
      ...additionalActorIds,
    ]);
    if (
      !this.#profile.authenticate ||
      ![...actorIdsUsed].some((actorId) => actorId !== actorIds.anonymous)
    ) {
      return;
    }
    const namedActorIds = [...actorIdsUsed].filter((actorId) => actorId !== actorIds.anonymous);
    const missingActorIds = await missingSessions(target, namedActorIds);
    if (missingActorIds.length === 0) return;
    const previous = this.#authentication.get(target) ?? Promise.resolve();
    const authentication = previous
      .catch(() => undefined)
      .then(async () => {
        const stillMissing = await missingSessions(target, missingActorIds);
        if (stillMissing.length === 0) return;
        await target.runProfileSetup(() => this.#profile.authenticate!(target, stillMissing));
      });
    this.#authentication.set(target, authentication);
    try {
      await authentication;
    } finally {
      if (this.#authentication.get(target) === authentication) {
        this.#authentication.delete(target);
      }
    }
  }
}

async function missingSessions(target: ScopedTarget, actorIdsToCheck: readonly ActorId[]) {
  const acquired = await Promise.all(
    actorIdsToCheck.map(async (actorId) => {
      try {
        await target.sessions.acquire(actorId);
        return true;
      } catch {
        return false;
      }
    }),
  );
  return actorIdsToCheck.filter((_, index) => !acquired[index]);
}
