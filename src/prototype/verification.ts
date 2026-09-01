import { randomInt } from "node:crypto";
import * as v from "valibot";
import { endpointMatchesRequest } from "./endpoint.ts";
import type { ProofArtifactStore } from "./proof-artifacts.ts";
import { evaluateProof } from "./proof.ts";
import { ReplayBudgetExceededError, replayFinding, replayRequestBudget } from "./replay.ts";
import type { ScopedTarget } from "./scoped-target.ts";
import { actorIds } from "./sessions.ts";
import type {
  Finding,
  FindingInput,
  ImpactLevel,
  ProofArtifacts,
  ProofResult,
  ReproductionRequest,
  ValidationObservation,
} from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";

export { ReplayBudgetExceededError } from "./replay.ts";

export interface VerificationContext {
  observations: readonly ValidationObservation[];
}

export interface PreflightResult {
  accepted: boolean;
  proof: ProofResult;
}

export interface VerificationReplay {
  fingerprint: string;
  replayedFinding: Finding;
  observations: ValidationObservation[];
  artifacts: ProofArtifacts;
  proof: ProofResult;
}

export interface VerificationEngineOptions {
  issueIntegerChallenge?: (minimum: number, maximum: number) => number;
}

/** The single external seam for accepting and independently replaying findings. */
export interface VerificationEngine {
  preflight(submission: FindingInput, context: VerificationContext): PreflightResult;
  impactLevelFor(request: ReproductionRequest): ImpactLevel | undefined;
  replay(finding: Finding, target: ScopedTarget): Promise<VerificationReplay>;
}

export class DefaultVerificationEngine implements VerificationEngine {
  readonly #profile: TargetProfile;
  readonly #artifacts: ProofArtifactStore;
  readonly #issueIntegerChallenge: (minimum: number, maximum: number) => number;
  readonly #authentication = new WeakMap<ScopedTarget, Promise<unknown>>();

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
    const challengedFinding = this.#freshCommandChallenge(finding);
    target.allowRequests(
      challengedFinding.reproduction.map(({ method = "GET", path }) => ({ method, path })),
    );
    await this.#prepareSessions(challengedFinding, target);

    const resetRequests =
      challengedFinding.proof.type === "state-transition"
        ? (this.#profile.validationResetRequestBudget ?? 0)
        : 0;
    const requiredRequests = replayRequestBudget(challengedFinding) + resetRequests;
    if (target.remainingRequests < requiredRequests) {
      throw new ReplayBudgetExceededError(
        `Validation requires ${requiredRequests} requests but only ${target.remainingRequests} remain`,
      );
    }
    if (challengedFinding.proof.type === "state-transition" && this.#profile.prepareValidation) {
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
      artifacts: replay.artifacts,
      stateResetAvailable: this.#profile.prepareValidation !== undefined,
      maximumImpactLevel: this.#profile.maximumImpactLevel ?? "observation",
    });
    return { ...replay, proof };
  }

  #freshCommandChallenge(finding: Finding): Finding {
    if (finding.proof.type !== "command-execution-challenge") return finding;
    const proof = finding.proof;
    const policy = this.#profile.proofPolicies?.find(
      (candidate) =>
        candidate.kind === "command-execution-challenge" && candidate.id === proof.policyId,
    );
    if (policy?.kind !== "command-execution-challenge") {
      throw new Error("Unknown command-execution proof policy");
    }
    let challenge = this.#issueIntegerChallenge(policy.challengeMinimum, policy.challengeMaximum);
    if (
      !Number.isSafeInteger(challenge) ||
      challenge < policy.challengeMinimum ||
      challenge > policy.challengeMaximum
    ) {
      throw new Error("Command challenge issuer returned an out-of-policy value");
    }
    if (challenge === proof.challenge) {
      challenge = challenge === policy.challengeMaximum ? policy.challengeMinimum : challenge + 1;
    }
    return replaceVerificationChallenge(
      finding,
      proof.requestIndex,
      policy.challenge,
      String(challenge),
      { ...proof, challenge },
    );
  }

  async #prepareSessions(finding: Finding, target: ScopedTarget): Promise<void> {
    const actorIdsUsed = new Set(finding.reproduction.map(({ actorId }) => actorId));
    if (finding.proof.type === "browser-visible-effect") {
      actorIdsUsed.add(finding.proof.pageActorId);
    }
    if (
      !this.#profile.authenticate ||
      ![...actorIdsUsed].some((actorId) => actorId !== actorIds.anonymous)
    ) {
      return;
    }
    const namedActorIds = [...actorIdsUsed].filter((actorId) => actorId !== actorIds.anonymous);
    const acquired = await Promise.all(
      namedActorIds.map(async (actorId) => {
        try {
          await target.sessions.acquire(actorId);
          return true;
        } catch {
          return false;
        }
      }),
    );
    if (acquired.every(Boolean)) return;
    let authentication = this.#authentication.get(target);
    if (!authentication) {
      authentication = target.runProfileSetup(() => this.#profile.authenticate!(target));
      this.#authentication.set(target, authentication);
    }
    try {
      await authentication;
    } catch (error) {
      this.#authentication.delete(target);
      throw error;
    }
  }
}

const indexSchema = v.pipe(v.number(), v.integer(), v.minValue(0));
const jsonPointerSchema = v.pipe(
  v.string(),
  v.regex(/^(?:\/[^/]*)*$/, "Use an RFC 6901 JSON pointer such as /user/email"),
);
const evidenceSelectorSchema = v.object({
  requestIndex: indexSchema,
  jsonPointer: jsonPointerSchema,
});
const challengeMutationSchema = v.object({
  location: v.picklist(["query", "json-body"]),
  parameter: v.pipe(v.string(), v.minLength(1)),
  template: v.pipe(v.string(), v.includes("{{challenge}}")),
});

/** Runtime schema kept with the engine so proof-pack additions do not edit agent orchestration. */
export const proofPredicateSchema = v.variant("type", [
  v.object({
    type: v.literal("cross-principal-access"),
    actor: evidenceSelectorSchema,
    resourceOwner: evidenceSelectorSchema,
    accessRequestIndex: indexSchema,
    evidencePointers: v.pipe(v.array(jsonPointerSchema), v.minLength(1)),
  }),
  v.object({
    type: v.literal("unauthenticated-success"),
    requestIndex: indexSchema,
    evidencePointers: v.pipe(v.array(jsonPointerSchema), v.minLength(1)),
  }),
  v.object({
    type: v.literal("cross-principal-data-exposure"),
    actor: evidenceSelectorSchema,
    exposedSubject: evidenceSelectorSchema,
    responseRequestIndex: indexSchema,
    evidencePointers: v.pipe(v.array(jsonPointerSchema), v.minLength(1)),
  }),
  v.object({
    type: v.literal("internal-field-exposure"),
    requestIndex: indexSchema,
    evidencePointers: v.pipe(v.array(jsonPointerSchema), v.minLength(1)),
  }),
  v.object({
    type: v.literal("canary-retrieval"),
    policyId: v.string(),
    requestIndex: indexSchema,
    jsonPointer: jsonPointerSchema,
  }),
  v.object({
    type: v.literal("sql-semantic-differential"),
    policyId: v.string(),
    controlRequestIndex: indexSchema,
    probeRequestIndex: indexSchema,
  }),
  v.object({
    type: v.literal("command-execution-challenge"),
    policyId: v.string(),
    requestIndex: indexSchema,
    challenge: v.pipe(v.number(), v.integer(), v.minValue(1)),
  }),
  v.object({
    type: v.literal("state-transition"),
    policyId: v.string(),
    transitionRequestIndex: indexSchema,
    beforeRequestIndex: indexSchema,
    afterRequestIndex: indexSchema,
  }),
  v.object({
    type: v.literal("browser-visible-effect"),
    policyId: v.string(),
    probeId: v.string(),
    marker: v.string(),
    requestIndex: indexSchema,
    pagePath: v.string(),
    kind: v.literal("dialog"),
    challenge: challengeMutationSchema,
    pageActorId: v.string(),
    pageChallenge: v.optional(challengeMutationSchema),
    collectorRequestBudget: v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(20)),
  }),
  v.object({
    type: v.literal("oast-callback"),
    policyId: v.string(),
    probeId: v.string(),
    token: v.string(),
    requestIndex: indexSchema,
    callbackUrl: v.string(),
    challenge: challengeMutationSchema,
  }),
]);

export const verificationInstructions = `Every finding must declare a machine-checkable proof predicate using zero-based reproduction request indexes and RFC 6901 JSON pointers into parsed response bodies:
- cross-principal-access: identify the named actor and the accessed resource owner in replay responses; they must differ, the access response must succeed, and each evidence pointer must exist in that access response.
- unauthenticated-success: identify an anonymous request whose successful response contains each declared evidence field.
- cross-principal-data-exposure: identify the named actor and a different subject whose fields appear in the successful response, plus every concrete exposed field.
- internal-field-exposure: identify a successful response and implementation-only fields whose presence alone violates the response contract. Use this only for unmistakable internal/debug/configuration properties—not normal fields from the caller's own resource.
- canary-retrieval: select a value from a replay response that matches a target-owned canary policy.
- sql-semantic-differential: replay the target policy's exact false/true SQL predicates and select the control and probe requests. Both responses must match the target-owned semantic values while the requests differ only by that mutation.
- command-execution-challenge: use the target policy's bounded arithmetic command template and declare its integer challenge. Confirmation replaces it with a fresh challenge and requires the computed output, which is never present in the request; generic OAST callbacks cannot satisfy this proof.
- state-transition: identify before, protected transition, and after requests matching a target-owned state policy. Use distinct sampleIds on otherwise identical before/after reads.
- browser-visible-effect and oast-callback require fresh collector artifacts and a matching target-owned policy.

Choose a predicate compatible with the vulnerability-specific category and point only to values you observed. Categories with no compatible authoritative predicate cannot yet be submitted. submit_finding first runs the predicate against exploration observations; inspect failed deterministicProof checks before resubmitting. The same predicate must later pass against a fresh replay, and the deterministic result—not the validation model's opinion—decides confirmation.`;

function challengeFromRequest(
  request: Pick<ReproductionRequest, "path" | "body">,
  mutation: { location: "query" | "json-body"; parameter: string; template: string },
): number | undefined {
  let value: unknown;
  if (mutation.location === "query") {
    const values = new URL(request.path, "http://verification.invalid").searchParams.getAll(
      mutation.parameter,
    );
    if (values.length !== 1) return undefined;
    value = values[0];
  } else {
    try {
      const parsed: unknown = JSON.parse(request.body ?? "");
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") return undefined;
      value = (parsed as Record<string, unknown>)[mutation.parameter];
    } catch {
      return undefined;
    }
  }
  if (typeof value !== "string") return undefined;
  const parts = mutation.template.split("{{challenge}}");
  if (parts.length !== 2) return undefined;
  const [prefix = "", suffix = ""] = parts;
  if (!value.startsWith(prefix) || !value.endsWith(suffix)) return undefined;
  const encoded = value.slice(prefix.length, value.length - suffix.length);
  return /^(?:0|[1-9]\d*)$/.test(encoded) ? Number(encoded) : undefined;
}

function replaceVerificationChallenge(
  finding: Finding,
  requestIndex: number,
  mutation: { location: "query" | "json-body"; parameter: string; template: string },
  challenge: string,
  proof: Finding["proof"],
): Finding {
  const request = finding.reproduction[requestIndex];
  if (!request || mutation.template.split("{{challenge}}").length !== 2) return finding;
  const replacement = mutation.template.replace("{{challenge}}", challenge);
  const nextRequest = { ...request };
  if (mutation.location === "query") {
    const url = new URL(request.path, "http://verification.invalid");
    if (url.searchParams.getAll(mutation.parameter).length !== 1) return finding;
    url.searchParams.set(mutation.parameter, replacement);
    nextRequest.path = `${url.pathname}${url.search}${url.hash}`;
  } else {
    try {
      const parsed: unknown = JSON.parse(request.body ?? "");
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") return finding;
      nextRequest.body = JSON.stringify({
        ...(parsed as Record<string, unknown>),
        [mutation.parameter]: replacement,
      });
    } catch {
      return finding;
    }
  }
  return {
    ...finding,
    proof,
    reproduction: finding.reproduction.map((candidate, index) =>
      index === requestIndex ? nextRequest : candidate,
    ),
  };
}
