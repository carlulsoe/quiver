import type { ChallengeMutation, FindingCategory, ImpactLevel } from "./state.ts";
import type { AllowedRequest, DeniedRequest, ScopedTarget } from "./scoped-target.ts";
import type { ActorId } from "./sessions.ts";
import {
  assertValidTargetManifest,
  authenticateTargetManifest,
  manifestActorIds,
  type ProtectedOperationManifest,
  type TargetManifest,
} from "./target-manifest.ts";

export interface ReproductionAuthentication {
  description: string;
  /** Legacy single-actor commands. They must export QUIVER_TOKEN. */
  commands: string[];
  /** Optional per-actor commands. Each command set must export QUIVER_TOKEN. */
  actors?: Record<string, { description: string; commands: string[] }>;
}

interface ProofPolicyRule {
  id: string;
  category: FindingCategory;
  description: string;
}

type ProofScalar = string | number | boolean | null;

export interface CanaryProofPolicy extends ProofPolicyRule {
  kind: "canary";
  endpoint: string;
  method: string;
  verify: (value: string) => boolean;
  source: "immutable-fixture";
  jsonPointer: string;
}

export interface StateTransitionProofPolicy extends ProofPolicyRule {
  kind: "state-transition";
  endpoint: string;
  method: "POST" | "PUT" | "PATCH";
  jsonPointer: string;
  before: ProofScalar;
  after: ProofScalar;
  readEndpoint: string;
  readMethod: "GET" | "HEAD";
}

export interface BrowserEffectProofPolicy extends ProofPolicyRule {
  kind: "browser-effect";
  effect: "dialog";
  markerPattern: string;
  pagePath: string;
  payloadTemplate: string;
  challenge: ChallengeMutation;
  pageActorId: ActorId;
  pageChallenge?: ChallengeMutation;
  requestBudget: number;
}

export interface OastProofPolicy extends ProofPolicyRule {
  kind: "oast";
  protocol: "http";
  endpoint: string;
  method: string;
  challenge: ChallengeMutation;
}

export interface SqlSemanticDifferentialProofPolicy extends ProofPolicyRule {
  kind: "sql-semantic-differential";
  category: "sql-injection";
  endpoint: string;
  method: string;
  mutation: {
    location: "query" | "json-body";
    parameter: string;
    controlValue: string;
    probeValue: string;
  };
  response: {
    jsonPointer: string;
    controlValue: ProofScalar;
    probeValue: ProofScalar;
  };
}

export interface CommandExecutionChallengeProofPolicy extends ProofPolicyRule {
  kind: "command-execution-challenge";
  category: "command-injection";
  endpoint: string;
  method: string;
  challenge: ChallengeMutation;
  outputJsonPointer: string;
  outputPrefix: string;
  multiplier: number;
  addend: number;
  challengeMinimum: number;
  challengeMaximum: number;
}

export type ProofPolicy =
  | CanaryProofPolicy
  | StateTransitionProofPolicy
  | BrowserEffectProofPolicy
  | OastProofPolicy
  | SqlSemanticDifferentialProofPolicy
  | CommandExecutionChallengeProofPolicy;

export interface TargetProfile {
  id: string;
  displayName: string;
  objective: string;
  allowedRequests?: AllowedRequest[];
  setupRequests?: AllowedRequest[];
  deniedRequests?: DeniedRequest[];
  authenticate?: (
    target: ScopedTarget,
    actorIds?: readonly ActorId[],
  ) => Promise<{ authContext: string }>;
  /** Actor references made available to campaign agents. Anonymous is always available. */
  actorIds?: ActorId[];
  reproductionAuthentication?: ReproductionAuthentication;
  proofPolicies?: ProofPolicy[];
  prepareValidation?: (target: ScopedTarget) => Promise<void>;
  /** Exact scoped-request cost of one prepareValidation call. */
  validationResetRequestBudget?: number;
  /** Hard ceiling for code-derived proof impact. Defaults to observation. */
  maximumImpactLevel?: ImpactLevel;
  /** Declarative source used by bundled and external target adapters. */
  manifest?: TargetManifest;
  protectedOperations?: ProtectedOperationManifest[];
}

export type TargetProfileExtensions = Pick<
  TargetProfile,
  "proofPolicies" | "prepareValidation" | "validationResetRequestBudget"
>;

/** Builds the runtime profile API from a declarative onboarding manifest. */
export function createTargetProfile(
  manifest: TargetManifest,
  extensions: TargetProfileExtensions = {},
): TargetProfile {
  assertValidTargetManifest(manifest);
  const actorIds = manifestActorIds(manifest);
  const setupRequests = [...(manifest.scope.setupOperations ?? [])];
  const allowedRequests = uniqueOperations([
    ...setupRequests,
    ...(manifest.scope.protectedOperations ?? []).map(({ method, path }) => ({ method, path })),
  ]);
  return {
    id: manifest.id,
    displayName: manifest.displayName,
    objective: manifest.objective,
    allowedRequests: allowedRequests.length > 0 ? allowedRequests : undefined,
    setupRequests: setupRequests.length > 0 ? setupRequests : undefined,
    deniedRequests: manifest.scope.deniedOperations
      ? [...manifest.scope.deniedOperations]
      : undefined,
    protectedOperations: manifest.scope.protectedOperations
      ? [...manifest.scope.protectedOperations]
      : undefined,
    maximumImpactLevel: manifest.scope.maximumImpactLevel,
    actorIds,
    reproductionAuthentication: manifest.reproductionAuthentication,
    ...(actorIds.length > 0
      ? {
          authenticate: (target: ScopedTarget, requestedActorIds?: readonly ActorId[]) =>
            authenticateTargetManifest(target, manifest, { actorIds: requestedActorIds }),
        }
      : {}),
    manifest,
    ...extensions,
  };
}

function uniqueOperations(operations: AllowedRequest[]): AllowedRequest[] {
  return [
    ...new Map(
      operations.map((operation) => [`${operation.method} ${operation.path}`, operation]),
    ).values(),
  ];
}

export function assertValidTargetProfile(profile: TargetProfile): void {
  if (profile.manifest) assertValidTargetManifest(profile.manifest);
  if (
    profile.prepareValidation &&
    (!Number.isInteger(profile.validationResetRequestBudget) ||
      (profile.validationResetRequestBudget ?? -1) < 0)
  ) {
    throw new Error("Profiles with prepareValidation must declare validationResetRequestBudget");
  }
  for (const policy of profile.proofPolicies ?? []) {
    if (
      policy.kind === "browser-effect" &&
      (!Number.isInteger(policy.requestBudget) ||
        policy.requestBudget < 1 ||
        policy.requestBudget > 20)
    ) {
      throw new Error(`Browser-effect policy ${policy.id} requestBudget must be from 1 to 20`);
    }
    if (policy.kind === "oast" && policy.challenge.template.split("{{challenge}}").length !== 2) {
      throw new Error(`OAST policy ${policy.id} challenge must substitute the callback once`);
    }
    if (
      policy.kind === "sql-semantic-differential" &&
      (policy.mutation.controlValue === policy.mutation.probeValue ||
        Object.is(policy.response.controlValue, policy.response.probeValue))
    ) {
      throw new Error(
        `SQL semantic-differential policy ${policy.id} must use distinct request and response values`,
      );
    }
    if (
      policy.kind === "command-execution-challenge" &&
      (policy.challenge.template.split("{{challenge}}").length !== 2 ||
        !Number.isSafeInteger(policy.multiplier) ||
        policy.multiplier === 0 ||
        !Number.isSafeInteger(policy.addend) ||
        !Number.isSafeInteger(policy.challengeMinimum) ||
        !Number.isSafeInteger(policy.challengeMaximum) ||
        policy.challengeMinimum < 1 ||
        policy.challengeMinimum >= policy.challengeMaximum ||
        !Number.isSafeInteger(policy.challengeMinimum * policy.multiplier + policy.addend) ||
        !Number.isSafeInteger(policy.challengeMaximum * policy.multiplier + policy.addend) ||
        policy.outputPrefix.length === 0)
    ) {
      throw new Error(
        `Command-execution policy ${policy.id} must declare one bounded arithmetic challenge`,
      );
    }
    if (
      policy.kind === "browser-effect" &&
      (policy.challenge.template !== policy.payloadTemplate ||
        policy.challenge.template.split("{{challenge}}").length !== 2)
    ) {
      throw new Error(
        `Browser-effect policy ${policy.id} challenge must use its payloadTemplate once`,
      );
    }
    if (
      policy.kind === "browser-effect" &&
      policy.pageChallenge &&
      (policy.pageChallenge.location !== "query" ||
        !sameChallenge(policy.challenge, policy.pageChallenge) ||
        policy.pageChallenge.template.split("{{challenge}}").length !== 2 ||
        new URL(policy.pagePath, "http://browser-policy.invalid").searchParams.getAll(
          policy.pageChallenge.parameter,
        ).length !== 1)
    ) {
      throw new Error(
        `Browser-effect policy ${policy.id} pageChallenge must replace one declared query parameter`,
      );
    }
    if (
      policy.kind === "state-transition" &&
      (!["POST", "PUT", "PATCH"].includes(policy.method) ||
        !["GET", "HEAD"].includes(policy.readMethod))
    ) {
      throw new Error(
        `State-transition policy ${policy.id} must use POST/PUT/PATCH with a GET/HEAD state read`,
      );
    }
  }
}

function sameChallenge(left: ChallengeMutation, right: ChallengeMutation): boolean {
  return (
    left.location === right.location &&
    left.parameter === right.parameter &&
    left.template === right.template
  );
}

export function browserPolicyPath(policy: BrowserEffectProofPolicy, marker: string): string {
  if (!policy.pageChallenge) return policy.pagePath;
  if (
    policy.pageChallenge.location !== "query" ||
    policy.pageChallenge.template.split("{{challenge}}").length !== 2
  ) {
    throw new Error("Browser page challenge must be one query substitution");
  }
  const url = new URL(policy.pagePath, "http://browser-policy.invalid");
  if (url.searchParams.getAll(policy.pageChallenge.parameter).length !== 1) {
    throw new Error("Browser policy pagePath must contain its challenge query parameter once");
  }
  url.searchParams.set(
    policy.pageChallenge.parameter,
    policy.pageChallenge.template.replace("{{challenge}}", marker),
  );
  return `${url.pathname}${url.search}${url.hash}`;
}
