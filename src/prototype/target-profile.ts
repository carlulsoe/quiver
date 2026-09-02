import type {
  BrowserChallengeMutation,
  ChallengeMutation,
  FindingCategory,
  ImpactLevel,
  RequestMutation,
} from "./state.ts";
import type { AllowedRequest, DeniedRequest, ScopedTarget } from "./scoped-target.ts";
import type { ActorId } from "./sessions.ts";
import type { AttackSurfaceOrigin } from "./attack-surface.ts";
import type { RuntimeSafetyPolicy } from "./runtime-safety.ts";
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
  category: "cross-site-scripting";
  workflow: "stored" | "dom";
  endpoint: string;
  method: string;
  effect: "dialog";
  markerPattern: string;
  pagePath: string;
  payloadTemplate: string;
  challenge: BrowserChallengeMutation;
  submissionActorId: ActorId;
  pageActorId: ActorId;
  pageChallenge?: BrowserChallengeMutation;
  requestBudget: number;
}

export interface OastProofPolicy extends ProofPolicyRule {
  kind: "oast";
  category: "server-side-request-forgery";
  protocol: "http";
  endpoint: string;
  method: string;
  challenge: ChallengeMutation;
}

export interface FileContentProofPolicy extends ProofPolicyRule {
  kind: "file-content";
  category: "path-traversal";
  endpoint: string;
  method: string;
  request: Pick<RequestMutation, "location" | "parameter"> & { value: string };
  source: "immutable-fixture";
  contentTypePattern: string;
  verify: (content: string) => boolean;
}

export interface RedirectProofPolicy extends ProofPolicyRule {
  kind: "redirect";
  category: "open-redirect";
  endpoint: string;
  method: string;
  challenge: ChallengeMutation;
  destination: string;
}

export interface BrowserStateTransitionProofPolicy extends ProofPolicyRule {
  kind: "browser-state-transition";
  category: "cross-site-request-forgery";
  endpoint: string;
  method: "POST";
  sourceOrigin: string;
  sourcePath: string;
  pageActorId: ActorId;
  requestBudget: number;
  readEndpoint: string;
  readMethod: "GET" | "HEAD";
  jsonPointer: string;
  before: ProofScalar;
  after: ProofScalar;
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
  | BrowserStateTransitionProofPolicy
  | FileContentProofPolicy
  | RedirectProofPolicy
  | OastProofPolicy
  | SqlSemanticDifferentialProofPolicy
  | CommandExecutionChallengeProofPolicy;

export interface TargetProfile {
  id: string;
  displayName: string;
  objective: string;
  /** Extra browser discovery origins, each explicitly active or passive. */
  attackSurfaceOrigins?: AttackSurfaceOrigin[];
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
  /** Campaign-wide request admission, circuit-breaker, and testing-window policy. */
  runtimeSafety?: Partial<RuntimeSafetyPolicy>;
  /** Declarative source used by bundled and external target adapters. */
  manifest?: TargetManifest;
  protectedOperations?: ProtectedOperationManifest[];
  /**
   * Opaque, non-secret binding for values closed over by profile callbacks. Change it whenever
   * authentication, reset, or proof-verification callback configuration changes.
   */
  callbackConfigurationFingerprint?: string;
}

export type TargetProfileExtensions = Pick<
  TargetProfile,
  | "attackSurfaceOrigins"
  | "proofPolicies"
  | "prepareValidation"
  | "validationResetRequestBudget"
  | "runtimeSafety"
  | "callbackConfigurationFingerprint"
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
  const extensionCallbacks = containsFunction(extensions);
  const callbackConfigurationFingerprint =
    extensions.callbackConfigurationFingerprint ??
    (extensionCallbacks ? undefined : `manifest-derived:${manifest.schemaVersion}`);
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
    ...(callbackConfigurationFingerprint ? { callbackConfigurationFingerprint } : {}),
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
  if (
    profile.callbackConfigurationFingerprint !== undefined &&
    profile.callbackConfigurationFingerprint.trim().length === 0
  ) {
    throw new Error("callbackConfigurationFingerprint must not be empty");
  }
  for (const policy of profile.proofPolicies ?? []) {
    validateProofPolicy(policy, profile);
  }
}

function containsFunction(value: unknown, seen = new Set<object>()): boolean {
  if (typeof value === "function") return true;
  if (!value || typeof value !== "object" || seen.has(value)) return false;
  seen.add(value);
  return Array.isArray(value)
    ? value.some((entry) => containsFunction(entry, seen))
    : Object.values(value).some((entry) => containsFunction(entry, seen));
}

type ProofPolicyValidator<K extends ProofPolicy["kind"]> = (
  policy: Extract<ProofPolicy, { kind: K }>,
  profile: TargetProfile,
) => void;

type ProofPolicyValidators = {
  [K in ProofPolicy["kind"]]: ProofPolicyValidator<K>;
};

const proofPolicyValidators = {
  canary: () => undefined,
  "state-transition": (policy) => {
    if (
      !["POST", "PUT", "PATCH"].includes(policy.method) ||
      !["GET", "HEAD"].includes(policy.readMethod)
    ) {
      throw new Error(
        `State-transition policy ${policy.id} must use POST/PUT/PATCH with a GET/HEAD state read`,
      );
    }
  },
  "browser-effect": (policy) => {
    if (
      !Number.isInteger(policy.requestBudget) ||
      policy.requestBudget < 1 ||
      policy.requestBudget > 20
    ) {
      throw new Error(`Browser-effect policy ${policy.id} requestBudget must be from 1 to 20`);
    }
    if (
      policy.challenge.template !== policy.payloadTemplate ||
      policy.challenge.template.split("{{challenge}}").length !== 2
    ) {
      throw new Error(
        `Browser-effect policy ${policy.id} challenge must use its payloadTemplate once`,
      );
    }
    if (
      (policy.workflow === "stored" &&
        (!["POST", "PUT", "PATCH"].includes(policy.method) ||
          policy.challenge.location === "fragment" ||
          policy.pageChallenge !== undefined)) ||
      (policy.workflow === "dom" &&
        (policy.method !== "GET" ||
          policy.challenge.location !== "fragment" ||
          policy.pageChallenge?.location !== "fragment"))
    ) {
      throw new Error(
        `Browser-effect policy ${policy.id} must declare a closed stored or fragment-only DOM workflow`,
      );
    }
    if (
      policy.pageChallenge &&
      (!["query", "fragment"].includes(policy.pageChallenge.location) ||
        !sameChallenge(policy.challenge, policy.pageChallenge) ||
        policy.pageChallenge.template.split("{{challenge}}").length !== 2 ||
        browserChallengeValues(policy.pagePath, policy.pageChallenge).length !== 1)
    ) {
      throw new Error(
        `Browser-effect policy ${policy.id} pageChallenge must replace one declared URL parameter`,
      );
    }
  },
  "browser-state-transition": (policy, profile) => {
    if (
      !Number.isInteger(policy.requestBudget) ||
      policy.requestBudget < 2 ||
      policy.requestBudget > 20 ||
      policy.method !== "POST" ||
      !["GET", "HEAD"].includes(policy.readMethod) ||
      !profile.prepareValidation ||
      !Number.isInteger(profile.validationResetRequestBudget) ||
      policy.pageActorId === "anonymous" ||
      !isExactOrigin(policy.sourceOrigin) ||
      !isOriginRelativePath(policy.sourcePath) ||
      !profile.attackSurfaceOrigins?.some(
        ({ origin, scope }) =>
          new URL(origin).origin === policy.sourceOrigin && scope === "visit-only",
      )
    ) {
      throw new Error(
        `Browser-state-transition policy ${policy.id} requires an authenticated configured visit-only origin, a fresh-state reset hook, and a request budget from 2 to 20`,
      );
    }
  },
  "file-content": (policy) => {
    if (
      policy.request.value.length === 0 ||
      (policy.request.location === "json-body" &&
        !["POST", "PUT", "PATCH"].includes(policy.method)) ||
      safePolicyRegex(policy.contentTypePattern) === undefined
    ) {
      throw new Error(
        `File-content policy ${policy.id} must declare a valid request and media type`,
      );
    }
  },
  redirect: (policy) => {
    if (
      policy.challenge.template.split("{{challenge}}").length !== 2 ||
      !isAbsoluteHttpUrl(policy.destination)
    ) {
      throw new Error(
        `Redirect policy ${policy.id} must bind one absolute HTTP(S) destination challenge`,
      );
    }
  },
  oast: (policy) => {
    if (policy.challenge.template.split("{{challenge}}").length !== 2) {
      throw new Error(`OAST policy ${policy.id} challenge must substitute the callback once`);
    }
  },
  "sql-semantic-differential": (policy) => {
    if (
      policy.mutation.controlValue === policy.mutation.probeValue ||
      Object.is(policy.response.controlValue, policy.response.probeValue)
    ) {
      throw new Error(
        `SQL semantic-differential policy ${policy.id} must use distinct request and response values`,
      );
    }
  },
  "command-execution-challenge": (policy) => {
    if (
      policy.challenge.template.split("{{challenge}}").length !== 2 ||
      !Number.isSafeInteger(policy.multiplier) ||
      policy.multiplier === 0 ||
      !Number.isSafeInteger(policy.addend) ||
      !Number.isSafeInteger(policy.challengeMinimum) ||
      !Number.isSafeInteger(policy.challengeMaximum) ||
      policy.challengeMinimum < 1 ||
      policy.challengeMinimum >= policy.challengeMaximum ||
      !Number.isSafeInteger(policy.challengeMinimum * policy.multiplier + policy.addend) ||
      !Number.isSafeInteger(policy.challengeMaximum * policy.multiplier + policy.addend) ||
      policy.outputPrefix.length === 0
    ) {
      throw new Error(
        `Command-execution policy ${policy.id} must declare one bounded arithmetic challenge`,
      );
    }
  },
} satisfies ProofPolicyValidators;

function validateProofPolicy<K extends ProofPolicy["kind"]>(
  policy: Extract<ProofPolicy, { kind: K }>,
  profile: TargetProfile,
): void {
  const validator = proofPolicyValidators[policy.kind] as ProofPolicyValidator<K>;
  validator(policy, profile);
}

function sameChallenge(left: BrowserChallengeMutation, right: BrowserChallengeMutation): boolean {
  return (
    left.location === right.location &&
    left.parameter === right.parameter &&
    left.template === right.template
  );
}

export function browserPolicyPath(policy: BrowserEffectProofPolicy, marker: string): string {
  if (!policy.pageChallenge) return policy.pagePath;
  if (
    !["query", "fragment"].includes(policy.pageChallenge.location) ||
    policy.pageChallenge.template.split("{{challenge}}").length !== 2
  ) {
    throw new Error("Browser page challenge must be one URL substitution");
  }
  const url = new URL(policy.pagePath, "http://browser-policy.invalid");
  if (browserChallengeValues(policy.pagePath, policy.pageChallenge).length !== 1) {
    throw new Error("Browser policy pagePath must contain its challenge URL parameter once");
  }
  setBrowserChallenge(
    url,
    policy.pageChallenge,
    policy.pageChallenge.template.replace("{{challenge}}", marker),
  );
  return `${url.pathname}${url.search}${url.hash}`;
}

function browserChallengeValues(path: string, challenge: BrowserChallengeMutation): string[] {
  const url = new URL(path, "http://browser-policy.invalid");
  if (challenge.location === "query") return url.searchParams.getAll(challenge.parameter);
  if (challenge.location !== "fragment") return [];
  return new URLSearchParams(url.hash.slice(1)).getAll(challenge.parameter);
}

function setBrowserChallenge(url: URL, challenge: BrowserChallengeMutation, value: string): void {
  if (challenge.location === "query") {
    url.searchParams.set(challenge.parameter, value);
    return;
  }
  const fragment = new URLSearchParams(url.hash.slice(1));
  fragment.set(challenge.parameter, value);
  url.hash = fragment.toString();
}

function safePolicyRegex(pattern: string): RegExp | undefined {
  if (pattern.length > 256) return undefined;
  try {
    return new RegExp(pattern, "i");
  } catch {
    return undefined;
  }
}

function isAbsoluteHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && url.href === value;
  } catch {
    return false;
  }
}

function isExactOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && `${url.origin}` === value;
  } catch {
    return false;
  }
}

function isOriginRelativePath(value: string): boolean {
  return value.startsWith("/") && !value.startsWith("//");
}
