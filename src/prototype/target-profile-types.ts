import type { AttackSurfaceOrigin } from "./attack-surface.ts";
import type { RuntimeSafetyPolicy } from "./runtime-safety.ts";
import type { AllowedRequest, DeniedRequest, ScopedTarget } from "./scoped-target.ts";
import type { ActorId } from "./sessions.ts";
import type {
  BrowserChallengeMutation,
  ChallengeMutation,
  FindingCategory,
  ImpactLevel,
  RequestMutation,
} from "./state.ts";
import type { ProtectedOperationManifest, TargetManifest } from "./target-manifest.ts";

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
  method: string;
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
