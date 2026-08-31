import type { ChallengeMutation, FindingCategory } from "./state.ts";
import type { AllowedRequest, DeniedRequest, ScopedTarget } from "./scoped-target.ts";

export interface ReproductionAuthentication {
  description: string;
  commands: string[];
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
  readMethod: string;
}

export interface BrowserEffectProofPolicy extends ProofPolicyRule {
  kind: "browser-effect";
  effect: "dialog";
  markerPattern: string;
  pagePath: string;
  payloadTemplate: string;
  pageAuthenticated: boolean;
  pageChallenge?: ChallengeMutation;
  requestBudget: number;
}

export interface OastProofPolicy extends ProofPolicyRule {
  kind: "oast";
  protocol: "http";
  endpoint: string;
  method: string;
}

export type ProofPolicy =
  | CanaryProofPolicy
  | StateTransitionProofPolicy
  | BrowserEffectProofPolicy
  | OastProofPolicy;

export interface TargetProfile {
  id: string;
  displayName: string;
  objective: string;
  allowedRequests?: AllowedRequest[];
  deniedRequests?: DeniedRequest[];
  authenticate?: (target: ScopedTarget) => Promise<{ authContext: string }>;
  reproductionAuthentication?: ReproductionAuthentication;
  proofPolicies?: ProofPolicy[];
  prepareValidation?: (target: ScopedTarget) => Promise<void>;
}
