import type { ChallengeMutation, FindingCategory, ImpactLevel } from "./state.ts";
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
  /** Exact scoped-request cost of one prepareValidation call. */
  validationResetRequestBudget?: number;
  /** Hard ceiling for code-derived proof impact. Defaults to observation. */
  maximumImpactLevel?: ImpactLevel;
}

export function assertValidTargetProfile(profile: TargetProfile): void {
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
    if (
      policy.kind === "browser-effect" &&
      policy.pageChallenge &&
      (policy.pageChallenge.location !== "query" ||
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
