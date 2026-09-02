import type { RestMethod } from "./scoped-target.ts";
import type { ActorId } from "./sessions.ts";

export interface JsonEvidenceSelector {
  requestIndex: number;
  jsonPointer: string;
}
export interface RequestMutation {
  location: "query" | "json-body";
  parameter: string;
  controlValue: string;
  probeValue: string;
}
export interface ChallengeMutation {
  location: "query" | "json-body";
  parameter: string;
  template: string;
}
export interface BrowserChallengeMutation {
  location: "query" | "json-body" | "fragment";
  parameter: string;
  template: string;
}
export interface BrowserEffectEvidence {
  probeId: string;
  path: string;
  kind: "dialog";
  value: string;
}
export interface OastCallbackEvidence {
  probeId: string;
  token: string;
  protocol: "http";
  method: string;
  path: string;
  observedAt: string;
}
export interface BrowserStateTransitionEvidence {
  policyId: string;
  sourceOrigin: string;
  sourcePath: string;
  targetPath: string;
  method: string;
  status: number;
}
export interface ProofArtifacts {
  browserEffects: BrowserEffectEvidence[];
  browserStateTransitions: BrowserStateTransitionEvidence[];
  oastCallbacks: OastCallbackEvidence[];
}

export type ProofPredicate =
  | {
      type: "cross-principal-access";
      actor: JsonEvidenceSelector;
      resourceOwner: JsonEvidenceSelector;
      accessRequestIndex: number;
      evidencePointers: string[];
    }
  | {
      type: "authentication-bypass";
      authenticatedRequestIndex: number;
      anonymousRequestIndex: number;
      evidencePointers: string[];
    }
  | {
      type: "role-privilege-differential";
      authorizedRequestIndex: number;
      lessPrivilegedRequestIndex: number;
      evidencePointers: string[];
    }
  | { type: "unauthenticated-success"; requestIndex: number; evidencePointers: string[] }
  | {
      type: "cross-principal-data-exposure";
      actor: JsonEvidenceSelector;
      exposedSubject: JsonEvidenceSelector;
      responseRequestIndex: number;
      evidencePointers: string[];
    }
  | { type: "internal-field-exposure"; requestIndex: number; evidencePointers: string[] }
  | {
      type: "response-differential";
      controlRequestIndex: number;
      probeRequestIndex: number;
      comparison: "status" | "body" | "json-value";
      expectation: "equal" | "different";
      jsonPointer?: string;
      mutation: RequestMutation;
    }
  | {
      type: "timing-differential";
      controlRequestIndexes: number[];
      probeRequestIndexes: number[];
      minimumDeltaMs: number;
      mutation: RequestMutation;
    }
  | {
      type: "sql-semantic-differential";
      policyId: string;
      controlRequestIndex: number;
      probeRequestIndex: number;
    }
  | {
      type: "command-execution-challenge";
      policyId: string;
      requestIndex: number;
      challenge: number;
    }
  | { type: "canary-retrieval"; policyId: string; requestIndex: number; jsonPointer: string }
  | { type: "file-content-retrieval"; policyId: string; requestIndex: number }
  | { type: "redirect-destination"; policyId: string; requestIndex: number; destination: string }
  | {
      type: "state-transition";
      policyId: string;
      transitionRequestIndex: number;
      beforeRequestIndex: number;
      afterRequestIndex: number;
    }
  | {
      type: "browser-visible-effect";
      policyId: string;
      probeId: string;
      marker: string;
      requestIndex: number;
      pagePath: string;
      kind: "dialog";
      challenge: BrowserChallengeMutation;
      pageActorId: ActorId;
      pageChallenge?: BrowserChallengeMutation;
      collectorRequestBudget: number;
    }
  | {
      type: "browser-state-transition";
      policyId: string;
      beforeRequestIndex: number;
      afterRequestIndex: number;
      pageActorId: ActorId;
      collectorRequestBudget: number;
    }
  | {
      type: "oast-callback";
      policyId: string;
      probeId: string;
      token: string;
      requestIndex: number;
      callbackUrl: string;
      challenge: ChallengeMutation;
    };

export interface ProofCheck {
  description: string;
  passed: boolean;
  actual?: unknown;
}
export interface ProofResult {
  predicate: ProofPredicate["type"];
  classification?: "server-side-request-forgery" | "command-execution";
  passed: boolean;
  summary: string;
  checks: ProofCheck[];
}
export interface ValidationObservation {
  method?: RestMethod;
  status: number;
  path: string;
  actorId: ActorId;
  body: unknown;
  truncated: boolean;
  contentType?: string;
  redirectLocation?: string;
  redirected?: boolean;
  durationMs?: number;
  sampleId?: string;
}
