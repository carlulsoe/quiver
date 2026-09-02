import type {
  AttackSurfaceDocument,
  AttackSurfaceMap,
  AttackSurfaceOrigin,
  AttackSurfaceScope,
  BrowserCookie,
  BrowserRequestMetadata,
} from "./attack-surface.ts";
import type { BrowserProofProbe, BrowserStateTransitionProbe } from "./browser-proof.ts";
import type {
  BrowserEffectEvidence,
  BrowserStateTransitionEvidence,
  ImpactLevel,
} from "./state.ts";
import type { RuntimeRequestLease, RuntimeSafetyController } from "./runtime-safety.ts";
import type { ActorId, Sessions } from "./sessions.ts";

export type HttpTransport = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export interface HttpObservation {
  method?: RestMethod;
  status: number;
  path: string;
  body: unknown;
  truncated?: boolean;
  contentType?: string;
  redirectLocation?: string;
  redirected?: boolean;
  durationMs?: number;
}

export interface SetupHttpObservation extends HttpObservation {
  headers: Record<string, string>;
}

export interface TargetRequestEvent {
  number: number;
  method: string;
  path: string;
  /** True for repeatable profile authentication/reset traffic, not proof reproduction. */
  setup: boolean;
}

export interface AllowedRequest {
  method: RestMethod;
  path: string;
}

export interface DeniedRequest {
  method: RestMethod;
  path: string;
}

export interface ScopedTargetOptions {
  target: URL;
  requestBudget: number;
  allowedRequests?: AllowedRequest[];
  /** Operations reserved for trusted profile/session setup. Defaults to allowedRequests. */
  setupRequests?: AllowedRequest[];
  deniedRequests?: DeniedRequest[];
  onRequest?: (request: TargetRequestEvent) => void;
  transport?: HttpTransport;
  timeoutMs?: number;
  maxResponseChars?: number;
  openApi?: unknown;
  attackSurfaceOrigins?: AttackSurfaceOrigin[];
  browserExecutablePath?: string;
  attackSurfaceMapper?: (options: AttackSurfaceMapperOptions) => Promise<AttackSurfaceMap>;
  browserEffectCollector?: (probe: BrowserProofProbe) => Promise<BrowserEffectEvidence | undefined>;
  browserStateTransitionCollector?: (
    probe: BrowserStateTransitionProbe,
  ) => Promise<BrowserStateTransitionEvidence | undefined>;
  maximumImpactLevel?: ImpactLevel;
  /** Shared campaign request scheduler. Use one instance across exploration and validation. */
  runtimeSafety?: RuntimeSafetyController;
  sessions?: Sessions;
  browserActorId?: ActorId;
}

export interface AttackSurfaceMapperOptions {
  origin: string;
  startPath: string;
  maxDocuments: number;
  timeoutMs: number;
  authenticationHeaders?: Record<string, string>;
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
  cookies?: BrowserCookie[];
  openApi?: unknown;
  origins?: AttackSurfaceOrigin[];
  decideRequest: (
    method: string,
    path: string,
    metadata?: BrowserRequestMetadata,
  ) => { allowed: boolean; reason?: string };
  commitRequest?: (
    method: string,
    path: string,
    metadata?: BrowserRequestMetadata,
  ) => { allowed: boolean; reason?: string };
  onOperationDiscovered?: (
    method: string,
    path: string,
    source: "browser" | "openapi",
    metadata?: {
      automaticInteraction: boolean;
      allowed?: boolean;
      blockedReason?: string;
      origin?: string;
      scope?: AttackSurfaceScope;
    },
  ) => void;
  executablePath?: string;
  acquireRequest?: () => Promise<RuntimeRequestLease>;
}

export interface ScopedRequest {
  path: string;
  method?: RestMethod;
  headers?: Record<string, string>;
  body?: string;
  actorId?: ActorId;
  sampleId?: string;
}

export interface BrowserEffectRequest {
  probeId: string;
  path: string;
  marker: string;
  kind: BrowserEffectEvidence["kind"];
  actorId: ActorId;
  requestBudget: number;
}

export interface BrowserStateTransitionRequest {
  policyId: string;
  sourceOrigin: string;
  sourcePath: string;
  targetPath: string;
  method: "POST";
  actorId: ActorId;
  requestBudget: number;
}

export type RestMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";

export type CrawlDocument = AttackSurfaceDocument;

export type CrawlMap = AttackSurfaceMap;
