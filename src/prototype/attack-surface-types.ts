import type { Browser, BrowserContext } from "playwright-core";
import type { RuntimeRequestLease } from "./runtime-safety.ts";

export type AttackSurfaceScope = "attackable" | "visit-only" | "auth-only" | "blocked";

export interface AttackSurfaceOrigin {
  origin: string;
  scope: AttackSurfaceScope;
}

export interface AttackSurfaceDocument {
  path: string;
  status: number;
  contentType: string;
  truncated: boolean;
  origin?: string;
  scope?: AttackSurfaceScope;
}

export interface AttackSurfaceCallSite {
  documentPath: string;
  method: string;
  authentication: "likely" | "unknown";
  allowed?: boolean;
  blockedReason?: string;
}

export interface AttackSurfaceIdentifierSource {
  parameter: string;
  sourcePath: string;
}

export interface AttackSurfaceRequestBody {
  contentType: string;
  source: "browser" | "form" | "openapi";
  example?: unknown;
  fields?: string[];
  files?: Array<{ field: string; fileName?: string }>;
}

export interface AttackSurfaceGraphqlOperation {
  type: "query" | "mutation" | "subscription";
  name?: string;
  rootFields: string[];
}

export interface AttackSurfaceForm {
  index: number;
  documentPath: string;
  action: string;
  method: string;
  intent: string;
  fields: Array<{ name: string; type: string; valueSource: string }>;
  fileFields: string[];
  attempted: boolean;
  submitted: boolean;
}

export interface AttackSurfaceWebSocket {
  url: string;
  origin: string;
  path: string;
  scope: AttackSurfaceScope;
  documentPath: string;
  sentFrames: number;
  receivedFrames: number;
  sentBytes: number;
  receivedBytes: number;
}

export interface AttackSurfaceRouteDetail {
  path: string;
  methods: string[];
  sources: string[];
  examples: string[];
  callSites: AttackSurfaceCallSite[];
  /** @deprecated Use callSites. */
  getCallSites: AttackSurfaceCallSite[];
  identifierSources: AttackSurfaceIdentifierSource[];
  origin?: string;
  scope?: AttackSurfaceScope;
  requestBodies?: AttackSurfaceRequestBody[];
  graphqlOperations?: AttackSurfaceGraphqlOperation[];
  summary?: string;
}

export interface AttackSurfaceMap {
  startPath: string;
  documents: AttackSurfaceDocument[];
  routes: string[];
  routeDetails: AttackSurfaceRouteDetail[];
  forms?: AttackSurfaceForm[];
  webSockets?: AttackSurfaceWebSocket[];
}

export interface BrowserRequestDecision {
  allowed: boolean;
  reason?: string;
}

export interface BrowserRequestMetadata {
  budgeted: boolean;
  automaticInteraction?: boolean;
  origin?: string;
  scope?: AttackSurfaceScope;
  resourceType?: string;
  passiveVisitOnly?: boolean;
}

export type BrowserCookie = Parameters<BrowserContext["addCookies"]>[0][number];

export interface BrowserAttackSurfaceMapperOptions {
  origin: string;
  startPath: string;
  maxDocuments: number;
  timeoutMs: number;
  /** Additional exact origins. Visit-only origins load passive GETs but are never exercised. */
  origins?: AttackSurfaceOrigin[];
  authenticationHeaders?: Record<string, string>;
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
  cookies?: BrowserCookie[];
  openApi?: unknown;
  decideRequest: (
    method: string,
    path: string,
    metadata?: BrowserRequestMetadata,
  ) => BrowserRequestDecision;
  commitRequest?: (
    method: string,
    path: string,
    metadata?: BrowserRequestMetadata,
  ) => BrowserRequestDecision;
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
  acquireRequest?: () => Promise<RuntimeRequestLease>;
  executablePath?: string;
  launch?: (executablePath: string) => Promise<Browser>;
}
