import type { Request } from "playwright-core";
import { normalizeAttackSurfaceOrigins } from "./discovery/openapi.ts";
import type { RuntimeRequestLease } from "./runtime-safety.ts";
import type {
  AttackSurfaceCallSite,
  AttackSurfaceDocument,
  AttackSurfaceForm,
  AttackSurfaceGraphqlOperation,
  AttackSurfaceScope,
  AttackSurfaceWebSocket,
  BrowserAttackSurfaceMapperOptions,
} from "./attack-surface-types.ts";

export interface MutableRouteEvidence {
  origin: string;
  path: string;
  scope: AttackSurfaceScope;
  methods: Set<string>;
  sources: Set<string>;
  examples: Set<string>;
  callSites: AttackSurfaceCallSite[];
  requestBodies: import("./attack-surface-types.ts").AttackSurfaceRequestBody[];
  graphqlOperations: AttackSurfaceGraphqlOperation[];
  summary?: string;
}

export interface ActiveFormRequest {
  method: string;
  origin: string;
  pathname: string;
  allowed: boolean;
  observed: boolean;
  settle: () => void;
}

export interface AttackSurfaceState {
  readonly options: BrowserAttackSurfaceMapperOptions;
  readonly scopes: ReadonlyMap<string, AttackSurfaceScope>;
  readonly evidence: Map<string, MutableRouteEvidence>;
  readonly documents: Map<string, AttackSurfaceDocument>;
  readonly forms: AttackSurfaceForm[];
  readonly webSockets: AttackSurfaceWebSocket[];
  readonly requestLeases: Map<Request, RuntimeRequestLease>;
  automaticInteraction: boolean;
  activeFormRequest?: ActiveFormRequest;
}

export interface CurrentDocument {
  path: string;
  origin: string;
  scope: AttackSurfaceScope;
}

export function createAttackSurfaceState(
  options: BrowserAttackSurfaceMapperOptions,
): AttackSurfaceState {
  return {
    options,
    scopes: normalizeAttackSurfaceOrigins(options.origin, options.origins),
    evidence: new Map(),
    documents: new Map(),
    forms: [],
    webSockets: [],
    requestLeases: new Map(),
    automaticInteraction: false,
  };
}
