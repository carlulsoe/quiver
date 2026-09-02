import type { BrowserCookie } from "./attack-surface.ts";
import type { AllowedRequest, DeniedRequest, RestMethod } from "./scoped-target.ts";
import type { ActorId } from "./sessions.ts";
import type { ImpactLevel } from "./state.ts";

export type IdentityRole = "anonymous" | "user" | "administrator";

export interface ManifestEnvironmentValue {
  env: string;
  default?: string;
}

export type ManifestScalar = string | number | boolean | null | ManifestEnvironmentValue;
export type ManifestJson = ManifestScalar | ManifestJson[] | { [key: string]: ManifestJson };

export interface AuthenticationRequestManifest {
  method: RestMethod;
  path: string;
  headers?: Record<string, ManifestScalar>;
  body?: ManifestJson;
}

export type CredentialSource =
  | { location: "body"; pointer: string }
  | { location: "header"; name: string }
  | { location: "cookie"; name: string }
  | { location: "literal"; value: ManifestScalar };

export interface AuthenticationExchangeManifest {
  request: AuthenticationRequestManifest;
  credential: CredentialSource;
  refreshCredential?: CredentialSource;
  expectedStatuses?: readonly number[];
  /** Fixed lifetime used to decide when to refresh or reauthenticate. */
  expiresAfterMs?: number;
}

interface RefreshableSessionAdapterManifest {
  login?: AuthenticationExchangeManifest;
  /** Static credentials are useful for synthetic fixtures and API keys. */
  credential?: CredentialSource;
  refresh?: AuthenticationExchangeManifest;
  /** Refresh this long before expiry. Defaults to zero. */
  refreshBeforeMs?: number;
}

export interface HeaderTokenSessionAdapterManifest extends RefreshableSessionAdapterManifest {
  kind: "header-token";
  headerName?: string;
  headerValue?: string;
}

export interface CookieSessionAdapterManifest extends RefreshableSessionAdapterManifest {
  kind: "cookie";
  cookie: Omit<BrowserCookie, "name" | "value"> & { name: string };
}

export interface BrowserSessionTemplate {
  headers?: Record<string, string>;
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
  cookies?: ReadonlyArray<Omit<BrowserCookie, "value"> & { value: string }>;
}

export interface BrowserLoginSessionAdapterManifest extends RefreshableSessionAdapterManifest {
  kind: "browser-login";
  session: BrowserSessionTemplate;
}

export type SessionAdapterManifest =
  | HeaderTokenSessionAdapterManifest
  | CookieSessionAdapterManifest
  | BrowserLoginSessionAdapterManifest;

export interface TargetIdentityManifest {
  id: ActorId;
  label: string;
  role: IdentityRole;
  authentication?: SessionAdapterManifest;
}

export interface ProtectedOperationManifest {
  method: RestMethod;
  path: string;
  authorizedActors: readonly ActorId[];
  description?: string;
}

export interface TargetScopeManifest {
  setupOperations?: readonly AllowedRequest[];
  deniedOperations?: readonly DeniedRequest[];
  protectedOperations?: readonly ProtectedOperationManifest[];
  maximumImpactLevel?: ImpactLevel;
}

export interface ReproductionAuthenticationManifest {
  description: string;
  commands: string[];
  actors?: Record<string, { description: string; commands: string[] }>;
}

export interface TargetManifest {
  schemaVersion: 1;
  id: string;
  displayName: string;
  objective: string;
  scope: TargetScopeManifest;
  identities: readonly TargetIdentityManifest[];
  authenticationContext?: string;
  reproductionAuthentication?: ReproductionAuthenticationManifest;
}

export interface CredentialContext {
  credential: string;
  refreshCredential?: string;
}

export interface MaterializedCredentials extends CredentialContext {
  expiresAt?: number;
}
