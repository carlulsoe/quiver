import type { BrowserCookie } from "./attack-surface.ts";
import type {
  AllowedRequest,
  DeniedRequest,
  RestMethod,
  ScopedTarget,
  SetupHttpObservation,
} from "./scoped-target.ts";
import { actorIds, type ActorId, type StoredSession } from "./sessions.ts";
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

interface CredentialContext {
  credential: string;
  refreshCredential?: string;
}

interface MaterializedCredentials extends CredentialContext {
  expiresAt?: number;
}

export function manifestActorIds(manifest: TargetManifest): ActorId[] {
  return manifest.identities
    .map(({ id }) => id)
    .filter((actorId) => actorId !== actorIds.anonymous);
}

export function assertValidTargetManifest(manifest: TargetManifest): void {
  if (manifest.schemaVersion !== 1) throw new Error("Target manifests must use schemaVersion 1");
  const identities = new Map<ActorId, TargetIdentityManifest>();
  for (const identity of manifest.identities) {
    if (identities.has(identity.id)) {
      throw new Error(
        `Target manifest ${manifest.id} declares actor ${identity.id} more than once`,
      );
    }
    identities.set(identity.id, identity);
    if (identity.role === "anonymous" && identity.id !== actorIds.anonymous) {
      throw new Error("The anonymous identity must use the anonymous actor ID");
    }
    if (
      identity.id === actorIds.anonymous &&
      (identity.role !== "anonymous" || identity.authentication)
    ) {
      throw new Error("The anonymous actor cannot declare authentication");
    }
    if (identity.id !== actorIds.anonymous && !identity.authentication) {
      throw new Error(`Actor ${identity.id} must declare a session adapter`);
    }
    if (identity.authentication) assertValidSessionAdapter(identity.id, identity.authentication);
  }
  if (!identities.has(actorIds.anonymous)) {
    throw new Error(`Target manifest ${manifest.id} must declare the anonymous actor`);
  }
  for (const operation of manifest.scope.protectedOperations ?? []) {
    if (operation.authorizedActors.length === 0) {
      throw new Error(
        `Protected operation ${operation.method} ${operation.path} has no authorized actors`,
      );
    }
    for (const actorId of operation.authorizedActors) {
      if (!identities.has(actorId)) {
        throw new Error(
          `Protected operation ${operation.method} ${operation.path} references unknown actor ${actorId}`,
        );
      }
    }
  }
  const setupOperations = new Set(
    (manifest.scope.setupOperations ?? []).map(({ method, path }) => `${method} ${path}`),
  );
  for (const identity of manifest.identities) {
    const authentication = identity.authentication;
    if (!authentication) continue;
    for (const exchange of [authentication.login, authentication.refresh].filter(
      (candidate): candidate is AuthenticationExchangeManifest => candidate !== undefined,
    )) {
      const key = `${exchange.request.method} ${exchange.request.path}`;
      if (!setupOperations.has(key)) {
        throw new Error(
          `Authentication operation ${key} must be declared in scope.setupOperations`,
        );
      }
    }
  }
}

export async function authenticateTargetManifest(
  target: ScopedTarget,
  manifest: TargetManifest,
  options: { now?: () => number; actorIds?: readonly ActorId[] } = {},
): Promise<{ authContext: string }> {
  assertValidTargetManifest(manifest);
  const requestedActors = options.actorIds ? new Set(options.actorIds) : undefined;
  const authenticated = manifest.identities.filter(
    (identity): identity is TargetIdentityManifest & { authentication: SessionAdapterManifest } =>
      identity.authentication !== undefined &&
      (!requestedActors || requestedActors.has(identity.id)),
  );
  const resolvedActors = new Set(authenticated.map(({ id }) => id));
  const unknownActors = [...(requestedActors ?? [])].filter(
    (actorId) => actorId !== actorIds.anonymous && !resolvedActors.has(actorId),
  );
  if (unknownActors.length > 0) {
    throw new Error(
      `Target manifest ${manifest.id} has no authentication for ${unknownActors.join(", ")}`,
    );
  }
  for (const identity of authenticated) {
    target.setSessionProvider(
      identity.id,
      createSessionProvider(target, identity, options.now ?? Date.now),
    );
  }
  // Fail setup early and deterministically instead of discovering a bad principal mid-campaign.
  for (const identity of authenticated) await target.sessions.acquire(identity.id);
  return {
    authContext: manifest.authenticationContext ?? authenticated.map(({ id }) => id).join(","),
  };
}

function assertValidSessionAdapter(actorId: ActorId, adapter: SessionAdapterManifest): void {
  if ((adapter.refreshBeforeMs ?? 0) < 0) {
    throw new Error(`Actor ${actorId} refreshBeforeMs must be non-negative`);
  }
  if (!adapter.login && !adapter.credential) {
    throw new Error(`Actor ${actorId} must declare login or credential`);
  }
  if (adapter.login && adapter.credential) {
    throw new Error(`Actor ${actorId} cannot declare both login and credential`);
  }
  if (adapter.credential && adapter.credential.location !== "literal") {
    throw new Error(`Actor ${actorId} static credential must use a literal source`);
  }
  if (adapter.refresh && !adapter.login?.refreshCredential) {
    throw new Error(`Actor ${actorId} needs a login refreshCredential when refresh is configured`);
  }
  for (const exchange of [adapter.login, adapter.refresh].filter(
    (candidate): candidate is AuthenticationExchangeManifest => candidate !== undefined,
  )) {
    if (exchange.request.path.includes("{{")) {
      throw new Error(`Actor ${actorId} authentication request paths must be static`);
    }
    if (exchange.expiresAfterMs !== undefined && exchange.expiresAfterMs <= 0) {
      throw new Error(`Actor ${actorId} expiresAfterMs must be positive`);
    }
    if (exchange.expectedStatuses?.length === 0) {
      throw new Error(`Actor ${actorId} expectedStatuses must not be empty`);
    }
  }
  if (adapter.kind === "browser-login" && Object.keys(adapter.session).length === 0) {
    throw new Error(`Actor ${actorId} browser-login session must declare browser material`);
  }
}

function createSessionProvider(
  target: ScopedTarget,
  identity: TargetIdentityManifest & { authentication: SessionAdapterManifest },
  now: () => number,
): () => Promise<StoredSession> {
  const adapter = identity.authentication;
  let credentials: MaterializedCredentials | undefined;
  let pending: Promise<StoredSession> | undefined;
  return async () => {
    if (credentials && !isExpiring(credentials, adapter.refreshBeforeMs ?? 0, now())) {
      return materializeSession(adapter, credentials, target.origin);
    }
    pending ??= (async () => {
      const exchange = credentials && adapter.refresh ? adapter.refresh : adapter.login;
      const next = exchange
        ? await runExchange(target, identity, exchange, credentials, now())
        : staticCredentials(adapter.credential!);
      credentials = {
        ...next,
        refreshCredential: next.refreshCredential ?? credentials?.refreshCredential,
      };
      return materializeSession(adapter, credentials, target.origin);
    })().finally(() => {
      pending = undefined;
    });
    return pending;
  };
}

function staticCredentials(source: CredentialSource): MaterializedCredentials {
  if (source.location !== "literal") throw new Error("Static credentials must be literal");
  const credential = resolveManifestValue(source.value, { credential: "" });
  if (typeof credential !== "string" || credential.length === 0) {
    throw new Error("Static authentication credential did not resolve to a non-empty string");
  }
  return { credential };
}

function isExpiring(
  credentials: MaterializedCredentials,
  refreshBeforeMs: number,
  now: number,
): boolean {
  return credentials.expiresAt !== undefined && now >= credentials.expiresAt - refreshBeforeMs;
}

async function runExchange(
  target: ScopedTarget,
  identity: TargetIdentityManifest,
  exchange: AuthenticationExchangeManifest,
  previous: MaterializedCredentials | undefined,
  now: number,
): Promise<MaterializedCredentials> {
  const context: CredentialContext = previous ?? { credential: "" };
  const observation = await target.setupRequest({
    method: exchange.request.method,
    path: exchange.request.path,
    headers: exchange.request.headers
      ? Object.fromEntries(
          Object.entries(exchange.request.headers).map(([name, value]) => [
            name,
            String(resolveManifestValue(value, context)),
          ]),
        )
      : undefined,
    body:
      exchange.request.body === undefined
        ? undefined
        : JSON.stringify(resolveManifestJson(exchange.request.body, context)),
  });
  const expectedStatuses = exchange.expectedStatuses ?? [200, 201, 204];
  if (!expectedStatuses.includes(observation.status)) {
    throw new Error(
      `${identity.label} authentication failed with status ${observation.status}; expected ${expectedStatuses.join(", ")}`,
    );
  }
  return {
    credential: readCredential(exchange.credential, observation, context),
    ...(exchange.refreshCredential
      ? { refreshCredential: readCredential(exchange.refreshCredential, observation, context) }
      : {}),
    ...(exchange.expiresAfterMs === undefined ? {} : { expiresAt: now + exchange.expiresAfterMs }),
  };
}

function readCredential(
  source: CredentialSource,
  observation: SetupHttpObservation,
  context: CredentialContext,
): string {
  let value: unknown;
  if (source.location === "header") value = observation.headers[source.name.toLowerCase()];
  else if (source.location === "cookie") {
    value = readResponseCookie(observation.headers["set-cookie"], source.name);
  } else if (source.location === "literal") value = resolveManifestValue(source.value, context);
  else value = readJsonPointer(observation.body, source.pointer);
  if (typeof value !== "string" || value.length === 0) {
    const location = source.location === "body" ? source.pointer : source.location;
    throw new Error(`Authentication credential ${location} did not resolve to a non-empty string`);
  }
  return value;
}

function readResponseCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?:^|,\\s*)${escapedName}=([^;,]*)`).exec(header)?.[1];
}

function materializeSession(
  adapter: SessionAdapterManifest,
  credentials: MaterializedCredentials,
  origin: string,
): StoredSession {
  if (adapter.kind === "header-token") {
    return {
      headers: {
        [adapter.headerName ?? "authorization"]: renderTemplate(
          adapter.headerValue ?? "Bearer {{credential}}",
          credentials,
        ),
      },
    };
  }
  if (adapter.kind === "cookie") {
    return {
      browserState: {
        cookies: [materializeCookie(adapter.cookie, credentials.credential, origin)],
      },
    };
  }
  return {
    headers: renderRecord(adapter.session.headers, credentials),
    browserState: {
      localStorage: renderRecord(adapter.session.localStorage, credentials),
      sessionStorage: renderRecord(adapter.session.sessionStorage, credentials),
      cookies: adapter.session.cookies?.map((cookie) =>
        materializeCookie(cookie, renderTemplate(cookie.value, credentials), origin),
      ),
    },
  };
}

function materializeCookie(
  cookie: Omit<BrowserCookie, "value">,
  value: string,
  origin: string,
): BrowserCookie {
  if (/[;\r\n]/.test(value)) throw new Error("Cookie credentials may not contain separators");
  if (("url" in cookie && cookie.url) || ("domain" in cookie && cookie.domain)) {
    return { ...cookie, value } as BrowserCookie;
  }
  const target = new URL(origin);
  return {
    ...cookie,
    name: cookie.name,
    value,
    domain: target.hostname,
    path: cookie.path ?? "/",
    secure: cookie.secure ?? target.protocol === "https:",
  } as BrowserCookie;
}

function renderRecord(
  values: Record<string, string> | undefined,
  context: CredentialContext,
): Record<string, string> | undefined {
  return values
    ? Object.fromEntries(
        Object.entries(values).map(([name, value]) => [name, renderTemplate(value, context)]),
      )
    : undefined;
}

function resolveManifestJson(value: ManifestJson, context: CredentialContext): unknown {
  if (Array.isArray(value)) return value.map((entry) => resolveManifestJson(entry, context));
  if (isEnvironmentValue(value)) return resolveManifestValue(value, context);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, resolveManifestJson(entry, context)]),
    );
  }
  return typeof value === "string" ? renderTemplate(value, context) : value;
}

function resolveManifestValue(
  value: ManifestScalar,
  context: CredentialContext,
): string | number | boolean | null {
  if (!isEnvironmentValue(value)) {
    return typeof value === "string" ? renderTemplate(value, context) : value;
  }
  const resolved = process.env[value.env] ?? value.default;
  if (resolved === undefined)
    throw new Error(`Required environment variable ${value.env} is not set`);
  return resolved;
}

function isEnvironmentValue(value: unknown): value is ManifestEnvironmentValue {
  return !!value && typeof value === "object" && !Array.isArray(value) && "env" in value;
}

function renderTemplate(value: string, context: CredentialContext): string {
  return value
    .replaceAll("{{credential}}", context.credential)
    .replaceAll("{{refreshCredential}}", context.refreshCredential ?? "")
    .replace(
      /\{\{env:([A-Z_][A-Z0-9_]*)(?:\|([^}]*))?\}\}/g,
      (_match, name: string, fallback: string | undefined) => {
        const resolved = process.env[name] ?? fallback;
        if (resolved === undefined)
          throw new Error(`Required environment variable ${name} is not set`);
        return resolved;
      },
    );
}

function readJsonPointer(value: unknown, pointer: string): unknown {
  if (pointer === "") return value;
  if (!pointer.startsWith("/")) throw new Error(`Invalid JSON pointer ${pointer}`);
  return pointer
    .slice(1)
    .split("/")
    .map((segment) => segment.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce<unknown>((current, segment) => {
      if (!current || typeof current !== "object") return undefined;
      return (current as Record<string, unknown>)[segment];
    }, value);
}
