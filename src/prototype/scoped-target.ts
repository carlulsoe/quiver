import {
  BrowserAttackSurfaceMapper,
  type AttackSurfaceDocument,
  type AttackSurfaceMap,
  type BrowserCookie,
} from "./attack-surface.ts";
import { collectBrowserEffect, type BrowserProofProbe } from "./browser-proof.ts";
import { impactAtMost } from "./impact.ts";
import type { BrowserEffectEvidence, ImpactLevel } from "./state.ts";
import {
  actorIds,
  InMemorySessions,
  type ActorId,
  type Sessions,
  type StoredSession,
} from "./sessions.ts";

export type {
  AttackSurfaceCallSite as CrawlGetCallSite,
  AttackSurfaceIdentifierSource as CrawlIdentifierSource,
  AttackSurfaceRouteDetail as CrawlRouteDetail,
} from "./attack-surface.ts";

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
  durationMs?: number;
}

export interface SetupHttpObservation extends HttpObservation {
  headers: Record<string, string>;
}

export interface TargetRequestEvent {
  number: number;
  method: string;
  path: string;
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
  deniedRequests?: DeniedRequest[];
  onRequest?: (request: TargetRequestEvent) => void;
  transport?: HttpTransport;
  timeoutMs?: number;
  maxResponseChars?: number;
  openApi?: unknown;
  browserExecutablePath?: string;
  attackSurfaceMapper?: (options: AttackSurfaceMapperOptions) => Promise<AttackSurfaceMap>;
  browserEffectCollector?: (probe: BrowserProofProbe) => Promise<BrowserEffectEvidence | undefined>;
  maximumImpactLevel?: ImpactLevel;
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
  decideRequest: (
    method: string,
    path: string,
    metadata?: { budgeted: boolean; automaticInteraction?: boolean },
  ) => { allowed: boolean; reason?: string };
  onOperationDiscovered?: (
    method: string,
    path: string,
    source: "browser" | "openapi",
    metadata?: { automaticInteraction: boolean },
  ) => void;
  executablePath?: string;
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

export type RestMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";

export type CrawlDocument = AttackSurfaceDocument;

export type CrawlMap = AttackSurfaceMap;

export class RequestBudgetExceededError extends Error {
  override readonly name = "RequestBudgetExceededError";
}

export class TargetScopeError extends Error {
  override readonly name = "TargetScopeError";
}

export class ScopedTarget {
  readonly #origin: string;
  readonly #startPath: string;
  #requestBudget: number;
  readonly #allowedRequests: Set<string>;
  readonly #browserAllowedOperations: Set<string>;
  readonly #mappedOperations = new Set<string>();
  readonly #deniedRequests: Set<string>;
  readonly #onRequest?: (request: TargetRequestEvent) => void;
  readonly #transport: HttpTransport;
  readonly #timeoutMs: number;
  readonly #maxResponseChars: number;
  readonly #openApi?: unknown;
  readonly #browserExecutablePath?: string;
  readonly #attackSurfaceMapper: (options: AttackSurfaceMapperOptions) => Promise<AttackSurfaceMap>;
  readonly #browserEffectCollector: (
    probe: BrowserProofProbe,
  ) => Promise<BrowserEffectEvidence | undefined>;
  readonly #maximumImpactLevel: ImpactLevel;
  readonly #sessions: Sessions;
  readonly #inMemorySessions?: InMemorySessions;
  #setupAccess = false;
  #requestsUsed = 0;
  #browserActorId: ActorId;
  #attackSurfaceResult?: Promise<AttackSurfaceMap>;

  constructor(options: ScopedTargetOptions) {
    const localHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
    if (
      !localHosts.has(options.target.hostname) ||
      !["http:", "https:"].includes(options.target.protocol)
    ) {
      throw new TargetScopeError("Only loopback HTTP(S) targets are allowed");
    }
    this.#origin = options.target.origin;
    this.#startPath = `${options.target.pathname}${options.target.search}`;
    this.#requestBudget = options.requestBudget;
    this.#allowedRequests = new Set(
      options.allowedRequests?.map(({ method, path }) => operationKey(method, path)) ?? [],
    );
    this.#browserAllowedOperations = new Set(this.#allowedRequests);
    this.#deniedRequests = new Set(
      options.deniedRequests?.map(({ method, path }) => `${method} ${path}`) ?? [],
    );
    this.#onRequest = options.onRequest;
    this.#transport = options.transport ?? fetch;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#maxResponseChars = options.maxResponseChars ?? 12_000;
    this.#openApi = options.openApi;
    this.#browserExecutablePath = options.browserExecutablePath;
    this.#attackSurfaceMapper =
      options.attackSurfaceMapper ??
      ((mapperOptions) => new BrowserAttackSurfaceMapper(mapperOptions).map());
    this.#browserEffectCollector = options.browserEffectCollector ?? collectBrowserEffect;
    this.#maximumImpactLevel = options.maximumImpactLevel ?? "state-change";
    this.#sessions = options.sessions ?? new InMemorySessions();
    this.#inMemorySessions =
      this.#sessions instanceof InMemorySessions ? this.#sessions : undefined;
    this.#browserActorId = options.browserActorId ?? actorIds.anonymous;
  }

  get origin(): string {
    return this.#origin;
  }

  get startPath(): string {
    return this.#startPath;
  }

  get sessions(): Sessions {
    return this.#sessions;
  }

  get requestsUsed(): number {
    return this.#requestsUsed;
  }

  get requestBudget(): number {
    return this.#requestBudget;
  }

  /** Adds coordinator-reclaimed capacity without resetting the target session. */
  extendRequestBudget(additionalRequests: number): void {
    if (!Number.isInteger(additionalRequests) || additionalRequests < 0) {
      throw new Error("Additional request budget must be a non-negative integer");
    }
    this.#requestBudget += additionalRequests;
  }

  /** Allows newly submitted reproduction operations on the long-lived validation target. */
  allowRequests(requests: readonly AllowedRequest[]): void {
    for (const { method, path } of requests) {
      const key = operationKey(method, path);
      this.#allowedRequests.add(key);
      this.#browserAllowedOperations.add(key);
    }
  }

  get remainingRequests(): number {
    return Math.max(0, this.#requestBudget - this.#requestsUsed);
  }

  assertImpactLevel(level: ImpactLevel): void {
    if (!impactAtMost(level, this.#maximumImpactLevel)) {
      throw new TargetScopeError(
        `${level} impact exceeds the target's ${this.#maximumImpactLevel} ceiling`,
      );
    }
  }

  async runProfileSetup<T>(setup: () => Promise<T>): Promise<T> {
    this.#setupAccess = true;
    try {
      return await setup();
    } finally {
      this.#setupAccess = false;
    }
  }

  setSession(actorId: ActorId, session: StoredSession): void {
    if (!this.#inMemorySessions) {
      throw new Error("Sessions are managed by the configured session adapter");
    }
    this.#inMemorySessions.set(actorId, session);
    if (this.#browserActorId === actorIds.anonymous && actorId !== actorIds.anonymous) {
      this.#browserActorId = actorId;
    }
  }

  async request(request: ScopedRequest): Promise<HttpObservation> {
    return (await this.#request(request, this.#maxResponseChars)) as HttpObservation;
  }

  async setupRequest(request: ScopedRequest): Promise<SetupHttpObservation> {
    const method = request.method ?? "GET";
    const url = this.#resolvePath(request.path);
    if (!operationAllowed(this.#allowedRequests, method, url.pathname)) {
      throw new TargetScopeError(
        `${method} ${url.pathname} is not an allowed profile setup request`,
      );
    }
    const observation = await this.#request(request, this.#maxResponseChars, true);
    return observation as SetupHttpObservation;
  }

  async observeBrowserEffect(
    request: BrowserEffectRequest,
  ): Promise<BrowserEffectEvidence | undefined> {
    this.assertImpactLevel("bounded");
    this.#resolvePath(request.path);
    const browserState = await this.#sessions.browserState(request.actorId);
    let collectorRequests = 0;
    return this.#browserEffectCollector({
      ...request,
      origin: this.#origin,
      timeoutMs: this.#timeoutMs,
      authenticationHeaders: browserState.headers,
      cookies: browserState.cookies,
      localStorage: browserState.localStorage,
      sessionStorage: browserState.sessionStorage,
      executablePath: this.#browserExecutablePath,
      decideRequest: (method, path) => {
        if (!["GET", "HEAD"].includes(method) || collectorRequests >= request.requestBudget) {
          return false;
        }
        const decision = this.#decideBrowserRequest(method, path, true, false);
        if (decision.allowed) collectorRequests += 1;
        return decision.allowed;
      },
    });
  }

  async #request(
    request: ScopedRequest,
    responseLimit: number,
    includeResponseHeaders = false,
  ): Promise<HttpObservation | SetupHttpObservation> {
    const method = request.method ?? "GET";
    const url = this.#resolvePath(request.path);
    if (this.#setupAccess || includeResponseHeaders) {
      if (!operationAllowed(this.#allowedRequests, method, url.pathname)) {
        throw new TargetScopeError(`${method} ${url.pathname} is not a profile setup operation`);
      }
    } else {
      if (method === "DELETE") {
        throw new TargetScopeError("DELETE is never allowed for proof demonstration");
      }
      if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
        this.assertImpactLevel("state-change");
      }
    }
    if (!includeResponseHeaders && this.#isDenied(method, url.pathname)) {
      throw new TargetScopeError(`${method} ${url.pathname} is denied by the target profile`);
    }
    if (isStateChanging(method) && !this.#isAuthorizedOperation(method, url.pathname)) {
      throw new TargetScopeError(
        `${method} ${url.pathname} was not supplied by the profile or attack-surface map`,
      );
    }
    const actorId = request.actorId ?? actorIds.anonymous;
    const session = await this.#sessions.acquire(actorId);
    if (hasPotentialScopeOverrideHeaders(request.headers)) {
      throw new TargetScopeError(
        "Request headers may not override the scoped method or target path",
      );
    }
    if (hasPotentialAuthenticationHeaders(request.headers)) {
      throw new TargetScopeError(
        actorId !== actorIds.anonymous
          ? "Actor requests may not override the session adapter's credential headers"
          : "Anonymous requests may only use standard representation and precondition headers",
      );
    }
    if (this.#requestsUsed >= this.#requestBudget) {
      throw new RequestBudgetExceededError(
        `Request budget exhausted (${this.#requestsUsed}/${this.#requestBudget})`,
      );
    }

    this.#requestsUsed += 1;
    this.#onRequest?.({
      number: this.#requestsUsed,
      method,
      path: `${url.pathname}${url.search}`,
    });
    const startedAt = performance.now();
    const response = await this.#transport(url, {
      method,
      headers: {
        ...session.headers,
        ...request.headers,
      },
      body: request.body,
      redirect: "manual",
      signal: AbortSignal.timeout(this.#timeoutMs),
    });
    const responseText = await response.text();
    const truncated = responseText.length > responseLimit;
    const text = responseText.slice(0, responseLimit);
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      // Text is a valid target response body.
    }

    const observation: HttpObservation = {
      method,
      status: response.status,
      path: `${url.pathname}${url.search}`,
      body,
      truncated,
      contentType: response.headers.get("content-type") ?? "",
      durationMs: Math.round(performance.now() - startedAt),
    };
    return includeResponseHeaders
      ? { ...observation, headers: Object.fromEntries(response.headers.entries()) }
      : observation;
  }

  mapAttackSurface(options: { maxDocuments?: number } = {}): Promise<AttackSurfaceMap> {
    this.#attackSurfaceResult ??= this.#mapAttackSurface(options.maxDocuments ?? 8);
    return this.#attackSurfaceResult;
  }

  /** @deprecated Use mapAttackSurface. */
  crawl(options: { maxDocuments?: number } = {}): Promise<CrawlMap> {
    return this.mapAttackSurface(options);
  }

  async #mapAttackSurface(maxDocuments: number): Promise<AttackSurfaceMap> {
    const browserState = await this.#sessions.browserState(this.#browserActorId);
    const map = await this.#attackSurfaceMapper({
      origin: this.#origin,
      startPath: this.#startPath,
      maxDocuments,
      timeoutMs: this.#timeoutMs,
      authenticationHeaders: browserState.headers,
      localStorage: browserState.localStorage,
      sessionStorage: browserState.sessionStorage,
      cookies: browserState.cookies,
      openApi: this.#openApi,
      executablePath: this.#browserExecutablePath,
      decideRequest: (method, path, metadata) =>
        this.#decideBrowserRequest(
          method,
          path,
          metadata?.budgeted ?? true,
          metadata?.automaticInteraction ?? false,
        ),
      onOperationDiscovered: (method, path, source, metadata) => {
        if (source === "browser" && metadata?.automaticInteraction) return;
        const key = operationKey(method, path);
        this.#mappedOperations.add(key);
        if (source === "openapi") this.#browserAllowedOperations.add(key);
      },
    });
    return map;
  }

  #decideBrowserRequest(
    method: string,
    path: string,
    budgeted: boolean,
    automaticInteraction: boolean,
  ): { allowed: boolean; reason?: string } {
    const url = this.#resolvePath(path);
    if (method === "DELETE") {
      return { allowed: false, reason: "DELETE is never allowed for proof demonstration" };
    }
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      try {
        this.assertImpactLevel("state-change");
      } catch (error) {
        return { allowed: false, reason: error instanceof Error ? error.message : String(error) };
      }
    }
    if (this.#isDenied(method, url.pathname)) {
      return { allowed: false, reason: "denied by target profile" };
    }
    if (automaticInteraction) {
      return { allowed: false, reason: "automatic interactions cannot issue network requests" };
    }
    if (
      isStateChanging(method) &&
      !operationAllowed(this.#browserAllowedOperations, method, url.pathname)
    ) {
      return { allowed: false, reason: "state-changing operation is not preauthorized" };
    }
    if (!budgeted) return { allowed: true };
    if (this.#requestsUsed >= this.#requestBudget) {
      return { allowed: false, reason: "request budget exhausted" };
    }
    this.#requestsUsed += 1;
    this.#onRequest?.({
      number: this.#requestsUsed,
      method,
      path: `${url.pathname}${url.search}`,
    });
    return { allowed: true };
  }

  #resolvePath(path: string): URL {
    if (!path.startsWith("/") || path.startsWith("//")) {
      throw new TargetScopeError("Only origin-relative paths are allowed");
    }
    const url = new URL(path, this.#origin);
    if (url.origin !== this.#origin) throw new TargetScopeError("Out-of-scope origin blocked");
    return url;
  }

  #isDenied(method: string, pathname: string): boolean {
    return this.#deniedRequests.has(`${method} ${pathname}`);
  }

  #isAuthorizedOperation(method: RestMethod, path: string): boolean {
    return (
      operationAllowed(this.#allowedRequests, method, path) ||
      operationAllowed(this.#mappedOperations, method, path)
    );
  }
}

export function hasPotentialAuthenticationHeaders(
  headers: Record<string, string> | undefined,
): boolean {
  return Object.keys(headers ?? {}).some(isCredentialCapableHeader);
}

function hasPotentialScopeOverrideHeaders(headers: Record<string, string> | undefined): boolean {
  const forbidden = new Set([
    "x-forwarded-uri",
    "x-forwarded-url",
    "x-http-method",
    "x-http-method-override",
    "x-method-override",
    "x-original-url",
    "x-rewrite-url",
  ]);
  return Object.keys(headers ?? {}).some((name) => forbidden.has(name.toLowerCase()));
}

export function isCredentialCapableHeader(name: string): boolean {
  const parts = name
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  if (
    parts.some((part) =>
      [
        "auth",
        "authentication",
        "authorization",
        "cookie",
        "credential",
        "password",
        "secret",
        "session",
        "signature",
        "token",
      ].includes(part),
    )
  ) {
    return true;
  }
  return (
    parts.includes("key") &&
    parts.some((part) => ["access", "api", "client", "private", "security"].includes(part))
  );
}

function isStateChanging(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS"].includes(method);
}

function operationKey(method: string, path: string): string {
  return `${method.toUpperCase()} ${canonicalOperationPath(path)}`;
}

function operationAllowed(operations: ReadonlySet<string>, method: string, path: string): boolean {
  const concrete = canonicalOperationPath(path);
  if (operations.has(`${method.toUpperCase()} ${concrete}`)) return true;
  for (const operation of operations) {
    const separator = operation.indexOf(" ");
    if (operation.slice(0, separator) !== method.toUpperCase()) continue;
    if (pathTemplateMatches(operation.slice(separator + 1), concrete)) return true;
  }
  return false;
}

function canonicalOperationPath(path: string): string {
  const pathname = new URL(path, "http://scope.invalid").pathname
    .split("/")
    .map((encodedSegment) => {
      const segment = decodeURIComponent(encodedSegment);
      return /^(?:\{[^}]+\}|<[^>]+>|:[A-Za-z_$][\w$]*)$/.test(segment) ? "{id}" : segment;
    })
    .join("/");
  return pathname === "/" ? pathname : pathname.replace(/\/+$/, "");
}

function pathTemplateMatches(template: string, concrete: string): boolean {
  const templateSegments = template.split("/").map(decodeURIComponent);
  const concreteSegments = concrete.split("/").map(decodeURIComponent);
  return (
    templateSegments.length === concreteSegments.length &&
    templateSegments.every(
      (segment, index) => segment === "{id}" || segment === concreteSegments[index],
    )
  );
}
