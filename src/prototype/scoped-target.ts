import {
  BrowserAttackSurfaceMapper,
  type AttackSurfaceDocument,
  type AttackSurfaceMap,
  type BrowserCookie,
} from "./attack-surface.ts";

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
  authenticated?: boolean;
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
  readonly #requestBudget: number;
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
  #requestsUsed = 0;
  #authenticationHeaders?: Record<string, string>;
  #browserLocalStorage?: Record<string, string>;
  #browserSessionStorage?: Record<string, string>;
  #browserCookies?: BrowserCookie[];
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
  }

  get origin(): string {
    return this.#origin;
  }

  get startPath(): string {
    return this.#startPath;
  }

  get isAuthenticated(): boolean {
    return this.#authenticationHeaders !== undefined;
  }

  setAuthentication(headers: Record<string, string>): void {
    this.#authenticationHeaders = { ...headers };
  }

  setBrowserLocalStorage(entries: Record<string, string>): void {
    this.#browserLocalStorage = { ...entries };
  }

  setBrowserSession(session: {
    localStorage?: Record<string, string>;
    sessionStorage?: Record<string, string>;
    cookies?: BrowserCookie[];
  }): void {
    this.#browserLocalStorage = { ...session.localStorage };
    this.#browserSessionStorage = { ...session.sessionStorage };
    this.#browserCookies = session.cookies?.map((cookie) => ({ ...cookie }));
  }

  async request(request: ScopedRequest): Promise<HttpObservation> {
    return this.#request(request, this.#maxResponseChars);
  }

  async #request(request: ScopedRequest, responseLimit: number): Promise<HttpObservation> {
    const method = request.method ?? "GET";
    const url = this.#resolvePath(request.path);
    if (this.#isDenied(method, url.pathname)) {
      throw new TargetScopeError(`${method} ${url.pathname} is denied by the target profile`);
    }
    if (isStateChanging(method) && !this.#isAuthorizedOperation(method, url.pathname)) {
      throw new TargetScopeError(
        `${method} ${url.pathname} was not supplied by the profile or attack-surface map`,
      );
    }
    if (request.authenticated && !this.#authenticationHeaders) {
      throw new Error("This target has no authenticated session");
    }
    if (hasPotentialScopeOverrideHeaders(request.headers)) {
      throw new TargetScopeError(
        "Request headers may not override the scoped method or target path",
      );
    }
    if (hasPotentialAuthenticationHeaders(request.headers)) {
      throw new TargetScopeError(
        request.authenticated
          ? "Authenticated requests may not override the target profile's credential headers"
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
    const response = await this.#transport(url, {
      method,
      headers: {
        ...(request.authenticated ? this.#authenticationHeaders : {}),
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

    return {
      method,
      status: response.status,
      path: `${url.pathname}${url.search}`,
      body,
      truncated,
      contentType: response.headers.get("content-type") ?? "",
    };
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
    const map = await this.#attackSurfaceMapper({
      origin: this.#origin,
      startPath: this.#startPath,
      maxDocuments,
      timeoutMs: this.#timeoutMs,
      authenticationHeaders: this.#authenticationHeaders,
      localStorage: this.#browserLocalStorage,
      sessionStorage: this.#browserSessionStorage,
      cookies: this.#browserCookies,
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
