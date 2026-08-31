export type HttpTransport = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export interface HttpObservation {
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
  method: "POST";
  path: string;
}

export interface DeniedRequest {
  method: "GET" | "POST";
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
  maxCrawlResponseChars?: number;
}

export interface ScopedRequest {
  path: string;
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
  authenticated?: boolean;
}

export interface CrawlDocument {
  path: string;
  status: number;
  contentType: string;
  truncated: boolean;
}

export interface CrawlMap {
  startPath: string;
  documents: CrawlDocument[];
  routes: string[];
  routeDetails: CrawlRouteDetail[];
}

export interface CrawlGetCallSite {
  documentPath: string;
  authentication: "likely" | "unknown";
}

export interface CrawlIdentifierSource {
  parameter: string;
  sourcePath: string;
}

export interface CrawlRouteDetail {
  path: string;
  sources: string[];
  getCallSites: CrawlGetCallSite[];
  identifierSources: CrawlIdentifierSource[];
}

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
  readonly #deniedRequests: Set<string>;
  readonly #onRequest?: (request: TargetRequestEvent) => void;
  readonly #transport: HttpTransport;
  readonly #timeoutMs: number;
  readonly #maxResponseChars: number;
  readonly #maxCrawlResponseChars: number;
  #requestsUsed = 0;
  #authenticationHeaders?: Record<string, string>;
  #crawlResult?: Promise<CrawlMap>;

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
      options.allowedRequests?.map(({ method, path }) => `${method} ${path}`) ?? [],
    );
    this.#deniedRequests = new Set(
      options.deniedRequests?.map(({ method, path }) => `${method} ${path}`) ?? [],
    );
    this.#onRequest = options.onRequest;
    this.#transport = options.transport ?? fetch;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#maxResponseChars = options.maxResponseChars ?? 12_000;
    this.#maxCrawlResponseChars = options.maxCrawlResponseChars ?? 2_000_000;
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

  async request(request: ScopedRequest): Promise<HttpObservation> {
    return this.#request(request, this.#maxResponseChars);
  }

  async #request(request: ScopedRequest, responseLimit: number): Promise<HttpObservation> {
    const method = request.method ?? "GET";
    const url = this.#resolvePath(request.path);
    if (this.#isDenied(method, url.pathname)) {
      throw new TargetScopeError(`${method} ${url.pathname} is denied by the target profile`);
    }
    if (method !== "GET" && !this.#allowedRequests.has(`${method} ${url.pathname}`)) {
      throw new TargetScopeError(`${method} ${url.pathname} is not allowed for this target`);
    }
    if (request.authenticated && !this.#authenticationHeaders) {
      throw new Error("This target has no authenticated session");
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
      status: response.status,
      path: `${url.pathname}${url.search}`,
      body,
      truncated,
      contentType: response.headers.get("content-type") ?? "",
    };
  }

  crawl(options: { maxDocuments?: number } = {}): Promise<CrawlMap> {
    this.#crawlResult ??= this.#crawl(options.maxDocuments ?? 8);
    return this.#crawlResult;
  }

  async #crawl(maxDocuments: number): Promise<CrawlMap> {
    const queue = [this.#startPath];
    const queued = new Set(queue);
    const documents: CrawlDocument[] = [];
    const routes = new Set<string>(queue);
    const routeEvidence = new Map<string, RouteEvidence>();

    while (queue.length > 0 && documents.length < maxDocuments) {
      const path = queue.shift()!;
      const observation = await this.#request({ path }, this.#maxCrawlResponseChars);
      const contentType = observation.contentType ?? "";
      documents.push({
        path: observation.path,
        status: observation.status,
        contentType,
        truncated: observation.truncated ?? false,
      });
      if (typeof observation.body !== "string") continue;

      const found = extractRoutes(observation.body, this.#origin, contentType);
      for (const route of found.routes) {
        routes.add(route);
        mergeRouteEvidence(routeEvidence, route, observation.path, found.getCalls.get(route));
      }
      for (const link of found.crawlableLinks) {
        routes.add(link);
        if (!queued.has(link) && !this.#isDenied("GET", new URL(link, this.#origin).pathname)) {
          queued.add(link);
          queue.push(link);
        }
      }
    }

    return {
      startPath: this.#startPath,
      documents,
      routes: [...routes].sort(),
      routeDetails: buildRouteDetails(routeEvidence),
    };
  }

  #resolvePath(path: string): URL {
    if (!path.startsWith("/") || path.startsWith("//")) {
      throw new TargetScopeError("Only origin-relative paths are allowed");
    }
    const url = new URL(path, this.#origin);
    if (url.origin !== this.#origin) throw new TargetScopeError("Out-of-scope origin blocked");
    return url;
  }

  #isDenied(method: "GET" | "POST", pathname: string): boolean {
    return this.#deniedRequests.has(`${method} ${pathname}`);
  }
}

function extractRoutes(
  source: string,
  origin: string,
  contentType: string,
): {
  routes: Set<string>;
  crawlableLinks: Set<string>;
  getCalls: Map<string, "likely" | "unknown">;
} {
  const routes = new Set<string>();
  const crawlableLinks = new Set<string>();
  const getCalls = new Map<string, "likely" | "unknown">();

  if (contentType.includes("html")) {
    for (const match of source.matchAll(/\b(?:href|src|action)\s*=\s*["']([^"']+)["']/gi)) {
      const route = sameOriginPath(match[1]!, origin);
      if (!route) continue;
      routes.add(route);
      if (isCrawlableDocument(route)) crawlableLinks.add(route);
    }
  }

  for (const match of source.matchAll(/["'`]((?:\/)[A-Za-z0-9_?&=./{}:<>,%-]{2,})["'`]/g)) {
    const route = sameOriginPath(match[1]!, origin);
    if (route) routes.add(route);
  }

  if (contentType.includes("javascript") || contentType.includes("ecmascript")) {
    for (const route of deriveComposedRoutes(source)) routes.add(route);
    for (const call of extractDirectGetCalls(source, origin)) {
      routes.add(call.path);
      getCalls.set(call.path, call.authentication);
    }
  }

  return { routes, crawlableLinks, getCalls };
}

interface RouteEvidence {
  sources: Set<string>;
  getCallSites: CrawlGetCallSite[];
}

function mergeRouteEvidence(
  evidence: Map<string, RouteEvidence>,
  route: string,
  documentPath: string,
  authentication?: "likely" | "unknown",
): void {
  const detail = evidence.get(route) ?? { sources: new Set<string>(), getCallSites: [] };
  detail.sources.add(documentPath);
  if (authentication) detail.getCallSites.push({ documentPath, authentication });
  evidence.set(route, detail);
}

function extractDirectGetCalls(
  source: string,
  origin: string,
): Array<{ path: string; authentication: "likely" | "unknown" }> {
  const calls: Array<{ path: string; authentication: "likely" | "unknown" }> = [];
  for (const match of source.matchAll(
    /\bfetch\s*\(\s*([^,()]{1,300})(?:,\s*([\s\S]{0,500}?))?\)/g,
  )) {
    const options = match[2] ?? "";
    const method = /\bmethod\s*:\s*["']([A-Za-z]+)["']/i.exec(options)?.[1]?.toUpperCase();
    if (method && method !== "GET") continue;
    const sourceBeforeCall = source.slice(Math.max(0, (match.index ?? 0) - 12_000), match.index);
    const resolved = resolveRouteExpression(match[1]!, sourceBeforeCall, source);
    if (!resolved) continue;
    const path = sameOriginPath(normalizeRouteTemplate(resolved), origin);
    if (!path) continue;
    calls.push({
      path,
      authentication: likelyUsesAuthentication(options, sourceBeforeCall) ? "likely" : "unknown",
    });
  }
  return calls;
}

function resolveRouteExpression(
  expression: string,
  sourceBeforeCall: string,
  definitionsSource: string,
  depth = 0,
): string | undefined {
  if (depth >= 8) return undefined;
  const trimmed = expression.trim();
  const literal = /^(?:["'`]([\s\S]*)["'`])$/.exec(trimmed)?.[1];
  if (literal !== undefined) return literal;

  const identifier = /^([A-Za-z_$][\w$]*)$/.exec(trimmed)?.[1];
  if (identifier) {
    const pattern = () => new RegExp(`\\b${escapeRegExp(identifier)}\\s*=\\s*([^;,]{1,500})`, "g");
    const assignment =
      lastMatch(sourceBeforeCall, pattern()) ?? lastMatch(definitionsSource, pattern());
    return assignment
      ? resolveRouteExpression(assignment[1]!, sourceBeforeCall, definitionsSource, depth + 1)
      : undefined;
  }

  const parts = splitConcatenation(trimmed);
  if (parts.length < 2) return undefined;
  const resolved: string[] = [];
  for (const part of parts) {
    const member = /^([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)$/.exec(part);
    if (member) {
      const pattern = () =>
        new RegExp(`\\b${escapeRegExp(member[1]!)}\\s*=\\s*\\{([^{}]{1,12000})\\}`, "g");
      const object =
        lastMatch(sourceBeforeCall, pattern()) ?? lastMatch(definitionsSource, pattern());
      const value = object
        ? new RegExp(`\\b${escapeRegExp(member[2]!)}\\s*:\\s*["'\`]([^"'\`]+)["'\`]`).exec(
            object[1]!,
          )?.[1]
        : undefined;
      if (!value) return undefined;
      resolved.push(value);
      continue;
    }
    const value = resolveRouteExpression(part, sourceBeforeCall, definitionsSource, depth + 1);
    if (!value) return undefined;
    resolved.push(value);
  }
  return resolved.join("");
}

function splitConcatenation(expression: string): string[] {
  return expression.split(/\s*\+\s*/).filter(Boolean);
}

function likelyUsesAuthentication(options: string, sourceBeforeCall: string): boolean {
  if (/\b(?:authorization|bearer)\b/i.test(options)) return true;
  const headersVariable =
    /\bheaders\s*:\s*([A-Za-z_$][\w$]*)/.exec(options)?.[1] ??
    (/\bheaders\b/.test(options) ? "headers" : undefined);
  if (!headersVariable) return false;
  const assignment = lastMatch(
    sourceBeforeCall,
    new RegExp(`\\b${escapeRegExp(headersVariable)}\\s*=\\s*([^;]{1,2000})`, "g"),
  );
  return /\b(?:authorization|bearer)\b/i.test(assignment?.[1] ?? "");
}

function lastMatch(source: string, pattern: RegExp): RegExpMatchArray | undefined {
  let last: RegExpMatchArray | undefined;
  for (const match of source.matchAll(pattern)) last = match;
  return last;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeRouteTemplate(route: string): string {
  return route.replaceAll(/\$\{\s*([A-Za-z_$][\w$]*)\s*\}/g, "{$1}");
}

function buildRouteDetails(evidence: Map<string, RouteEvidence>): CrawlRouteDetail[] {
  const details: CrawlRouteDetail[] = [...evidence.entries()].map(([path, detail]) => ({
    path,
    sources: [...detail.sources].sort(),
    getCallSites: detail.getCallSites,
    identifierSources: [],
  }));
  const getSources = details.filter((detail) => detail.getCallSites.length > 0);
  for (const detail of details) {
    for (const parameter of routeParameters(detail.path)) {
      const prefix = detail.path.slice(0, parameter.index).replace(/\/$/, "");
      const source = getSources
        .filter(
          (candidate) =>
            candidate.path !== detail.path &&
            !routeParameters(candidate.path).length &&
            (candidate.path === prefix ||
              prefix.startsWith(`${candidate.path}/`) ||
              candidate.path.startsWith(`${prefix}/`)),
        )
        .sort((left, right) => right.path.length - left.path.length)[0];
      if (source)
        detail.identifierSources.push({ parameter: parameter.name, sourcePath: source.path });
    }
  }
  return details
    .filter(
      (detail) =>
        !/^\/(?:\{|<|:)/.test(detail.path) &&
        (detail.getCallSites.length > 0 || detail.identifierSources.length > 0),
    )
    .sort((left, right) => left.path.localeCompare(right.path));
}

function routeParameters(path: string): Array<{ name: string; index: number }> {
  const parameters: Array<{ name: string; index: number }> = [];
  for (const match of path.matchAll(/\{([^/{}]+)\}|<([^/<>]+)>|:([A-Za-z_$][\w$]*)/g)) {
    parameters.push({ name: match[1] ?? match[2] ?? match[3]!, index: match.index });
  }
  return parameters;
}

function deriveComposedRoutes(source: string): Set<string> {
  const strings = new Map<string, string>();
  for (const match of source.matchAll(/\b([A-Za-z_$][\w$]*)\s*=\s*["'`]([^"'`]{1,200})["'`]/g)) {
    strings.set(match[1]!, match[2]!);
  }

  const objects = new Map<string, Map<string, string>>();
  for (const match of source.matchAll(/\b([A-Za-z_$][\w$]*)\s*=\s*\{([^{}]{1,12000})\}/g)) {
    const members = new Map<string, string>();
    for (const member of match[2]!.matchAll(/\b([A-Za-z_$][\w$]*)\s*:\s*["'`]([^"'`]+)["'`]/g)) {
      members.set(member[1]!, member[2]!);
    }
    if (members.size > 0) objects.set(match[1]!, members);
  }

  const routes = new Set<string>();
  for (const usage of source.matchAll(
    /\b([A-Za-z_$][\w$]*)\s*\+\s*([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)/g,
  )) {
    const prefix = strings.get(usage[1]!);
    const suffix = objects.get(usage[2]!)?.get(usage[3]!);
    if (!prefix || !suffix) continue;
    const combined = `/${prefix}${suffix}`.replaceAll("//", "/");
    if (combined.includes("/api/")) routes.add(combined);
  }
  return routes;
}

function sameOriginPath(candidate: string, origin: string): string | undefined {
  if (candidate.startsWith("/>") || candidate.includes("><") || candidate.endsWith(",")) {
    return undefined;
  }
  try {
    const url = new URL(candidate, origin);
    if (url.origin !== origin) return undefined;
    return restoreRouteTemplates(`${url.pathname}${url.search}`);
  } catch {
    return undefined;
  }
}

function restoreRouteTemplates(path: string): string {
  return path.replaceAll(/%7B([^/%]+)%7D/gi, "{$1}").replaceAll(/%3C([^/%]+)%3E/gi, "<$1>");
}

function isCrawlableDocument(path: string): boolean {
  const pathname = new URL(path, "http://scope.invalid").pathname;
  const extension = pathname.match(/\.([A-Za-z0-9]+)$/)?.[1]?.toLowerCase();
  return !extension || extension === "html" || extension === "htm" || extension === "js";
}
