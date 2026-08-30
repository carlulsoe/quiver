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

export interface ScopedTargetOptions {
  target: URL;
  requestBudget: number;
  allowedRequests?: AllowedRequest[];
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
      for (const route of found.routes) routes.add(route);
      for (const link of found.crawlableLinks) {
        routes.add(link);
        if (!queued.has(link)) {
          queued.add(link);
          queue.push(link);
        }
      }
    }

    return { startPath: this.#startPath, documents, routes: [...routes].sort() };
  }

  #resolvePath(path: string): URL {
    if (!path.startsWith("/") || path.startsWith("//")) {
      throw new TargetScopeError("Only origin-relative paths are allowed");
    }
    const url = new URL(path, this.#origin);
    if (url.origin !== this.#origin) throw new TargetScopeError("Out-of-scope origin blocked");
    return url;
  }
}

function extractRoutes(
  source: string,
  origin: string,
  contentType: string,
): { routes: Set<string>; crawlableLinks: Set<string> } {
  const routes = new Set<string>();
  const crawlableLinks = new Set<string>();

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
  }

  return { routes, crawlableLinks };
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
    return `${url.pathname}${url.search}`;
  } catch {
    return undefined;
  }
}

function isCrawlableDocument(path: string): boolean {
  const pathname = new URL(path, "http://scope.invalid").pathname;
  const extension = pathname.match(/\.([A-Za-z0-9]+)$/)?.[1]?.toLowerCase();
  return !extension || extension === "html" || extension === "htm" || extension === "js";
}
