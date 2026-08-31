import { RouteDiscovery, type CrawlRouteDetail } from "./route-discovery.ts";

export type {
  CrawlGetCallSite,
  CrawlIdentifierSource,
  CrawlRouteDetail,
} from "./route-discovery.ts";

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
    const routeDiscovery = new RouteDiscovery(this.#origin);

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

      const found = routeDiscovery.analyzeDocument({
        path: observation.path,
        source: observation.body,
        contentType,
      });
      for (const route of found.routes) {
        routes.add(route);
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
      routeDetails: routeDiscovery.routeDetails(),
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
