import { access } from "node:fs/promises";
import {
  chromium,
  type Browser,
  type BrowserContext,
  type Page,
  type Request,
} from "playwright-core";
import { normalizeEndpoint } from "./endpoint.ts";

export interface AttackSurfaceDocument {
  path: string;
  status: number;
  contentType: string;
  truncated: boolean;
}

export interface AttackSurfaceCallSite {
  documentPath: string;
  method: string;
  authentication: "likely" | "unknown";
}

export interface AttackSurfaceIdentifierSource {
  parameter: string;
  sourcePath: string;
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
  summary?: string;
}

export interface AttackSurfaceMap {
  startPath: string;
  documents: AttackSurfaceDocument[];
  routes: string[];
  routeDetails: AttackSurfaceRouteDetail[];
}

export interface BrowserRequestDecision {
  allowed: boolean;
  reason?: string;
}

export interface BrowserRequestMetadata {
  budgeted: boolean;
  automaticInteraction?: boolean;
}

export type BrowserCookie = Parameters<BrowserContext["addCookies"]>[0][number];

export interface BrowserAttackSurfaceMapperOptions {
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
    metadata?: BrowserRequestMetadata,
  ) => BrowserRequestDecision;
  onOperationDiscovered?: (
    method: string,
    path: string,
    source: "browser" | "openapi",
    metadata?: { automaticInteraction: boolean },
  ) => void;
  executablePath?: string;
  launch?: (executablePath: string) => Promise<Browser>;
}

interface MutableRouteEvidence {
  methods: Set<string>;
  sources: Set<string>;
  examples: Set<string>;
  callSites: AttackSurfaceCallSite[];
  summary?: string;
}

/** Maps the surface the application actually exercises in a real browser. */
export class BrowserAttackSurfaceMapper {
  readonly #options: BrowserAttackSurfaceMapperOptions;
  readonly #evidence = new Map<string, MutableRouteEvidence>();
  readonly #documents = new Map<string, AttackSurfaceDocument>();
  #exercisingControls = false;

  constructor(options: BrowserAttackSurfaceMapperOptions) {
    this.#options = options;
  }

  async map(): Promise<AttackSurfaceMap> {
    this.#addOpenApi(this.#options.openApi);
    const executablePath =
      this.#options.executablePath ??
      process.env.QUIVER_BROWSER_PATH ??
      (await findBrowserExecutable());
    const browser = await (this.#options.launch ?? launchChromium)(executablePath);
    try {
      const context = await browser.newContext({
        extraHTTPHeaders: this.#options.authenticationHeaders,
        serviceWorkers: "block",
      });
      await this.#mapContext(context);
    } finally {
      await browser.close();
    }
    return this.#result();
  }

  async #mapContext(context: BrowserContext): Promise<void> {
    if (this.#options.cookies?.length) await context.addCookies(this.#options.cookies);
    if (this.#options.localStorage || this.#options.sessionStorage) {
      await context.addInitScript(
        (storage) => {
          for (const [name, value] of Object.entries(storage.local)) {
            localStorage.setItem(name, value);
          }
          for (const [name, value] of Object.entries(storage.session)) {
            sessionStorage.setItem(name, value);
          }
        },
        {
          local: this.#options.localStorage ?? {},
          session: this.#options.sessionStorage ?? {},
        },
      );
    }
    const page = await context.newPage();
    const pendingResponses: Promise<void>[] = [];
    let currentDocument = this.#options.startPath;

    page.on("response", (response) => {
      const request = response.request();
      if (request.resourceType() !== "document" && request.resourceType() !== "script") return;
      const path = this.#sameOriginPath(response.url());
      if (!path) return;
      pendingResponses.push(
        response
          .headerValue("content-type")
          .then((contentType) => {
            this.#documents.set(path, {
              path,
              status: response.status(),
              contentType: contentType ?? "",
              truncated: false,
            });
          })
          .catch(() => undefined),
      );
    });

    await page.route("**/*", async (route) => {
      const request = route.request();
      const path = this.#sameOriginPath(request.url());
      if (!path) {
        await route.abort("blockedbyclient");
        return;
      }
      const method = request.method().toUpperCase();
      const observedOperation = this.#observeRequest(request, path, currentDocument);
      const decision = this.#options.decideRequest(method, path, {
        budgeted: true,
        automaticInteraction: this.#exercisingControls,
      });
      if (observedOperation) {
        this.#options.onOperationDiscovered?.(method, normalizeEndpoint(path), "browser", {
          automaticInteraction: this.#exercisingControls,
        });
      }
      if (!decision.allowed) {
        await route.abort("blockedbyclient");
        return;
      }
      await route.continue();
    });

    const queue = [this.#options.startPath];
    const queued = new Set(queue);
    let visitedDocuments = 0;
    while (queue.length > 0 && visitedDocuments < this.#options.maxDocuments) {
      const path = queue.shift()!;
      visitedDocuments += 1;
      currentDocument = path;
      // A full navigation destroys callbacks from the previously exercised document.
      // Until then, keep the guard set so delayed click handlers retain automatic provenance.
      this.#exercisingControls = false;
      try {
        await page.goto(new URL(path, this.#options.origin).href, {
          waitUntil: "networkidle",
          timeout: this.#options.timeoutMs,
        });
      } catch (error) {
        if (!isExpectedNavigationInterruption(error)) throw error;
      }
      await this.#exerciseInteractiveControls(page);
      for (const link of await sameOriginLinks(page, this.#options.origin)) {
        if (!queued.has(link)) {
          queued.add(link);
          queue.push(link);
        }
      }
    }
    await Promise.all(pendingResponses);
  }

  async #exerciseInteractiveControls(page: Page): Promise<void> {
    this.#exercisingControls = true;
    const controls = page.locator(
      "button:not([disabled]), [role=button]:not([aria-disabled=true]), input[type=submit]:not([disabled])",
    );
    const count = Math.min(await controls.count().catch(() => 0), 12);
    for (let index = 0; index < count; index += 1) {
      const control = controls.nth(index);
      if (!(await control.isVisible().catch(() => false))) continue;
      await control.click({ timeout: 1_000, noWaitAfter: true }).catch(() => undefined);
      await page.waitForTimeout(50);
    }
  }

  #observeRequest(request: Request, path: string, documentPath: string): boolean {
    const method = request.method().toUpperCase();
    const resourceType = request.resourceType();
    const source = `browser:${resourceType}:${documentPath}`;
    if (["script", "stylesheet", "image", "font", "media"].includes(resourceType)) return false;
    if (resourceType === "document" && method === "GET") return false;
    const headers = request.headers();
    const authentication = headers.authorization || headers.cookie ? "likely" : "unknown";
    this.#mergeEvidence(
      normalizeEndpoint(path),
      method,
      source,
      { documentPath, method, authentication },
      { examplePath: path },
    );
    return true;
  }

  #addOpenApi(input: unknown): void {
    if (!input || typeof input !== "object") return;
    const document = input as Record<string, unknown>;
    const paths = document.paths;
    if (!paths || typeof paths !== "object") return;
    for (const [path, pathItem] of Object.entries(paths)) {
      if (!path.startsWith("/") || !pathItem || typeof pathItem !== "object") continue;
      for (const [method, operation] of Object.entries(pathItem)) {
        const upperMethod = method.toUpperCase();
        if (!HTTP_METHODS.has(upperMethod) || !operation || typeof operation !== "object") continue;
        const details = operation as Record<string, unknown>;
        const prefixes = resolveEffectiveOpenApiPrefixes(
          document,
          pathItem as Record<string, unknown>,
          details,
          this.#options.origin,
        );
        for (const prefix of prefixes) {
          const operationPath = `${prefix}${path}`.replaceAll(/\/{2,}/g, "/");
          this.#mergeEvidence(operationPath, upperMethod, "openapi", undefined, {
            summary: typeof details.summary === "string" ? details.summary : undefined,
          });
          this.#options.onOperationDiscovered?.(upperMethod, operationPath, "openapi");
        }
      }
    }
  }

  #mergeEvidence(
    path: string,
    method: string,
    source: string,
    callSite?: AttackSurfaceCallSite,
    metadata?: { summary?: string; examplePath?: string },
  ): void {
    const evidence = this.#evidence.get(path) ?? {
      methods: new Set<string>(),
      sources: new Set<string>(),
      examples: new Set<string>(),
      callSites: [],
    };
    evidence.methods.add(method);
    evidence.sources.add(source);
    if (metadata?.examplePath) evidence.examples.add(metadata.examplePath);
    if (
      callSite &&
      !evidence.callSites.some(
        (candidate) =>
          candidate.documentPath === callSite.documentPath &&
          candidate.method === callSite.method &&
          candidate.authentication === callSite.authentication,
      )
    ) {
      evidence.callSites.push(callSite);
    }
    evidence.summary ??= metadata?.summary;
    this.#evidence.set(path, evidence);
  }

  #result(): AttackSurfaceMap {
    const routeDetails: AttackSurfaceRouteDetail[] = [...this.#evidence.entries()]
      .map(([path, evidence]) => ({
        path,
        methods: [...evidence.methods].sort(),
        sources: [...evidence.sources].sort(),
        examples: [...evidence.examples].sort(),
        callSites: evidence.callSites,
        getCallSites: evidence.callSites.filter(({ method }) => method === "GET"),
        identifierSources: [],
        ...(evidence.summary ? { summary: evidence.summary } : {}),
      }))
      .sort((left, right) => left.path.localeCompare(right.path));
    addIdentifierSources(routeDetails);
    return {
      startPath: this.#options.startPath,
      documents: [...this.#documents.values()],
      routes: routeDetails.map(({ path }) => path),
      routeDetails,
    };
  }

  #sameOriginPath(candidate: string): string | undefined {
    try {
      const url = new URL(candidate, this.#options.origin);
      if (url.origin !== this.#options.origin) return undefined;
      return `${url.pathname}${url.search}`;
    } catch {
      return undefined;
    }
  }
}

const HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

export function resolveOpenApiPrefixes(
  document: Record<string, unknown>,
  origin: string,
): string[] {
  if (typeof document.swagger === "string" && document.swagger.startsWith("2.")) {
    if (typeof document.host === "string") {
      const schemes = Array.isArray(document.schemes)
        ? document.schemes.filter((value): value is string => typeof value === "string")
        : [new URL(origin).protocol.replace(":", "")];
      try {
        if (!schemes.some((scheme) => new URL(`${scheme}://${document.host}`).origin === origin)) {
          return [];
        }
      } catch {
        return [];
      }
    }
    return [normalizePrefix(typeof document.basePath === "string" ? document.basePath : "")];
  }
  return resolveDeclaredServerPrefixes(document, origin, [""]);
}

export function resolveEffectiveOpenApiPrefixes(
  document: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  operation: Record<string, unknown>,
  origin: string,
): string[] {
  const documentPrefixes = resolveOpenApiPrefixes(document, origin);
  if (typeof document.swagger === "string" && document.swagger.startsWith("2.")) {
    return documentPrefixes;
  }
  const pathPrefixes = resolveDeclaredServerPrefixes(pathItem, origin, documentPrefixes);
  return resolveDeclaredServerPrefixes(operation, origin, pathPrefixes);
}

function resolveDeclaredServerPrefixes(
  owner: Record<string, unknown>,
  origin: string,
  inherited: string[],
): string[] {
  if (!("servers" in owner)) return inherited;
  if (!Array.isArray(owner.servers)) return [];
  const prefixes = owner.servers.flatMap((server) => {
    if (!server || typeof server !== "object" || !("url" in server)) return [];
    const value = (server as { url?: unknown }).url;
    if (typeof value !== "string" || value.includes("{")) return [];
    try {
      const url = new URL(value, origin);
      return url.origin === origin ? [normalizePrefix(url.pathname)] : [];
    } catch {
      return [];
    }
  });
  return [...new Set(prefixes)];
}

function normalizePrefix(value: string): string {
  const prefix = `/${value}`.replaceAll(/\/{2,}/g, "/").replace(/\/$/, "");
  return prefix === "/" ? "" : prefix;
}

async function sameOriginLinks(page: Page, origin: string): Promise<string[]> {
  return page
    .locator("a[href]")
    .evaluateAll(
      (anchors, expectedOrigin) => [
        ...new Set(
          anchors.flatMap((anchor) => {
            const href = (anchor as HTMLAnchorElement).href;
            try {
              const url = new URL(href);
              return url.origin === expectedOrigin ? [`${url.pathname}${url.search}`] : [];
            } catch {
              return [];
            }
          }),
        ),
      ],
      origin,
    )
    .catch(() => []);
}

function addIdentifierSources(details: AttackSurfaceRouteDetail[]): void {
  const getSources = details.filter(
    (detail) => detail.methods.includes("GET") && routeParameters(detail.path).length === 0,
  );
  for (const detail of details) {
    for (const parameter of routeParameters(detail.path)) {
      const prefix = detail.path.slice(0, parameter.index).replace(/\/$/, "");
      const source = getSources
        .filter(
          (candidate) =>
            candidate.path !== detail.path &&
            (candidate.path === prefix ||
              prefix.startsWith(`${candidate.path}/`) ||
              candidate.path.startsWith(`${prefix}/`)),
        )
        .sort((left, right) => right.path.length - left.path.length)[0];
      if (source) {
        detail.identifierSources.push({ parameter: parameter.name, sourcePath: source.path });
      }
    }
  }
}

function routeParameters(path: string): Array<{ name: string; index: number }> {
  const parameters: Array<{ name: string; index: number }> = [];
  for (const match of path.matchAll(/\{([^/{}]+)\}|<([^/<>]+)>|:([A-Za-z_$][\w$]*)/g)) {
    parameters.push({ name: match[1] ?? match[2] ?? match[3]!, index: match.index });
  }
  return parameters;
}

export async function launchChromium(executablePath: string): Promise<Browser> {
  return chromium.launch({ executablePath, headless: true });
}

export async function findBrowserExecutable(): Promise<string> {
  const candidates = [
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ];
  for (const candidate of candidates) {
    if (
      await access(candidate)
        .then(() => true)
        .catch(() => false)
    )
      return candidate;
  }
  throw new Error(
    "No Chromium browser found. Install Chromium or set QUIVER_BROWSER_PATH to its executable.",
  );
}

function isExpectedNavigationInterruption(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /ERR_ABORTED|ERR_BLOCKED_BY_CLIENT|ERR_FAILED|Timeout/i.test(message);
}
