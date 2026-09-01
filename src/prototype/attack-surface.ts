import { access } from "node:fs/promises";
import {
  chromium,
  type Browser,
  type BrowserContext,
  type Locator,
  type Page,
  type Request,
} from "playwright-core";
import { normalizeEndpoint } from "./endpoint.ts";

export type AttackSurfaceScope = "attackable" | "visit-only";

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
  executablePath?: string;
  launch?: (executablePath: string) => Promise<Browser>;
}

interface MutableRouteEvidence {
  origin: string;
  path: string;
  scope: AttackSurfaceScope;
  methods: Set<string>;
  sources: Set<string>;
  examples: Set<string>;
  callSites: AttackSurfaceCallSite[];
  requestBodies: AttackSurfaceRequestBody[];
  graphqlOperations: AttackSurfaceGraphqlOperation[];
  summary?: string;
}

interface FormCandidate {
  index: number;
  submitterIndex: number;
  action: string;
  method: string;
  enctype: string;
  intent: string;
  destructive: boolean;
  purposeful: boolean;
  fields: Array<{ name: string; type: string; value?: string; valueSource: string }>;
  fileFields: string[];
}

/** Maps browser-observed workflows and supplied API descriptions without testing findings. */
export class BrowserAttackSurfaceMapper {
  readonly #options: BrowserAttackSurfaceMapperOptions;
  readonly #scopes: ReadonlyMap<string, AttackSurfaceScope>;
  readonly #evidence = new Map<string, MutableRouteEvidence>();
  readonly #documents = new Map<string, AttackSurfaceDocument>();
  readonly #forms: AttackSurfaceForm[] = [];
  readonly #webSockets: AttackSurfaceWebSocket[] = [];
  #automaticInteraction = false;
  #activeFormRequest?: { method: string; origin: string; pathname: string; allowed: boolean };

  constructor(options: BrowserAttackSurfaceMapperOptions) {
    this.#options = options;
    this.#scopes = normalizeAttackSurfaceOrigins(options.origin, options.origins);
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
    const cookieJars = new Map<string, BrowserCookie[]>();
    let activeCookieOrigin = this.#options.origin;
    const selectCookieJar = async (origin: string) => {
      if (origin === activeCookieOrigin) return;
      cookieJars.set(activeCookieOrigin, await context.cookies());
      await context.clearCookies();
      const cookies = cookieJars.get(origin);
      if (cookies?.length) await context.addCookies(cookies);
      activeCookieOrigin = origin;
    };
    if (this.#options.localStorage || this.#options.sessionStorage) {
      await context.addInitScript(
        (storage) => {
          if (location.origin !== storage.origin) return;
          for (const [name, value] of Object.entries(storage.local))
            localStorage.setItem(name, value);
          for (const [name, value] of Object.entries(storage.session))
            sessionStorage.setItem(name, value);
        },
        {
          origin: this.#options.origin,
          local: this.#options.localStorage ?? {},
          session: this.#options.sessionStorage ?? {},
        },
      );
    }
    let currentDocument = this.#identifier(new URL(this.#options.startPath, this.#options.origin));
    let currentDocumentOrigin = this.#options.origin;
    let currentDocumentScope: AttackSurfaceScope = "attackable";
    await context.routeWebSocket("**/*", (route) => {
      const scoped = this.#scopedUrl(route.url());
      if (!scoped) {
        route.close({ code: 1008, reason: "Origin is outside discovery scope" });
        return;
      }
      const evidence: AttackSurfaceWebSocket = {
        url: route.url(),
        origin: scoped.origin,
        path: `${scoped.url.pathname}${scoped.url.search}`,
        scope: scoped.scope,
        documentPath: currentDocument,
        sentFrames: 0,
        receivedFrames: 0,
        sentBytes: 0,
        receivedBytes: 0,
      };
      this.#webSockets.push(evidence);
      if (
        scoped.scope === "visit-only" ||
        scoped.origin !== this.#options.origin ||
        currentDocumentOrigin !== this.#options.origin
      ) {
        route.close({ code: 1008, reason: "Secondary-origin WebSockets are observation-only" });
        return;
      }
      const server = route.connectToServer();
      route.onMessage((message) => {
        evidence.sentFrames += 1;
        evidence.sentBytes += frameByteLength(message);
        server.send(message);
      });
      server.onMessage((message) => {
        evidence.receivedFrames += 1;
        evidence.receivedBytes += frameByteLength(message);
        route.send(message);
      });
    });

    const page = await context.newPage();
    context.on("page", (candidate) => {
      if (candidate !== page) void candidate.close();
    });
    const pendingResponses: Promise<void>[] = [];

    page.on("response", (response) => {
      const resourceType = response.request().resourceType();
      if (resourceType !== "document" && resourceType !== "script") return;
      const scoped = this.#scopedUrl(response.url());
      if (!scoped) return;
      const path = this.#identifier(scoped.url);
      pendingResponses.push(
        response
          .headerValue("content-type")
          .then((contentType) => {
            this.#documents.set(path, {
              path,
              status: response.status(),
              contentType: contentType ?? "",
              truncated: false,
              origin: scoped.url.origin,
              scope: scoped.scope,
            });
          })
          .catch(() => undefined),
      );
    });

    await page.route("**/*", async (route) => {
      const request = route.request();
      const scoped = this.#scopedUrl(request.url());
      if (!scoped) {
        await route.abort("blockedbyclient");
        return;
      }
      const method = request.method().toUpperCase();
      const path = `${scoped.url.pathname}${scoped.url.search}`;
      const resourceType = request.resourceType();
      const passiveVisitOnly =
        (currentDocumentScope !== "visit-only" && scoped.scope !== "visit-only") ||
        (scoped.origin === currentDocumentOrigin &&
          ["GET", "HEAD"].includes(method) &&
          (PASSIVE_RESOURCE_TYPES.has(resourceType) ||
            (resourceType === "document" && this.#identifier(scoped.url) === currentDocument)));
      const decision = this.#options.decideRequest(method, path, {
        budgeted: true,
        automaticInteraction: this.#automaticInteraction,
        origin: scoped.url.origin,
        scope: scoped.scope,
        resourceType,
        passiveVisitOnly,
      });
      const scopeAllows =
        passiveVisitOnly &&
        (resourceType !== "document" ||
          scoped.origin === currentDocumentOrigin ||
          this.#identifier(scoped.url) === currentDocument) &&
        (scoped.scope === "attackable" ||
          (!this.#automaticInteraction && ["GET", "HEAD"].includes(method)));
      const allowed = decision.allowed && scopeAllows;
      if (
        this.#activeFormRequest &&
        method === this.#activeFormRequest.method &&
        scoped.origin === this.#activeFormRequest.origin &&
        scoped.url.pathname === this.#activeFormRequest.pathname
      ) {
        this.#activeFormRequest.allowed ||= allowed;
      }
      const blockedReason = allowed
        ? undefined
        : (decision.reason ?? "blocked by discovery origin scope");
      const observed = this.#observeRequest(
        request,
        scoped.url,
        scoped.scope,
        currentDocument,
        allowed,
        blockedReason,
      );
      if (observed) {
        this.#options.onOperationDiscovered?.(method, normalizeEndpoint(path), "browser", {
          automaticInteraction: this.#automaticInteraction,
          allowed,
          blockedReason,
          origin: scoped.url.origin,
          scope: scoped.scope,
        });
      }
      if (!allowed) {
        await route.abort("blockedbyclient");
      } else {
        await route.continue({
          headers: await this.#requestHeaders(request, scoped.origin, currentDocumentOrigin),
        });
      }
    });

    const start = new URL(this.#options.startPath, this.#options.origin).href;
    const queue = [start];
    const queued = new Set(queue);
    let visited = 0;
    while (queue.length > 0 && visited < this.#options.maxDocuments) {
      const scoped = this.#scopedUrl(queue.shift()!);
      if (!scoped) continue;
      visited += 1;
      currentDocument = this.#identifier(scoped.url);
      currentDocumentOrigin = scoped.origin;
      currentDocumentScope = scoped.scope;
      this.#automaticInteraction = false;
      await selectCookieJar(scoped.origin);
      try {
        await page.goto(scoped.url.href, {
          waitUntil: "domcontentloaded",
          timeout: this.#options.timeoutMs,
        });
      } catch (error) {
        if (!isExpectedNavigationInterruption(error)) throw error;
      }
      await page
        .waitForLoadState("networkidle", { timeout: Math.min(this.#options.timeoutMs, 1_000) })
        .catch(() => undefined);
      await page.waitForTimeout(75);
      const discoveredLinks = await scopedLinks(page, this.#scopes);
      if (scoped.scope === "attackable") {
        await this.#exploreWorkflow(page, currentDocument, (path, origin, scope) => {
          currentDocument = path;
          currentDocumentOrigin = origin;
          currentDocumentScope = scope;
        });
      } else this.#recordForms(await inspectForms(page), currentDocument);
      for (const href of [...discoveredLinks, ...(await scopedLinks(page, this.#scopes))]) {
        if (!queued.has(href)) {
          queued.add(href);
          queue.push(href);
        }
      }
      const current = this.#scopedUrl(page.url());
      if (current && !queued.has(current.url.href)) {
        queued.add(current.url.href);
        queue.push(current.url.href);
      }
    }
    this.#automaticInteraction = false;
    await Promise.all(pendingResponses);
  }

  async #exploreWorkflow(
    page: Page,
    initialDocument: string,
    setCurrentDocument: (path: string, origin: string, scope: AttackSurfaceScope) => void,
  ): Promise<void> {
    const exercised = new Set<string>();
    let documentPath = initialDocument;
    for (let step = 0; step < 4; step += 1) {
      const candidates = await inspectForms(page);
      this.#recordForms(candidates, documentPath);
      const candidate = candidates.find((form) => {
        const key = `${page.url()} ${form.index} ${form.action} ${form.method}`;
        return (
          !exercised.has(key) &&
          form.purposeful &&
          !form.destructive &&
          new URL(form.action).origin === new URL(page.url()).origin &&
          form.fields.length > 0
        );
      });
      if (!candidate) return;
      const key = `${page.url()} ${candidate.index} ${candidate.action} ${candidate.method}`;
      exercised.add(key);
      const form = page.locator("form").nth(candidate.index);
      await fillForm(form, candidate);
      const oldUrl = page.url();
      this.#automaticInteraction = true;
      const action = new URL(candidate.action);
      this.#activeFormRequest = {
        method: candidate.method,
        origin: action.origin,
        pathname: action.pathname,
        allowed: false,
      };
      const navigation = page
        .waitForNavigation({
          waitUntil: "domcontentloaded",
          timeout: this.#options.timeoutMs,
        })
        .catch(() => undefined);
      await form
        .evaluate((element: HTMLFormElement, submitterIndex) => {
          const submitters = [
            ...element.querySelectorAll<HTMLButtonElement | HTMLInputElement>(
              'button:not([disabled]), input[type="submit"]:not([disabled]), input[type="image"]:not([disabled])',
            ),
          ].filter(
            (control) =>
              control instanceof HTMLInputElement || control.type.toLowerCase() === "submit",
          );
          element.requestSubmit(submitterIndex < 0 ? undefined : submitters[submitterIndex]);
        }, candidate.submitterIndex)
        .catch(() => undefined);
      await navigation;
      await page.waitForTimeout(75);
      const submitted = this.#activeFormRequest.allowed;
      this.#activeFormRequest = undefined;
      this.#automaticInteraction = false;
      const recorded = this.#forms.findLast(
        (item) =>
          item.documentPath === documentPath &&
          item.index === candidate.index &&
          item.action === candidate.action &&
          item.method === candidate.method,
      );
      if (recorded) {
        recorded.attempted = true;
        recorded.submitted = submitted;
      }
      if (!submitted && page.url() !== oldUrl) {
        try {
          await page.goto(oldUrl, {
            waitUntil: "domcontentloaded",
            timeout: this.#options.timeoutMs,
          });
        } catch (error) {
          if (!isExpectedNavigationInterruption(error)) throw error;
        }
        await page.waitForTimeout(75);
        continue;
      }
      if (page.url() !== oldUrl) {
        const current = this.#scopedUrl(page.url());
        if (!current || current.scope !== "attackable") return;
        documentPath = this.#identifier(current.url);
        setCurrentDocument(documentPath, current.origin, current.scope);
      }
    }
  }

  #recordForms(forms: FormCandidate[], documentPath: string): void {
    for (const form of forms) {
      if (
        this.#forms.some(
          (item) =>
            item.documentPath === documentPath &&
            item.index === form.index &&
            item.action === form.action &&
            item.method === form.method,
        )
      )
        continue;
      this.#forms.push({
        index: form.index,
        documentPath,
        action: form.action,
        method: form.method,
        intent: form.intent,
        fields: form.fields.map(({ name, type, valueSource }) => ({ name, type, valueSource })),
        fileFields: form.fileFields,
        attempted: false,
        submitted: false,
      });
      if (form.fileFields.length === 0) continue;
      const scoped = this.#scopedUrl(form.action);
      if (!scoped) continue;
      this.#mergeEvidence(scoped.url, form.method, "form", undefined, {
        body: {
          contentType: form.enctype || "multipart/form-data",
          source: "form",
          fields: form.fields.map(({ name }) => name),
          files: form.fileFields.map((field) => ({ field })),
        },
      });
    }
  }

  #observeRequest(
    request: Request,
    url: URL,
    scope: AttackSurfaceScope,
    documentPath: string,
    allowed: boolean,
    blockedReason: string | undefined,
  ): boolean {
    const method = request.method().toUpperCase();
    const resourceType = request.resourceType();
    if (["script", "stylesheet", "image", "font", "media"].includes(resourceType)) return false;
    if (resourceType === "document" && method === "GET") return false;
    const headers = request.headers();
    const authentication =
      headers.authorization ||
      headers.cookie ||
      (url.origin === this.#options.origin &&
        Object.keys(this.#options.authenticationHeaders ?? {}).some(isCredentialHeaderName))
        ? "likely"
        : "unknown";
    this.#mergeEvidence(
      url,
      method,
      `browser:${resourceType}:${documentPath}`,
      {
        documentPath,
        method,
        authentication,
        allowed,
        ...(blockedReason ? { blockedReason } : {}),
      },
      {
        examplePath: `${url.pathname}${url.search}`,
        body: observeRequestBody(request),
        graphql: discoverGraphqlOperationsFromRequest(request),
        scope,
      },
    );
    return true;
  }

  #addOpenApi(input: unknown): void {
    if (!isRecord(input) || !isRecord(input.paths)) return;
    for (const [path, rawPathItem] of Object.entries(input.paths)) {
      if (!path.startsWith("/") || !isRecord(rawPathItem)) continue;
      for (const [method, rawOperation] of Object.entries(rawPathItem)) {
        const upperMethod = method.toUpperCase();
        if (!HTTP_METHODS.has(upperMethod) || !isRecord(rawOperation)) continue;
        const targets = resolveOpenApiTargets(
          input,
          rawPathItem,
          rawOperation,
          this.#options.origin,
          this.#scopes,
        );
        const bodies = extractOpenApiRequestBodies(input, rawPathItem, rawOperation);
        for (const target of targets) {
          const operationPath = `${target.prefix}${path}`.replaceAll(/\/{2,}/g, "/");
          const url = new URL(operationPath, target.origin);
          if (bodies.length === 0) {
            this.#mergeEvidence(url, upperMethod, "openapi", undefined, {
              summary: typeof rawOperation.summary === "string" ? rawOperation.summary : undefined,
              scope: target.scope,
              routePath: operationPath,
            });
          }
          for (const body of bodies) {
            this.#mergeEvidence(url, upperMethod, "openapi", undefined, {
              summary: typeof rawOperation.summary === "string" ? rawOperation.summary : undefined,
              body,
              scope: target.scope,
              routePath: operationPath,
            });
          }
          this.#options.onOperationDiscovered?.(upperMethod, operationPath, "openapi", {
            automaticInteraction: false,
            allowed: true,
            origin: target.origin,
            scope: target.scope,
          });
        }
      }
    }
  }

  #mergeEvidence(
    url: URL,
    method: string,
    source: string,
    callSite?: AttackSurfaceCallSite,
    metadata?: {
      summary?: string;
      examplePath?: string;
      body?: AttackSurfaceRequestBody;
      graphql?: AttackSurfaceGraphqlOperation[];
      scope?: AttackSurfaceScope;
      routePath?: string;
    },
  ): void {
    const path = metadata?.routePath ?? normalizeEndpoint(url.pathname);
    const key = `${url.origin} ${path}`;
    const evidence = this.#evidence.get(key) ?? {
      origin: url.origin,
      path,
      scope: metadata?.scope ?? this.#scopes.get(url.origin) ?? "visit-only",
      methods: new Set<string>(),
      sources: new Set<string>(),
      examples: new Set<string>(),
      callSites: [],
      requestBodies: [],
      graphqlOperations: [],
    };
    evidence.methods.add(method);
    evidence.sources.add(source);
    if (metadata?.examplePath) evidence.examples.add(metadata.examplePath);
    if (metadata?.body && !containsJson(evidence.requestBodies, metadata.body)) {
      evidence.requestBodies.push(metadata.body);
    }
    for (const operation of metadata?.graphql ?? []) {
      if (!containsJson(evidence.graphqlOperations, operation))
        evidence.graphqlOperations.push(operation);
    }
    if (callSite && !containsJson(evidence.callSites, callSite)) evidence.callSites.push(callSite);
    evidence.summary ??= metadata?.summary;
    this.#evidence.set(key, evidence);
  }

  #result(): AttackSurfaceMap {
    const routeDetails: AttackSurfaceRouteDetail[] = [...this.#evidence.values()]
      .map((evidence) => ({
        path:
          evidence.origin === this.#options.origin
            ? evidence.path
            : `${evidence.origin}${evidence.path}`,
        methods: [...evidence.methods].sort(),
        sources: [...evidence.sources].sort(),
        examples: [...evidence.examples].sort(),
        callSites: evidence.callSites,
        getCallSites: evidence.callSites.filter(({ method }) => method === "GET"),
        identifierSources: [],
        origin: evidence.origin,
        scope: evidence.scope,
        ...(evidence.requestBodies.length > 0 ? { requestBodies: evidence.requestBodies } : {}),
        ...(evidence.graphqlOperations.length > 0
          ? { graphqlOperations: evidence.graphqlOperations }
          : {}),
        ...(evidence.summary ? { summary: evidence.summary } : {}),
      }))
      .sort((left, right) => left.path.localeCompare(right.path));
    addIdentifierSources(routeDetails);
    return {
      startPath: this.#options.startPath,
      documents: [...this.#documents.values()],
      routes: routeDetails.map(({ path }) => path),
      routeDetails,
      forms: this.#forms,
      webSockets: this.#webSockets,
    };
  }

  #identifier(url: URL): string {
    const path = `${url.pathname}${url.search}`;
    return url.origin === this.#options.origin ? path : `${url.origin}${path}`;
  }

  async #requestHeaders(
    request: Request,
    origin: string,
    documentOrigin: string,
  ): Promise<Record<string, string>> {
    const headers = await request.allHeaders();
    if (origin === this.#options.origin && documentOrigin === this.#options.origin) {
      return { ...headers, ...this.#options.authenticationHeaders };
    }
    return {
      ...Object.fromEntries(
        Object.entries(headers).filter(([name]) => !isCredentialHeaderName(name)),
      ),
      cookie: "",
    };
  }

  #scopedUrl(
    candidate: string,
  ): { url: URL; origin: string; scope: AttackSurfaceScope } | undefined {
    try {
      const url = new URL(candidate, this.#options.origin);
      const origin =
        url.protocol === "ws:"
          ? `http://${url.host}`
          : url.protocol === "wss:"
            ? `https://${url.host}`
            : url.origin;
      const scope = this.#scopes.get(origin);
      return scope ? { url, origin, scope } : undefined;
    } catch {
      return undefined;
    }
  }
}

const HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const PASSIVE_RESOURCE_TYPES = new Set(["script", "stylesheet", "image", "font", "media"]);

export function normalizeAttackSurfaceOrigins(
  primaryOrigin: string,
  configured: readonly AttackSurfaceOrigin[] = [],
): ReadonlyMap<string, AttackSurfaceScope> {
  const primary = exactHttpOrigin(primaryOrigin);
  const scopes = new Map<string, AttackSurfaceScope>();
  for (const candidate of configured) {
    const origin = exactHttpOrigin(candidate.origin);
    if (scopes.get(origin) !== "attackable") scopes.set(origin, candidate.scope);
  }
  scopes.set(primary, "attackable");
  return scopes;
}

function exactHttpOrigin(candidate: string): string {
  const url = new URL(candidate);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error(`Discovery origin must be an HTTP(S) origin: ${candidate}`);
  }
  if (`${url.origin}/` !== url.href) {
    throw new Error(`Discovery origin must not include a path, query, or fragment: ${candidate}`);
  }
  return url.origin;
}

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

interface OpenApiTarget {
  origin: string;
  prefix: string;
  scope: AttackSurfaceScope;
}

function resolveOpenApiTargets(
  document: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  operation: Record<string, unknown>,
  primaryOrigin: string,
  scopes: ReadonlyMap<string, AttackSurfaceScope>,
): OpenApiTarget[] {
  if (typeof document.swagger === "string" && document.swagger.startsWith("2.")) {
    const basePath = normalizePrefix(
      typeof document.basePath === "string" ? document.basePath : "",
    );
    if (typeof document.host !== "string") {
      return [{ origin: primaryOrigin, prefix: basePath, scope: "attackable" }];
    }
    const schemes = Array.isArray(document.schemes)
      ? document.schemes.filter((value): value is string => typeof value === "string")
      : [new URL(primaryOrigin).protocol.replace(":", "")];
    return schemes.flatMap((scheme): OpenApiTarget[] => {
      try {
        const origin = new URL(`${scheme}://${document.host}`).origin;
        const scope = scopes.get(origin);
        return scope ? [{ origin, prefix: basePath, scope }] : [];
      } catch {
        return [];
      }
    });
  }

  let servers: unknown = "servers" in document ? document.servers : undefined;
  if ("servers" in pathItem) servers = pathItem.servers;
  if ("servers" in operation) servers = operation.servers;
  if (servers === undefined) {
    return [{ origin: primaryOrigin, prefix: "", scope: "attackable" }];
  }
  if (!Array.isArray(servers)) return [];
  return uniqueJson(
    servers.flatMap((server): OpenApiTarget[] => {
      if (!isRecord(server) || typeof server.url !== "string" || server.url.includes("{"))
        return [];
      try {
        const url = new URL(server.url, primaryOrigin);
        const scope = scopes.get(url.origin);
        return scope ? [{ origin: url.origin, prefix: normalizePrefix(url.pathname), scope }] : [];
      } catch {
        return [];
      }
    }),
  );
}

function resolveDeclaredServerPrefixes(
  owner: Record<string, unknown>,
  origin: string,
  inherited: string[],
): string[] {
  if (!("servers" in owner)) return inherited;
  if (!Array.isArray(owner.servers)) return [];
  const prefixes = owner.servers.flatMap((server) => {
    if (!isRecord(server) || typeof server.url !== "string" || server.url.includes("{")) return [];
    try {
      const url = new URL(server.url, origin);
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

export function extractOpenApiRequestBodies(
  document: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  operation: Record<string, unknown>,
): AttackSurfaceRequestBody[] {
  const requestBody = resolveLocalReference(document, operation.requestBody);
  if (isRecord(requestBody) && isRecord(requestBody.content)) {
    return Object.entries(requestBody.content).flatMap(([contentType, rawMedia]) => {
      const media = resolveLocalReference(document, rawMedia);
      if (!isRecord(media)) return [];
      const examples: unknown[] = [];
      if ("example" in media) examples.push(media.example);
      if (isRecord(media.examples)) {
        for (const rawExample of Object.values(media.examples)) {
          const example = resolveLocalReference(document, rawExample);
          if (isRecord(example) && "value" in example) examples.push(example.value);
        }
      }
      const rawSchema = media.schema;
      const schema = resolveLocalReference(document, rawSchema);
      if (isRecord(schema) && "example" in schema) examples.push(schema.example);
      const generated = schemaExample(document, schema);
      if (generated !== undefined) examples.push(generated);
      const multipart = contentType.toLowerCase().startsWith("multipart/form-data")
        ? multipartSchemaMetadata(document, rawSchema)
        : {};
      const bodies = uniqueJson(examples)
        .map((example) => redactExampleWithSchema(document, example, rawSchema))
        .filter((example) => example !== undefined)
        .map((example) => ({ contentType, source: "openapi" as const, example, ...multipart }));
      return bodies.length > 0
        ? bodies
        : [{ contentType, source: "openapi" as const, ...multipart }];
    });
  }

  const parameters = [
    ...(Array.isArray(pathItem.parameters) ? pathItem.parameters : []),
    ...(Array.isArray(operation.parameters) ? operation.parameters : []),
  ]
    .map((parameter) => resolveLocalReference(document, parameter))
    .filter(isRecord);
  const body = parameters.find((parameter) => parameter.in === "body");
  if (body) {
    const schema = resolveLocalReference(document, body.schema);
    const rawExample =
      "x-example" in body ? safeExample(body["x-example"]) : schemaExample(document, schema);
    const example =
      (typeof body.name === "string" && isSensitiveExampleKey(body.name)) ||
      isSensitiveSchema(document, body.schema)
        ? "[redacted]"
        : redactExampleWithSchema(document, rawExample, body.schema);
    return [
      {
        contentType:
          firstString(operation.consumes) ?? firstString(document.consumes) ?? "application/json",
        source: "openapi",
        ...(example === undefined ? {} : { example }),
      },
    ];
  }
  const form = parameters.filter((parameter) => parameter.in === "formData");
  if (form.length === 0) return [];
  const fields = form
    .filter((parameter) => parameter.type !== "file")
    .map((parameter) => parameter.name)
    .filter((name): name is string => typeof name === "string");
  const files = form.flatMap((parameter) =>
    parameter.type === "file" && typeof parameter.name === "string"
      ? [{ field: parameter.name }]
      : [],
  );
  const example = Object.fromEntries(
    form.flatMap((parameter) => {
      if (parameter.type === "file" || typeof parameter.name !== "string") return [];
      const value = schemaExample(document, parameter);
      return value === undefined
        ? []
        : [[parameter.name, redactExampleWithSchema(document, value, parameter)]];
    }),
  );
  return [
    {
      contentType:
        firstString(operation.consumes) ??
        firstString(document.consumes) ??
        (files.length > 0 ? "multipart/form-data" : "application/x-www-form-urlencoded"),
      source: "openapi",
      ...(Object.keys(example).length > 0 ? { example: safeExample(example) } : {}),
      fields,
      files,
    },
  ];
}

function multipartSchemaMetadata(
  document: Record<string, unknown>,
  rawSchema: unknown,
): Pick<AttackSurfaceRequestBody, "fields" | "files"> {
  const fields: string[] = [];
  const files: Array<{ field: string }> = [];
  for (const [name, property] of collectSchemaProperties(document, rawSchema)) {
    if (isBinarySchema(document, property)) files.push({ field: name });
    else fields.push(name);
  }
  return fields.length > 0 || files.length > 0 ? { fields, files } : {};
}

function collectSchemaProperties(
  document: Record<string, unknown>,
  rawSchema: unknown,
  depth = 0,
): Map<string, unknown> {
  const properties = new Map<string, unknown>();
  if (depth > 8) return properties;
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return properties;
  if (isRecord(schema.properties)) {
    for (const [name, property] of Object.entries(schema.properties))
      properties.set(name, property);
  }
  for (const composition of ["allOf", "oneOf", "anyOf"] as const) {
    if (!Array.isArray(schema[composition])) continue;
    for (const part of schema[composition]) {
      for (const [name, property] of collectSchemaProperties(document, part, depth + 1)) {
        properties.set(name, property);
      }
    }
  }
  return properties;
}

function isBinarySchema(document: Record<string, unknown>, rawSchema: unknown, depth = 0): boolean {
  if (depth > 8) return false;
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return false;
  if (schema.format === "binary") return true;
  if (schema.type === "array" && isBinarySchema(document, schema.items, depth + 1)) return true;
  return ["allOf", "oneOf", "anyOf"].some(
    (composition) =>
      Array.isArray(schema[composition]) &&
      schema[composition].some((part: unknown) => isBinarySchema(document, part, depth + 1)),
  );
}

function schemaExample(document: Record<string, unknown>, rawSchema: unknown, depth = 0): unknown {
  if (depth > 6) return undefined;
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return undefined;
  if ("example" in schema) return safeExample(schema.example);
  if ("default" in schema) return safeExample(schema.default);
  if ("const" in schema) return safeExample(schema.const);
  if (Array.isArray(schema.enum) && schema.enum.length > 0) return safeExample(schema.enum[0]);
  for (const composition of ["oneOf", "anyOf"] as const) {
    if (Array.isArray(schema[composition])) {
      const value = schemaExample(document, schema[composition][0], depth + 1);
      if (value !== undefined) return value;
    }
  }
  if (Array.isArray(schema.allOf)) {
    const values = schema.allOf.map((part) => schemaExample(document, part, depth + 1));
    if (values.every(isRecord)) return Object.assign({}, ...values);
  }
  if (schema.type === "object" || isRecord(schema.properties)) {
    if (!isRecord(schema.properties)) return {};
    return Object.fromEntries(
      Object.entries(schema.properties)
        .slice(0, 24)
        .flatMap(([name, property]) => {
          const value = schemaExample(document, property, depth + 1);
          return value === undefined ? [] : [[name, value]];
        }),
    );
  }
  if (schema.type === "array") {
    const value = schemaExample(document, schema.items, depth + 1);
    return value === undefined ? [] : [value];
  }
  if (schema.type === "integer" || schema.type === "number") return schema.minimum ?? 1;
  if (schema.type === "boolean") return true;
  if (schema.type === "null") return null;
  if (schema.type === "string" || typeof schema.format === "string") {
    if (schema.format === "binary") return undefined;
    if (schema.format === "date") return "2024-01-01";
    if (schema.format === "date-time") return "2024-01-01T00:00:00Z";
    if (schema.format === "email") return "quiver@example.invalid";
    if (schema.format === "uuid") return "00000000-0000-4000-8000-000000000001";
    if (["uri", "url"].includes(String(schema.format))) return "https://example.invalid/";
    return typeof schema.pattern === "string" ? undefined : "quiver";
  }
  return undefined;
}

function isSensitiveSchema(document: Record<string, unknown>, rawSchema: unknown): boolean {
  const schema = resolveLocalReference(document, rawSchema);
  const reference = isRecord(rawSchema) && typeof rawSchema.$ref === "string" ? rawSchema.$ref : "";
  if (!isRecord(schema)) return isSensitiveExampleKey(reference);
  if (schema["x-sensitive"] === true || schema.format === "password") return true;
  return [reference, schema.title, schema.name]
    .filter((value): value is string => typeof value === "string")
    .some(isSensitiveExampleKey);
}

function redactExampleWithSchema(
  document: Record<string, unknown>,
  value: unknown,
  rawSchema: unknown,
): unknown {
  return redactSchemaValue(document, safeExample(value), rawSchema, 0);
}

function redactSchemaValue(
  document: Record<string, unknown>,
  value: unknown,
  rawSchema: unknown,
  depth: number,
): unknown {
  if (depth > 8 || value === undefined) return value;
  if (isBinarySchema(document, rawSchema)) return "[file content omitted]";
  if (isSensitiveSchema(document, rawSchema)) return "[redacted]";
  const schema = resolveLocalReference(document, rawSchema);
  if (!isRecord(schema)) return value;
  let redacted: unknown = value;
  for (const composition of ["allOf", "oneOf", "anyOf"] as const) {
    if (!Array.isArray(schema[composition])) continue;
    for (const part of schema[composition]) {
      redacted = redactSchemaValue(document, redacted, part, depth + 1);
    }
  }
  if (Array.isArray(redacted) && schema.items !== undefined) {
    return redacted.map((item) => redactSchemaValue(document, item, schema.items, depth + 1));
  }
  if (!isRecord(redacted)) return redacted;
  const properties = isRecord(schema.properties) ? schema.properties : {};
  return Object.fromEntries(
    Object.entries(redacted).map(([key, child]) => {
      if (isSensitiveExampleKey(key)) return [key, "[redacted]"];
      const childSchema = properties[key] ?? schema.additionalProperties;
      return [
        key,
        childSchema === undefined
          ? child
          : redactSchemaValue(document, child, childSchema, depth + 1),
      ];
    }),
  );
}

function resolveLocalReference(document: Record<string, unknown>, value: unknown): unknown {
  if (!isRecord(value) || typeof value.$ref !== "string" || !value.$ref.startsWith("#/")) {
    return value;
  }
  let current: unknown = document;
  for (const encoded of value.$ref.slice(2).split("/")) {
    const part = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (!isRecord(current) || !(part in current)) return undefined;
    current = current[part];
  }
  return current;
}

function observeRequestBody(request: Request): AttackSurfaceRequestBody | undefined {
  const postData = request.postData();
  if (postData === null) return undefined;
  const contentType = request.headers()["content-type"]?.split(";", 1)[0]?.trim() ?? "";
  if (contentType === "application/json" || contentType.endsWith("+json")) {
    try {
      return { contentType, source: "browser", example: safeExample(JSON.parse(postData)) };
    } catch {
      return { contentType, source: "browser" };
    }
  }
  if (contentType === "application/x-www-form-urlencoded") {
    const values = Object.fromEntries(new URLSearchParams(postData));
    return {
      contentType,
      source: "browser",
      example: safeExample(values),
      fields: Object.keys(values),
    };
  }
  if (contentType === "multipart/form-data") return observeMultipart(postData);
  return { contentType: contentType || "application/octet-stream", source: "browser" };
}

function observeMultipart(postData: string): AttackSurfaceRequestBody {
  const fields: string[] = [];
  const files: NonNullable<AttackSurfaceRequestBody["files"]> = [];
  for (const match of postData.matchAll(/content-disposition:\s*form-data;([^\r\n]*)/gi)) {
    const parameters = match[1] ?? "";
    const name = /\bname="([^"]+)"/i.exec(parameters)?.[1];
    if (!name) continue;
    const fileName = /\bfilename="([^"]*)"/i.exec(parameters)?.[1];
    if (fileName !== undefined) files.push({ field: name, fileName });
    else fields.push(name);
  }
  return {
    contentType: "multipart/form-data",
    source: "browser",
    fields: [...new Set(fields)],
    files: uniqueJson(files),
  };
}

export function discoverGraphqlOperations(query: string): AttackSurfaceGraphqlOperation[] {
  const tokens = graphqlTokens(query);
  const operations: AttackSurfaceGraphqlOperation[] = [];
  let index = 0;
  while (index < tokens.length) {
    if (tokens[index] === "fragment") {
      while (index < tokens.length && tokens[index] !== "{") index += 1;
      index = tokens[index] === "{" ? skipGraphqlGroup(tokens, index, "{", "}") : tokens.length;
      continue;
    }
    let type: AttackSurfaceGraphqlOperation["type"] = "query";
    let name: string | undefined;
    if (["query", "mutation", "subscription"].includes(tokens[index] ?? "")) {
      type = tokens[index] as AttackSurfaceGraphqlOperation["type"];
      index += 1;
      if (isGraphqlName(tokens[index]) && tokens[index] !== "on") name = tokens[index++];
      if (tokens[index] === "(") index = skipGraphqlGroup(tokens, index, "(", ")");
      while (tokens[index] === "@") {
        index += 2;
        if (tokens[index] === "(") index = skipGraphqlGroup(tokens, index, "(", ")");
      }
      while (index < tokens.length && tokens[index] !== "{") index += 1;
    } else if (tokens[index] !== "{") {
      index += 1;
      continue;
    }
    if (tokens[index] !== "{") break;
    const rootFields: string[] = [];
    let depth = 0;
    for (; index < tokens.length; index += 1) {
      const token = tokens[index]!;
      if (token === "{") {
        depth += 1;
        continue;
      }
      if (token === "}") {
        depth -= 1;
        if (depth === 0) {
          index += 1;
          break;
        }
        continue;
      }
      if (depth === 1 && token === "...") {
        while (index + 1 < tokens.length && !["{", "}"].includes(tokens[index + 1]!)) {
          index += 1;
        }
        continue;
      }
      if (depth !== 1 || !isGraphqlName(token)) continue;
      const aliased = tokens[index + 1] === ":" && isGraphqlName(tokens[index + 2]);
      const field = aliased ? tokens[index + 2]! : token;
      if (!rootFields.includes(field) && !["fragment", "on"].includes(field)) {
        rootFields.push(field);
      }
      let cursor = index + (aliased ? 3 : 1);
      if (tokens[cursor] === "(") cursor = skipGraphqlGroup(tokens, cursor, "(", ")");
      while (tokens[cursor] === "@") {
        cursor += 2;
        if (tokens[cursor] === "(") cursor = skipGraphqlGroup(tokens, cursor, "(", ")");
      }
      index = cursor - 1;
    }
    operations.push({ type, ...(name ? { name } : {}), rootFields });
  }
  return operations;
}

function discoverGraphqlOperationsFromRequest(request: Request): AttackSurfaceGraphqlOperation[] {
  const queries = new URL(request.url()).searchParams.getAll("query");
  const postData = request.postData();
  if (postData) {
    const contentType = request.headers()["content-type"] ?? "";
    if (contentType.includes("json")) {
      try {
        const body: unknown = JSON.parse(postData);
        for (const entry of Array.isArray(body) ? body : [body]) {
          if (isRecord(entry) && typeof entry.query === "string") queries.push(entry.query);
        }
      } catch {
        // The malformed body remains visible as body-format metadata.
      }
    } else if (contentType.includes("application/x-www-form-urlencoded")) {
      const query = new URLSearchParams(postData).get("query");
      if (query) queries.push(query);
    } else if (contentType.includes("multipart/form-data")) {
      for (const match of postData.matchAll(/\r?\n\r?\n({[\s\S]*?})\r?\n--/g)) {
        try {
          const body: unknown = JSON.parse(match[1]!);
          if (isRecord(body) && typeof body.query === "string") queries.push(body.query);
        } catch {
          // Ignore file data and unrelated multipart fields.
        }
      }
    }
  }
  return uniqueJson(queries.flatMap(discoverGraphqlOperations));
}

function graphqlTokens(query: string): string[] {
  const scrubbed = query
    .replace(/#[^\r\n]*/g, " ")
    .replace(/"""[\s\S]*?"""/g, " ")
    .replace(/"(?:\\.|[^"\\])*"/g, " ");
  return scrubbed.match(/\.\.\.|\$?[_A-Za-z][_0-9A-Za-z]*|[{}():@!,]|\[|\]/g) ?? [];
}

function skipGraphqlGroup(
  tokens: readonly string[],
  start: number,
  open: string,
  close: string,
): number {
  let depth = 0;
  for (let index = start; index < tokens.length; index += 1) {
    if (tokens[index] === open) depth += 1;
    if (tokens[index] === close) {
      depth -= 1;
      if (depth === 0) return index + 1;
    }
  }
  return tokens.length;
}

function isGraphqlName(value: string | undefined): value is string {
  return value !== undefined && /^[_A-Za-z][_0-9A-Za-z]*$/.test(value);
}

async function inspectForms(page: Page): Promise<FormCandidate[]> {
  return page
    .locator("form")
    .evaluateAll((forms) =>
      forms.map((form, index) => {
        const element = form as HTMLFormElement;
        const baseIntent = [
          element.getAttribute("aria-label"),
          element.getAttribute("name"),
          element.getAttribute("id"),
          element.querySelector("legend")?.textContent,
        ]
          .filter(Boolean)
          .join(" ")
          .trim();
        const submitters = [
          ...element.querySelectorAll<HTMLButtonElement | HTMLInputElement>(
            'button:not([disabled]), input[type="submit"]:not([disabled]), input[type="image"]:not([disabled])',
          ),
        ].filter(
          (control) =>
            control instanceof HTMLInputElement || control.type.toLowerCase() === "submit",
        );
        const submitterIndex = submitters.findIndex((control) => {
          const hint = `${baseIntent} ${control.textContent ?? ""} ${control.value} ${control.formAction}`;
          return (
            /\b(search|filter|find|lookup|login|log\s*in|sign\s*in|authenticate|continue|next|step|verify)\b/i.test(
              hint,
            ) &&
            !/\b(delete|destroy|remove|revoke|logout|sign\s*out|unsubscribe|purchase|pay|checkout|transfer|reset|wipe)\b/i.test(
              hint,
            )
          );
        });
        const selectedSubmitter = submitters[submitterIndex < 0 ? 0 : submitterIndex];
        const effectiveSubmitterIndex = selectedSubmitter
          ? submitters.indexOf(selectedSubmitter)
          : -1;
        const intent =
          [baseIntent, selectedSubmitter?.textContent, selectedSubmitter?.value]
            .filter(Boolean)
            .join(" ")
            .trim() || "form submission";
        const action = selectedSubmitter?.hasAttribute("formaction")
          ? selectedSubmitter.formAction
          : element.action;
        const method =
          (selectedSubmitter?.hasAttribute("formmethod")
            ? selectedSubmitter.formMethod
            : element.method
          ).toUpperCase() || "GET";
        const enctype = selectedSubmitter?.hasAttribute("formenctype")
          ? selectedSubmitter.formEnctype
          : element.enctype;
        const fields = [...element.elements].flatMap((rawControl) => {
          if (
            !(
              rawControl instanceof HTMLInputElement ||
              rawControl instanceof HTMLTextAreaElement ||
              rawControl instanceof HTMLSelectElement
            ) ||
            rawControl.disabled ||
            !rawControl.name
          )
            return [];
          const control = rawControl;
          const type =
            control instanceof HTMLInputElement
              ? control.type.toLowerCase()
              : control instanceof HTMLSelectElement
                ? "select"
                : "textarea";
          if (["submit", "button", "reset", "image", "file", "hidden"].includes(type)) return [];
          let value: string | undefined;
          let valueSource = "semantic";
          if (control.value && type !== "password") {
            value = control.value;
            valueSource = "existing";
          } else if (control instanceof HTMLSelectElement) {
            value = [...control.options].find((option) => !option.disabled && option.value)?.value;
            valueSource = "option";
          } else if (["checkbox", "radio"].includes(type)) {
            value = "true";
            valueSource = "control-type";
          } else {
            const hint =
              `${control.name} ${control.id} ${control.getAttribute("autocomplete") ?? ""} ${control.getAttribute("placeholder") ?? ""}`.toLowerCase();
            if (type === "email" || hint.includes("email")) value = "quiver@example.invalid";
            else if (type === "url" || hint.includes("url")) value = "https://example.invalid/";
            else if (type === "number" || type === "range")
              value = control.getAttribute("min") ?? "1";
            else if (type === "date") value = "2024-01-01";
            else if (type === "datetime-local") value = "2024-01-01T00:00";
            else if (type === "password") value = "quiver-discovery";
            else if (/code|otp|token/.test(hint)) value = "000000";
            else value = control.getAttribute("placeholder") || "quiver";
          }
          return [{ name: control.name, type, value, valueSource }];
        });
        const fileFields = [
          ...element.querySelectorAll<HTMLInputElement>('input[type="file"][name]'),
        ]
          .filter((input) => !input.disabled)
          .map((input) => input.name);
        return {
          index,
          submitterIndex: effectiveSubmitterIndex,
          action,
          method,
          enctype,
          intent,
          destructive:
            /\b(delete|destroy|remove|revoke|logout|sign\s*out|unsubscribe|purchase|pay|checkout|transfer|reset|wipe|cancel|close|deactivate|disable|terminate|suspend|archive|erase|purge)\b/i.test(
              `${intent} ${action}`,
            ),
          purposeful:
            /\b(search|filter|find|lookup|login|log\s*in|sign\s*in|authenticate|continue|next|step|verify)\b/i.test(
              `${intent} ${action}`,
            ),
          fields,
          fileFields,
        };
      }),
    )
    .catch(() => []);
}

async function fillForm(form: Locator, candidate: FormCandidate): Promise<void> {
  for (const field of candidate.fields) {
    const control = form.locator(`[name=${JSON.stringify(field.name)}]`).first();
    if (["checkbox", "radio"].includes(field.type)) {
      await control.check({ timeout: 500 }).catch(() => undefined);
    } else if (field.type === "select" && field.value !== undefined) {
      await control.selectOption(field.value).catch(() => undefined);
    } else if (field.value !== undefined) {
      await control.fill(field.value, { timeout: 500 }).catch(() => undefined);
    }
  }
}

async function scopedLinks(
  page: Page,
  scopes: ReadonlyMap<string, AttackSurfaceScope>,
): Promise<string[]> {
  return page
    .locator("a[href]")
    .evaluateAll(
      (anchors, origins) => [
        ...new Set(
          anchors.flatMap((anchor) => {
            try {
              const href = (anchor as HTMLAnchorElement).href;
              return origins.includes(new URL(href).origin) ? [href] : [];
            } catch {
              return [];
            }
          }),
        ),
      ],
      [...scopes.keys()],
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
            candidate.origin === detail.origin &&
            candidate.path !== detail.path &&
            (candidate.path === prefix ||
              prefix.startsWith(`${candidate.path}/`) ||
              candidate.path.startsWith(`${prefix}/`)),
        )
        .sort((left, right) => right.path.length - left.path.length)[0];
      if (source)
        detail.identifierSources.push({ parameter: parameter.name, sourcePath: source.path });
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

function frameByteLength(payload: string | Buffer): number {
  return typeof payload === "string" ? Buffer.byteLength(payload) : payload.byteLength;
}

function safeExample(value: unknown): unknown {
  try {
    const json = JSON.stringify(value);
    if (json === undefined) return undefined;
    if (json.length > 8_000) return "[example truncated]";
    return redactSensitiveExample(JSON.parse(json) as unknown);
  } catch {
    return undefined;
  }
}

function redactSensitiveExample(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSensitiveExample);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, child]) => [
      key,
      isSensitiveExampleKey(key) ? "[redacted]" : redactSensitiveExample(child),
    ]),
  );
}

function isSensitiveExampleKey(key: string): boolean {
  const parts = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  return (
    parts.some((part) =>
      [
        "auth",
        "authorization",
        "cookie",
        "credential",
        "password",
        "secret",
        "session",
        "signature",
        "token",
      ].includes(part),
    ) ||
    (parts.includes("key") &&
      parts.some((part) => ["access", "api", "client", "private", "security"].includes(part)))
  );
}

function isCredentialHeaderName(name: string): boolean {
  const parts = name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  return (
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
    ) ||
    (parts.includes("key") &&
      parts.some((part) => ["access", "api", "client", "private", "security"].includes(part)))
  );
}

function containsJson(values: readonly unknown[], candidate: unknown): boolean {
  const json = JSON.stringify(candidate);
  return values.some((value) => JSON.stringify(value) === json);
}

function uniqueJson<T>(values: readonly T[]): T[] {
  return values.filter(
    (value, index) =>
      values.findIndex((candidate) => JSON.stringify(candidate) === JSON.stringify(value)) ===
      index,
  );
}

function firstString(value: unknown): string | undefined {
  return Array.isArray(value)
    ? value.find((entry): entry is string => typeof entry === "string")
    : undefined;
}

function isRecord(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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
