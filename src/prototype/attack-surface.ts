import { access } from "node:fs/promises";
import {
  chromium,
  type Browser,
  type BrowserContext,
  type Page,
  type Request,
} from "playwright-core";
import { fillForm, inspectForms, type FormCandidate } from "./discovery/forms.ts";
import { normalizeEndpoint } from "./endpoint.ts";
import {
  extractOpenApiRequestBodies,
  normalizeAttackSurfaceOrigins,
  resolveOpenApiTargets,
} from "./discovery/openapi.ts";
import {
  discoverGraphqlOperationsFromRequest,
  observeRequestBody,
} from "./discovery/request-evidence.ts";
import { observeWebSocketTraffic } from "./discovery/websocket.ts";
import { classifyHttpStatus, type RuntimeRequestLease } from "./runtime-safety.ts";
import { isCredentialHeaderName } from "./security/credentials.ts";

export { discoverGraphqlOperations } from "./discovery/graphql.ts";
export {
  extractOpenApiRequestBodies,
  normalizeAttackSurfaceOrigins,
  resolveEffectiveOpenApiPrefixes,
  resolveOpenApiPrefixes,
} from "./discovery/openapi.ts";

export type AttackSurfaceScope = "attackable" | "visit-only" | "auth-only" | "blocked";

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
  commitRequest?: (
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
  acquireRequest?: () => Promise<RuntimeRequestLease>;
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

/** Maps browser-observed workflows and supplied API descriptions without testing findings. */
export class BrowserAttackSurfaceMapper {
  readonly #options: BrowserAttackSurfaceMapperOptions;
  readonly #scopes: ReadonlyMap<string, AttackSurfaceScope>;
  readonly #evidence = new Map<string, MutableRouteEvidence>();
  readonly #documents = new Map<string, AttackSurfaceDocument>();
  readonly #forms: AttackSurfaceForm[] = [];
  readonly #webSockets: AttackSurfaceWebSocket[] = [];
  readonly #requestLeases = new Map<Request, RuntimeRequestLease>();
  #automaticInteraction = false;
  #activeFormRequest?: {
    method: string;
    origin: string;
    pathname: string;
    allowed: boolean;
    observed: boolean;
    settle: () => void;
  };

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
      for (const lease of this.#requestLeases.values()) lease.fail();
      this.#requestLeases.clear();
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
        scoped.scope !== "attackable" ||
        scoped.origin !== this.#options.origin ||
        currentDocumentOrigin !== this.#options.origin
      ) {
        route.close({ code: 1008, reason: "Secondary-origin WebSockets are observation-only" });
        return;
      }
      observeWebSocketTraffic(route, evidence);
    });

    const page = await context.newPage();
    context.on("requestfinished", (request) => {
      const lease = this.#requestLeases.get(request);
      if (!lease) return;
      this.#requestLeases.delete(request);
      void request
        .response()
        .then((response) => lease.finish(classifyHttpStatus(response?.status() ?? 0)))
        .catch(() => lease.fail());
    });
    context.on("requestfailed", (request) => {
      const lease = this.#requestLeases.get(request);
      if (!lease) return;
      this.#requestLeases.delete(request);
      lease.fail();
    });
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
      const metadata: BrowserRequestMetadata = {
        budgeted: true,
        automaticInteraction: this.#automaticInteraction,
        origin: scoped.url.origin,
        scope: scoped.scope,
        resourceType,
        passiveVisitOnly,
      };
      const decision = this.#options.decideRequest(method, path, metadata);
      const scopeAllows =
        passiveVisitOnly &&
        (resourceType !== "document" ||
          scoped.origin === currentDocumentOrigin ||
          this.#identifier(scoped.url) === currentDocument) &&
        (scoped.scope === "attackable" ||
          (!this.#automaticInteraction && ["GET", "HEAD"].includes(method)));
      let allowed = decision.allowed && scopeAllows;
      let admissionReason: string | undefined;
      let lease: RuntimeRequestLease | undefined;
      const formAttempt =
        this.#activeFormRequest &&
        method === this.#activeFormRequest.method &&
        scoped.origin === this.#activeFormRequest.origin &&
        scoped.url.pathname === this.#activeFormRequest.pathname
          ? this.#activeFormRequest
          : undefined;
      if (formAttempt) formAttempt.observed = true;
      if (allowed && this.#options.acquireRequest) {
        try {
          lease = await this.#options.acquireRequest();
          this.#requestLeases.set(request, lease);
          if (formAttempt && this.#activeFormRequest !== formAttempt) {
            allowed = false;
            admissionReason = "form attempt expired while waiting for request admission";
            this.#requestLeases.delete(request);
            lease.release();
            lease = undefined;
          }
        } catch (error) {
          allowed = false;
          admissionReason = error instanceof Error ? error.message : String(error);
        }
      }
      if (allowed && this.#options.commitRequest) {
        const committed = this.#options.commitRequest(method, path, metadata);
        if (!committed.allowed) {
          allowed = false;
          admissionReason = committed.reason ?? "request budget exhausted before admission";
          this.#requestLeases.delete(request);
          lease?.release();
          lease = undefined;
        }
      }
      if (formAttempt && this.#activeFormRequest === formAttempt) {
        formAttempt.allowed ||= allowed;
        formAttempt.settle();
      }
      const blockedReason = allowed
        ? undefined
        : (admissionReason ?? decision.reason ?? "blocked by discovery origin scope");
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
        if (request.isNavigationRequest()) {
          await route.fulfill({ status: 204, body: "" });
        } else {
          await route.abort("blockedbyclient");
        }
      } else {
        try {
          await route.continue({
            headers: await this.#requestHeaders(request, scoped.origin, currentDocumentOrigin),
          });
        } catch (error) {
          this.#requestLeases.delete(request);
          lease?.fail();
          throw error;
        }
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
      const form = page.locator("form").nth(candidate.index);
      await fillForm(form, candidate);
      const oldUrl = page.url();
      this.#automaticInteraction = true;
      const action = new URL(candidate.action);
      let settleRequest!: () => void;
      const requestDecision = new Promise<void>((resolve) => {
        settleRequest = resolve;
      });
      this.#activeFormRequest = {
        method: candidate.method,
        origin: action.origin,
        pathname: action.pathname,
        allowed: false,
        observed: false,
        settle: settleRequest,
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
      await Promise.race([
        navigation,
        requestDecision,
        page.waitForTimeout(Math.min(500, this.#options.timeoutMs)),
      ]);
      if (this.#activeFormRequest.observed) exercised.add(key);
      if (this.#activeFormRequest.allowed) await navigation;
      await page.waitForTimeout(75);
      const attempted = this.#activeFormRequest.observed;
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
        recorded.attempted = attempted;
        recorded.submitted = submitted;
      }
      if (!submitted) {
        if (attempted) await navigation;
        if (page.url() !== oldUrl) {
          try {
            await page.goto(oldUrl, {
              waitUntil: "domcontentloaded",
              timeout: this.#options.timeoutMs,
            });
          } catch (error) {
            if (!isExpectedNavigationInterruption(error)) throw error;
          }
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
      return scope && scope !== "blocked" && scope !== "auth-only"
        ? { url, origin, scope }
        : undefined;
    } catch {
      return undefined;
    }
  }
}

const HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const PASSIVE_RESOURCE_TYPES = new Set(["script", "stylesheet", "image", "font", "media"]);

async function scopedLinks(
  page: Page,
  scopes: ReadonlyMap<string, AttackSurfaceScope>,
): Promise<string[]> {
  const visitableOrigins = [...scopes]
    .filter(([, scope]) => scope === "attackable" || scope === "visit-only")
    .map(([origin]) => origin);
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
      visitableOrigins,
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

function containsJson(values: readonly unknown[], candidate: unknown): boolean {
  const json = JSON.stringify(candidate);
  return values.some((value) => JSON.stringify(value) === json);
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
