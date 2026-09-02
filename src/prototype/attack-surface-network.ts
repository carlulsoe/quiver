import type { BrowserContext, Page } from "playwright-core";
import { normalizeEndpoint } from "./endpoint.ts";
import { observeWebSocketTraffic } from "./discovery/websocket.ts";
import { classifyHttpStatus, type RuntimeRequestLease } from "./runtime-safety.ts";
import { observeRequest } from "./attack-surface-observation.ts";
import { attackSurfaceIdentifier, requestHeaders, scopedUrl } from "./attack-surface-scope.ts";
import type { AttackSurfaceState, CurrentDocument } from "./attack-surface-state.ts";
import type { AttackSurfaceWebSocket, BrowserRequestMetadata } from "./attack-surface-types.ts";

const PASSIVE_RESOURCE_TYPES = new Set(["script", "stylesheet", "image", "font", "media"]);

export async function attachAttackSurfaceNetwork(
  state: AttackSurfaceState,
  context: BrowserContext,
  page: Page,
  current: CurrentDocument,
  pendingResponses: Promise<void>[],
): Promise<void> {
  await context.routeWebSocket("**/*", (route) => {
    const scoped = scopedUrl(state, route.url());
    if (!scoped) {
      route.close({ code: 1008, reason: "Origin is outside discovery scope" });
      return;
    }
    const evidence: AttackSurfaceWebSocket = {
      url: route.url(),
      origin: scoped.origin,
      path: `${scoped.url.pathname}${scoped.url.search}`,
      scope: scoped.scope,
      documentPath: current.path,
      sentFrames: 0,
      receivedFrames: 0,
      sentBytes: 0,
      receivedBytes: 0,
    };
    state.webSockets.push(evidence);
    if (
      scoped.scope !== "attackable" ||
      scoped.origin !== state.options.origin ||
      current.origin !== state.options.origin
    ) {
      route.close({ code: 1008, reason: "Secondary-origin WebSockets are observation-only" });
      return;
    }
    observeWebSocketTraffic(route, evidence);
  });
  attachLifecycleListeners(state, context, page);
  page.on("response", (response) => {
    const resourceType = response.request().resourceType();
    if (resourceType !== "document" && resourceType !== "script") return;
    const scoped = scopedUrl(state, response.url());
    if (!scoped) return;
    const path = attackSurfaceIdentifier(state, scoped.url);
    pendingResponses.push(
      response
        .headerValue("content-type")
        .then((contentType) => {
          state.documents.set(path, {
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
    const scoped = scopedUrl(state, request.url());
    if (!scoped) {
      await route.abort("blockedbyclient");
      return;
    }
    const method = request.method().toUpperCase();
    const path = `${scoped.url.pathname}${scoped.url.search}`;
    const resourceType = request.resourceType();
    const passiveVisitOnly =
      (current.scope !== "visit-only" && scoped.scope !== "visit-only") ||
      (scoped.origin === current.origin &&
        ["GET", "HEAD"].includes(method) &&
        (PASSIVE_RESOURCE_TYPES.has(resourceType) ||
          (resourceType === "document" &&
            attackSurfaceIdentifier(state, scoped.url) === current.path)));
    const metadata: BrowserRequestMetadata = {
      budgeted: true,
      automaticInteraction: state.automaticInteraction,
      origin: scoped.url.origin,
      scope: scoped.scope,
      resourceType,
      passiveVisitOnly,
    };
    const decision = state.options.decideRequest(method, path, metadata);
    const scopeAllows =
      passiveVisitOnly &&
      (resourceType !== "document" ||
        scoped.origin === current.origin ||
        attackSurfaceIdentifier(state, scoped.url) === current.path) &&
      (scoped.scope === "attackable" ||
        (!state.automaticInteraction && ["GET", "HEAD"].includes(method)));
    let allowed = decision.allowed && scopeAllows;
    let admissionReason: string | undefined;
    let lease: RuntimeRequestLease | undefined;
    const formAttempt =
      state.activeFormRequest &&
      method === state.activeFormRequest.method &&
      scoped.origin === state.activeFormRequest.origin &&
      scoped.url.pathname === state.activeFormRequest.pathname
        ? state.activeFormRequest
        : undefined;
    if (formAttempt) formAttempt.observed = true;
    if (allowed && state.options.acquireRequest) {
      try {
        lease = await state.options.acquireRequest();
        state.requestLeases.set(request, lease);
        if (formAttempt && state.activeFormRequest !== formAttempt) {
          allowed = false;
          admissionReason = "form attempt expired while waiting for request admission";
          state.requestLeases.delete(request);
          lease.release();
          lease = undefined;
        }
      } catch (error) {
        allowed = false;
        admissionReason = error instanceof Error ? error.message : String(error);
      }
    }
    if (allowed && state.options.commitRequest) {
      const committed = state.options.commitRequest(method, path, metadata);
      if (!committed.allowed) {
        allowed = false;
        admissionReason = committed.reason ?? "request budget exhausted before admission";
        state.requestLeases.delete(request);
        lease?.release();
        lease = undefined;
      }
    }
    if (formAttempt && state.activeFormRequest === formAttempt) {
      formAttempt.allowed ||= allowed;
      formAttempt.settle();
    }
    const blockedReason = allowed
      ? undefined
      : (admissionReason ?? decision.reason ?? "blocked by discovery origin scope");
    if (
      observeRequest(state, request, scoped.url, scoped.scope, current.path, allowed, blockedReason)
    ) {
      state.options.onOperationDiscovered?.(method, normalizeEndpoint(path), "browser", {
        automaticInteraction: state.automaticInteraction,
        allowed,
        blockedReason,
        origin: scoped.url.origin,
        scope: scoped.scope,
      });
    }
    if (!allowed) {
      if (request.isNavigationRequest()) await route.fulfill({ status: 204, body: "" });
      else await route.abort("blockedbyclient");
    } else {
      try {
        await route.continue({
          headers: await requestHeaders(state, request, scoped.origin, current.origin),
        });
      } catch (error) {
        state.requestLeases.delete(request);
        lease?.fail();
        throw error;
      }
    }
  });
}

function attachLifecycleListeners(
  state: AttackSurfaceState,
  context: BrowserContext,
  page: Page,
): void {
  context.on("requestfinished", (request) => {
    const lease = state.requestLeases.get(request);
    if (!lease) return;
    state.requestLeases.delete(request);
    void request
      .response()
      .then((response) => lease.finish(classifyHttpStatus(response?.status() ?? 0)))
      .catch(() => lease.fail());
  });
  context.on("requestfailed", (request) => {
    const lease = state.requestLeases.get(request);
    if (!lease) return;
    state.requestLeases.delete(request);
    lease.fail();
  });
  context.on("page", (candidate) => {
    if (candidate !== page) void candidate.close();
  });
}
