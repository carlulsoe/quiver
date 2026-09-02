import { actorIds } from "./sessions.ts";
import { browserCookieTargetsOrigin } from "./scoped-target-cookie.ts";
import { TargetScopeError } from "./scoped-target-errors.ts";
import {
  assertImpactLevel,
  commitBrowserRequest,
  decideBrowserRequest,
  resolvePath,
} from "./scoped-target-policy.ts";
import type { ScopedTargetState } from "./scoped-target-state.ts";
import type { BrowserEffectEvidence, BrowserStateTransitionEvidence } from "./state.ts";
import type { BrowserEffectRequest, BrowserStateTransitionRequest } from "./scoped-target-types.ts";

export async function observeBrowserEffect(
  state: ScopedTargetState,
  request: BrowserEffectRequest,
): Promise<BrowserEffectEvidence | undefined> {
  assertImpactLevel(state, "bounded");
  resolvePath(state, request.path);
  const browserState = await state.sessions.browserState(request.actorId);
  let collectorRequests = 0;
  return state.browserEffectCollector({
    ...request,
    origin: state.origin,
    timeoutMs: state.timeoutMs,
    authenticationHeaders: browserState.headers,
    cookies: browserState.cookies,
    localStorage: browserState.localStorage,
    sessionStorage: browserState.sessionStorage,
    executablePath: state.browserExecutablePath,
    acquireRequest: state.runtimeSafety ? () => state.runtimeSafety!.acquire() : undefined,
    commitRequest: state.runtimeSafety
      ? (method, path) => {
          if (collectorRequests >= request.requestBudget) return false;
          const committed = commitBrowserRequest(state, method, path, true);
          if (committed.allowed) collectorRequests += 1;
          return committed.allowed;
        }
      : undefined,
    decideRequest: (method, path) => {
      if (!["GET", "HEAD"].includes(method) || collectorRequests >= request.requestBudget)
        return false;
      const decision = decideBrowserRequest(state, method, path, true, false);
      if (decision.allowed && !state.runtimeSafety) collectorRequests += 1;
      return decision.allowed;
    },
  });
}

export async function observeBrowserStateTransition(
  state: ScopedTargetState,
  request: BrowserStateTransitionRequest,
): Promise<BrowserStateTransitionEvidence | undefined> {
  assertImpactLevel(state, "state-change");
  const source = new URL(request.sourceOrigin);
  const configuredSource = state.attackSurfaceOrigins?.find(
    ({ origin, scope }) => new URL(origin).origin === source.origin && scope === "visit-only",
  );
  if (
    !configuredSource ||
    source.origin === state.origin ||
    source.origin !== request.sourceOrigin
  ) {
    throw new TargetScopeError(
      "Browser state proof source must be an exact configured cross-origin visit-only origin",
    );
  }
  const targetUrl = resolvePath(state, request.targetPath);
  if (targetUrl.origin !== state.origin)
    throw new TargetScopeError("Browser state proof transition must target the primary origin");
  const browserState = await state.sessions.browserState(request.actorId);
  const cookies = (browserState.cookies ?? []).filter((cookie) =>
    browserCookieTargetsOrigin(cookie, new URL(state.origin)),
  );
  if (request.actorId === actorIds.anonymous || cookies.length === 0)
    throw new TargetScopeError(
      "Browser state proof requires a named actor with target-scoped cookies",
    );
  let collectorRequests = 0;
  return state.browserStateTransitionCollector({
    policyId: request.policyId,
    targetOrigin: state.origin,
    sourceOrigin: request.sourceOrigin,
    sourcePath: request.sourcePath,
    targetPath: request.targetPath,
    method: request.method,
    timeoutMs: state.timeoutMs,
    cookies,
    executablePath: state.browserExecutablePath,
    acquireRequest: state.runtimeSafety ? () => state.runtimeSafety!.acquire() : undefined,
    commitRequest: state.runtimeSafety
      ? (method, url) => {
          if (collectorRequests >= request.requestBudget) return false;
          const committed = commitBrowserRequest(
            state,
            method,
            `${url.pathname}${url.search}`,
            true,
          );
          if (committed.allowed) collectorRequests += 1;
          return committed.allowed;
        }
      : undefined,
    decideRequest: (method, url) => {
      if (collectorRequests >= request.requestBudget) return false;
      const path = `${url.pathname}${url.search}`;
      const decision =
        url.origin === state.origin
          ? decideBrowserRequest(state, method, path, true, false)
          : url.origin === source.origin
            ? decideBrowserRequest(
                state,
                method,
                path,
                true,
                false,
                "visit-only",
                source.origin,
                true,
              )
            : { allowed: false };
      if (decision.allowed && !state.runtimeSafety) collectorRequests += 1;
      return decision.allowed;
    },
  });
}
