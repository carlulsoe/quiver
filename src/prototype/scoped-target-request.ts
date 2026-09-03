import { classifyHttpStatus } from "./runtime-safety.ts";
import { actorIds } from "./sessions.ts";
import { RequestBudgetExceededError, TargetScopeError } from "./scoped-target-errors.ts";
import {
  assertImpactLevel,
  hasPotentialAuthenticationHeaders,
  hasPotentialScopeOverrideHeaders,
  isAuthorizedOperation,
  isDenied,
  isStateChanging,
  operationKey,
  operationAllowed,
  resolvePath,
  targetIdentifier,
} from "./scoped-target-policy.ts";
import type { ScopedTargetState } from "./scoped-target-state.ts";
import type {
  HttpObservation,
  ScopedRequest,
  SetupHttpObservation,
} from "./scoped-target-types.ts";

export async function scopedRequest(
  state: ScopedTargetState,
  request: ScopedRequest,
  responseLimit: number,
  includeResponseHeaders = false,
): Promise<HttpObservation | SetupHttpObservation> {
  const method = request.method ?? "GET";
  operationKey(method, request.path);
  const url = resolvePath(
    state,
    request.path,
    state.setupAccess || includeResponseHeaders ? "setup" : "attack",
  );
  const targetPath = targetIdentifier(state, url);
  assertRequestAllowed(state, method, targetPath, url.pathname, includeResponseHeaders);
  const actorId = request.actorId ?? actorIds.anonymous;
  const session = await state.sessions.acquire(actorId, url);
  if (hasPotentialScopeOverrideHeaders(request.headers))
    throw new TargetScopeError("Request headers may not override the scoped method or target path");
  if (!includeResponseHeaders && hasPotentialAuthenticationHeaders(request.headers)) {
    throw new TargetScopeError(
      actorId !== actorIds.anonymous
        ? "Actor requests may not override the session adapter's credential headers"
        : "Anonymous requests may only use standard representation and precondition headers",
    );
  }
  assertBudgetAvailable(state);
  const send = async (): Promise<HttpObservation | SetupHttpObservation> => {
    assertBudgetAvailable(state);
    state.requestsUsed += 1;
    state.onRequest?.({
      number: state.requestsUsed,
      method,
      path: targetPath,
      context:
        state.setupContext ?? (includeResponseHeaders ? "authentication" : state.requestContext),
    });
    const startedAt = performance.now();
    const headers = { ...request.headers };
    if (url.origin === state.origin) Object.assign(headers, session.headers);
    const response = await state.transport(url, {
      method,
      headers,
      body: request.body,
      redirect: "manual",
      signal: AbortSignal.timeout(state.timeoutMs),
    });
    return responseObservation(
      response,
      method,
      targetPath,
      responseLimit,
      includeResponseHeaders,
      startedAt,
    );
  };
  return state.runtimeSafety
    ? state.runtimeSafety.execute(
        send,
        ({ status }) => classifyHttpStatus(status),
        (error) => (error instanceof RequestBudgetExceededError ? "ignore" : "failure"),
      )
    : send();
}

export async function setupRequest(
  state: ScopedTargetState,
  request: ScopedRequest,
): Promise<SetupHttpObservation> {
  const method = request.method ?? "GET";
  const targetPath = targetIdentifier(state, resolvePath(state, request.path, "setup"));
  if (!operationAllowed(state.setupRequests, method, targetPath))
    throw new TargetScopeError(`${method} ${targetPath} is not an allowed profile setup request`);
  return scopedRequest(
    state,
    request,
    state.maxResponseChars,
    true,
  ) as Promise<SetupHttpObservation>;
}

function assertRequestAllowed(
  state: ScopedTargetState,
  method: string,
  targetPath: string,
  pathname: string,
  includeResponseHeaders: boolean,
): void {
  if (state.setupAccess || includeResponseHeaders) {
    if (!operationAllowed(state.setupRequests, method, targetPath))
      throw new TargetScopeError(`${method} ${targetPath} is not a profile setup operation`);
  } else {
    if (method === "DELETE")
      throw new TargetScopeError("DELETE is never allowed for proof demonstration");
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) assertImpactLevel(state, "state-change");
  }
  if (!includeResponseHeaders && isDenied(state, method, pathname))
    throw new TargetScopeError(`${method} ${pathname} is denied by the target profile`);
  if (
    !state.setupAccess &&
    !includeResponseHeaders &&
    isStateChanging(method) &&
    !isAuthorizedOperation(state, method, targetPath)
  ) {
    throw new TargetScopeError(
      `${method} ${targetPath} was not supplied by the profile or attack-surface map`,
    );
  }
}

function assertBudgetAvailable(state: ScopedTargetState): void {
  if (state.requestsUsed >= state.requestBudget)
    throw new RequestBudgetExceededError(
      `Request budget exhausted (${state.requestsUsed}/${state.requestBudget})`,
    );
}

async function responseObservation(
  response: Response,
  method: string,
  targetPath: string,
  responseLimit: number,
  includeHeaders: boolean,
  startedAt: number,
): Promise<HttpObservation | SetupHttpObservation> {
  const responseText = await response.text();
  const text = responseText.slice(0, responseLimit);
  let body = text;
  try {
    body = JSON.parse(text);
  } catch {
    /* Text is a valid target response body. */
  }
  const observation: HttpObservation = {
    method: method as HttpObservation["method"],
    status: response.status,
    path: targetPath,
    body,
    truncated: responseText.length > responseLimit,
    contentType: response.headers.get("content-type") ?? "",
    redirectLocation: response.headers.get("location") ?? undefined,
    redirected: response.redirected,
    durationMs: Math.round(performance.now() - startedAt),
  };
  return includeHeaders
    ? { ...observation, headers: Object.fromEntries(response.headers.entries()) }
    : observation;
}
