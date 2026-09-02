import type { AttackSurfaceScope, BrowserRequestDecision } from "./attack-surface.ts";
import { impactAtMost } from "./impact.ts";
import { containsCredentialHeader, isCredentialHeaderName } from "./security/credentials.ts";
import { TargetScopeError } from "./scoped-target-errors.ts";
import type { ScopedTargetState } from "./scoped-target-state.ts";
import type { ImpactLevel } from "./state.ts";

export function assertImpactLevel(state: ScopedTargetState, level: ImpactLevel): void {
  if (!impactAtMost(level, state.maximumImpactLevel)) {
    throw new TargetScopeError(
      `${level} impact exceeds the target's ${state.maximumImpactLevel} ceiling`,
    );
  }
}

export function decideBrowserRequest(
  state: ScopedTargetState,
  method: string,
  path: string,
  budgeted: boolean,
  automaticInteraction: boolean,
  scope?: AttackSurfaceScope,
  origin = state.origin,
  passiveVisitOnly = true,
): BrowserRequestDecision {
  const targetPath = origin === state.origin ? path : `${origin}${path}`;
  if (scope === "blocked") return { allowed: false, reason: "origin is blocked" };
  if (scope === "auth-only")
    return { allowed: false, reason: "auth-only origins are reserved for profile setup" };
  let url: URL;
  try {
    state.runtimeSafety?.assertReady();
    url = scope === "visit-only" ? new URL(path, origin) : resolvePath(state, targetPath);
  } catch (error) {
    return { allowed: false, reason: error instanceof Error ? error.message : String(error) };
  }
  if (!passiveVisitOnly)
    return { allowed: false, reason: "visit-only documents permit passive assets only" };
  if (scope === "visit-only" && (automaticInteraction || !["GET", "HEAD"].includes(method)))
    return { allowed: false, reason: "visit-only origins permit passive reads only" };
  if (method === "DELETE")
    return { allowed: false, reason: "DELETE is never allowed for proof demonstration" };
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    try {
      assertImpactLevel(state, "state-change");
    } catch (error) {
      return { allowed: false, reason: error instanceof Error ? error.message : String(error) };
    }
  }
  if (isDenied(state, method, url.pathname))
    return { allowed: false, reason: "denied by target profile" };
  if (
    isStateChanging(method) &&
    !operationAllowed(state.browserAllowedOperations, method, targetPath)
  )
    return { allowed: false, reason: "state-changing operation is not preauthorized" };
  if (!budgeted) return { allowed: true };
  if (state.requestsUsed >= state.requestBudget)
    return { allowed: false, reason: "request budget exhausted" };
  if (state.runtimeSafety) return { allowed: true };
  return commitBrowserRequest(state, method, targetPath, true);
}

export function commitBrowserRequest(
  state: ScopedTargetState,
  method: string,
  targetPath: string,
  budgeted: boolean,
): BrowserRequestDecision {
  if (!budgeted) return { allowed: true };
  if (state.requestsUsed >= state.requestBudget)
    return { allowed: false, reason: "request budget exhausted" };
  state.requestsUsed += 1;
  state.onRequest?.({ number: state.requestsUsed, method, path: targetPath, setup: false });
  return { allowed: true };
}

export function resolvePath(
  state: ScopedTargetState,
  path: string,
  access: "attack" | "setup" = "attack",
): URL {
  if (path.startsWith("//"))
    throw new TargetScopeError("Protocol-relative target paths are not allowed");
  const absolute = /^https?:\/\//i.test(path);
  if (!absolute && !path.startsWith("/"))
    throw new TargetScopeError(
      "Only origin-relative paths or configured absolute URLs are allowed",
    );
  const url = new URL(path, state.origin);
  const scope = state.originScopes.get(url.origin);
  if (
    !scope ||
    scope === "blocked" ||
    scope === "visit-only" ||
    (scope === "auth-only" && access !== "setup")
  ) {
    throw new TargetScopeError(
      scope === "auth-only"
        ? "Auth-only origin is reserved for profile setup"
        : "Out-of-scope, blocked, or visit-only origin blocked",
    );
  }
  return url;
}

export function targetIdentifier(state: ScopedTargetState, url: URL): string {
  const path = `${url.pathname}${url.search}`;
  return url.origin === state.origin ? path : `${url.origin}${path}`;
}
export function isDenied(state: ScopedTargetState, method: string, pathname: string): boolean {
  return state.deniedRequests.has(`${method} ${pathname}`);
}
export function isAuthorizedOperation(
  state: ScopedTargetState,
  method: string,
  path: string,
): boolean {
  return (
    operationAllowed(state.allowedRequests, method, path) ||
    operationAllowed(state.mappedOperations, method, path)
  );
}
export function hasPotentialAuthenticationHeaders(
  headers: Record<string, string> | undefined,
): boolean {
  return containsCredentialHeader(headers);
}
export function hasPotentialScopeOverrideHeaders(
  headers: Record<string, string> | undefined,
): boolean {
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
  return isCredentialHeaderName(name);
}
export function isStateChanging(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS"].includes(method);
}
export function operationKey(method: string, path: string): string {
  return `${method.toUpperCase()} ${canonicalOperationPath(path)}`;
}
export function operationAllowed(
  operations: ReadonlySet<string>,
  method: string,
  path: string,
): boolean {
  const concrete = canonicalOperationPath(path);
  if (operations.has(`${method.toUpperCase()} ${concrete}`)) return true;
  for (const operation of operations) {
    const separator = operation.indexOf(" ");
    if (
      operation.slice(0, separator) === method.toUpperCase() &&
      pathTemplateMatches(operation.slice(separator + 1), concrete)
    )
      return true;
  }
  return false;
}
function canonicalOperationPath(path: string): string {
  const absolute = /^https?:\/\//i.test(path);
  const url = new URL(path, "http://scope.invalid");
  const pathname = url.pathname
    .split("/")
    .map((encoded) => {
      const segment = decodeURIComponent(encoded);
      return /^(?:\{[^}]+\}|<[^>]+>|:[A-Za-z_$][\w$]*)$/.test(segment) ? "{id}" : segment;
    })
    .join("/");
  const canonical = pathname === "/" ? pathname : pathname.replace(/\/+$/, "");
  return absolute ? `${url.origin}${canonical}` : canonical;
}
function pathTemplateMatches(template: string, concrete: string): boolean {
  const expected = template.split("/").map(decodeURIComponent);
  const actual = concrete.split("/").map(decodeURIComponent);
  return (
    expected.length === actual.length &&
    expected.every((segment, index) => segment === "{id}" || segment === actual[index])
  );
}
