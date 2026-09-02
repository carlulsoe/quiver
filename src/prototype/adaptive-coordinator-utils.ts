import { normalizeEndpoint } from "./endpoint.ts";
import { actorIds, type ActorId } from "./sessions.ts";
import type {
  CoordinatorHypothesis,
  MutableWorkerBudget,
  WorkerBudget,
} from "./adaptive-coordinator-types.ts";

export function cloneHypothesis(hypothesis: CoordinatorHypothesis): CoordinatorHypothesis {
  return { ...hypothesis, evidenceSignals: [...hypothesis.evidenceSignals] };
}

export function workerBudget(allocation: MutableWorkerBudget): WorkerBudget {
  return {
    allocated: allocation.allocated,
    used: allocation.used,
    remaining: Math.max(0, allocation.allocated - allocation.used),
  };
}

export function maximumSequence(ids: Iterable<string>, prefix: string): number {
  return [...ids].reduce((maximum, id) => {
    const value = Number(id.slice(prefix.length));
    return id.startsWith(prefix) && Number.isSafeInteger(value)
      ? Math.max(maximum, value)
      : maximum;
  }, 0);
}

export function clampConfidence(confidence: number): number {
  return Math.min(1, Math.max(0, confidence));
}

export function taskKey(operation: string, actorId: ActorId): string {
  return `${operation}:${actorId}`;
}

export function uniqueActorIds(configured: readonly ActorId[]): readonly ActorId[] {
  return [...new Set([actorIds.anonymous, ...configured])];
}

export function operationKey(method: string, route: string): string {
  return `${method.toUpperCase()} ${route}`;
}

export function safeNormalizeEndpoint(endpoint: string): string | undefined {
  try {
    return normalizeEndpoint(endpoint);
  } catch {
    return undefined;
  }
}

export function safeCoordinatorKey(endpoint: string): string | undefined {
  try {
    const url = new URL(endpoint, "http://scope.invalid");
    const path = normalizeEndpoint(url.pathname);
    url.searchParams.sort();
    return `${path}${url.search}`;
  } catch {
    return undefined;
  }
}

export function routeMatches(route: string, request: string): boolean {
  const routeUrl = new URL(route, "http://scope.invalid");
  const requestUrl = new URL(request, "http://scope.invalid");
  const routeSegments = routeUrl.pathname.split("/").map(decodeURIComponent);
  const requestSegments = requestUrl.pathname.split("/").map(decodeURIComponent);
  if (
    routeSegments.length !== requestSegments.length ||
    !routeSegments.every(
      (segment, index) => isPlaceholder(segment) || segment === requestSegments[index],
    )
  ) {
    return false;
  }

  const routeParameters = [...routeUrl.searchParams];
  const requestParameters = [...requestUrl.searchParams];
  return (
    routeParameters.length === requestParameters.length &&
    routeParameters.every(([name, value], index) => {
      const requestParameter = requestParameters[index];
      return (
        requestParameter !== undefined &&
        name === requestParameter[0] &&
        (isPlaceholder(value) || value === requestParameter[1])
      );
    })
  );
}

export function routeSpecificity(route: string): number {
  return route
    .split("/")
    .filter(Boolean)
    .reduce((score, segment) => score + (segment === "{id}" ? 0 : 1), 0);
}

export function isPlaceholder(value: string): boolean {
  return /^(?:<[^>]+>|\{[^}]+\}|:[A-Za-z_$][\w$]*)$/.test(value);
}
