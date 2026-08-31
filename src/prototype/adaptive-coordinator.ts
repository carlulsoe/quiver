import { normalizeEndpoint } from "./endpoint.ts";
import type { FindingInput, TestedRequest } from "./state.ts";

export interface CoordinatedTask {
  route: string;
  authenticated: boolean;
  source: "uncovered-surface" | "incoming-evidence";
  reason: string;
}

export interface WorkAssignment {
  agentId: string;
  tasks: CoordinatedTask[];
  uncoveredRouteCount: number;
  evidenceSignals: string[];
}

export interface AdaptiveCoordinatorOptions {
  supportsAuthentication?: boolean;
}

interface Candidate extends CoordinatedTask {
  key: string;
  priority: number;
}

/** Keeps concurrent explorers pointed at distinct gaps as campaign evidence arrives. */
export class AdaptiveCoordinator {
  readonly #routes = new Map<string, string>();
  readonly #tested = new Map<string, TestedRequest[]>();
  readonly #claims = new Map<string, string>();
  readonly #findings = new Set<string>();
  readonly #supportsAuthentication: boolean;

  constructor(options: AdaptiveCoordinatorOptions = {}) {
    this.#supportsAuthentication = options.supportsAuthentication ?? true;
  }

  discoverRoutes(routes: readonly string[]): void {
    for (const route of routes) {
      const normalized = safeCoordinatorKey(route);
      if (!normalized) continue;
      if (!this.#routes.has(normalized)) this.#routes.set(normalized, route);
    }
  }

  observeRequest(request: TestedRequest): void {
    const route = this.#routeForRequest(request.path);
    if (!route) return;
    const requests = this.#tested.get(route) ?? [];
    requests.push({ ...request });
    this.#tested.set(route, requests);
    this.#claims.delete(taskKey(route, request.authenticated));
  }

  observeFinding(finding: FindingInput): void {
    const route = safeNormalizeEndpoint(finding.endpoint);
    if (route) this.#findings.add(route);
  }

  release(agentId: string): void {
    for (const [key, owner] of this.#claims) {
      if (owner === agentId) this.#claims.delete(key);
    }
  }

  assign(agentId: string, limit = 3): WorkAssignment {
    if (!Number.isInteger(limit) || limit < 1) throw new Error("Assignment limit must be positive");

    const candidates = this.#candidates();
    const retained = candidates.filter((candidate) => this.#claims.get(candidate.key) === agentId);
    const available = candidates.filter((candidate) => !this.#claims.has(candidate.key));
    const selected = [...retained, ...available].slice(0, limit);
    for (const candidate of selected) this.#claims.set(candidate.key, agentId);

    const uncoveredRouteCount = [...this.#routes].filter(
      ([route]) => !this.#tested.has(route),
    ).length;
    const evidenceSignals = [...this.#tested.entries()].flatMap(([route, requests]) => {
      const modes = new Set(requests.map(({ authenticated }) => authenticated));
      if (modes.size > 1) return [];
      const latest = requests.at(-1)!;
      return [
        `${route} returned ${latest.status} as ${latest.authenticated ? "authenticated" : "anonymous"}; the opposite access mode is untested`,
      ];
    });

    return {
      agentId,
      tasks: selected.map(({ key: _key, priority: _priority, ...task }) => task),
      uncoveredRouteCount,
      evidenceSignals,
    };
  }

  #candidates(): Candidate[] {
    const candidates: Candidate[] = [];
    for (const [normalized, route] of this.#routes) {
      const requests = this.#tested.get(normalized) ?? [];
      const testedModes = new Set(requests.map(({ authenticated }) => authenticated));
      if (requests.length === 0) {
        const authenticated = this.#supportsAuthentication;
        candidates.push({
          key: taskKey(normalized, authenticated),
          route,
          authenticated,
          source: "uncovered-surface",
          priority: 80,
          reason: "No explorer has tested this discovered route yet.",
        });
        continue;
      }

      if (testedModes.size === 1) {
        const latest = requests.at(-1)!;
        const authenticated = !latest.authenticated;
        if (authenticated && !this.#supportsAuthentication) continue;
        const success = latest.status >= 200 && latest.status < 300;
        candidates.push({
          key: taskKey(normalized, authenticated),
          route,
          authenticated,
          source: "incoming-evidence",
          priority: success ? 100 : 90,
          reason: success
            ? `${latest.authenticated ? "Authenticated" : "Anonymous"} access succeeded; test the opposite access boundary.`
            : `${latest.authenticated ? "Authenticated" : "Anonymous"} access returned ${latest.status}; test the opposite mode to map the boundary.`,
        });
      }
    }

    return candidates.sort((left, right) => {
      const leftFinding = this.#findings.has(normalizeEndpoint(left.route)) ? 1 : 0;
      const rightFinding = this.#findings.has(normalizeEndpoint(right.route)) ? 1 : 0;
      return (
        leftFinding - rightFinding ||
        right.priority - left.priority ||
        left.route.localeCompare(right.route)
      );
    });
  }

  #routeForRequest(path: string): string | undefined {
    const normalized = safeCoordinatorKey(path);
    if (!normalized) return undefined;
    if (this.#routes.has(normalized)) return normalized;

    for (const route of this.#routes.keys()) {
      if (routeMatches(route, normalized)) return route;
    }
    return normalized;
  }
}

function taskKey(route: string, authenticated: boolean): string {
  return `${route}:${authenticated ? "authenticated" : "anonymous"}`;
}

function safeNormalizeEndpoint(endpoint: string): string | undefined {
  try {
    return normalizeEndpoint(endpoint);
  } catch {
    return undefined;
  }
}

function safeCoordinatorKey(endpoint: string): string | undefined {
  try {
    const url = new URL(endpoint, "http://scope.invalid");
    const path = normalizeEndpoint(url.pathname);
    url.searchParams.sort();
    return `${path}${url.search}`;
  } catch {
    return undefined;
  }
}

function routeMatches(route: string, request: string): boolean {
  const routeUrl = new URL(route, "http://scope.invalid");
  const requestUrl = new URL(request, "http://scope.invalid");
  const routeSegments = routeUrl.pathname.split("/").map(decodeURIComponent);
  const requestSegments = requestUrl.pathname.split("/").map(decodeURIComponent);
  if (
    routeSegments.length !== requestSegments.length ||
    !routeSegments.every(
      (segment, index) => segment === "{id}" || segment === requestSegments[index],
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

function isPlaceholder(value: string): boolean {
  return /^(?:<[^>]+>|\{[^}]+\}|:[A-Za-z_$][\w$]*)$/.test(value);
}
