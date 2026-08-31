export interface CrawlGetCallSite {
  documentPath: string;
  authentication: "likely" | "unknown";
}

export interface CrawlIdentifierSource {
  parameter: string;
  sourcePath: string;
}

export interface CrawlRouteDetail {
  path: string;
  sources: string[];
  getCallSites: CrawlGetCallSite[];
  identifierSources: CrawlIdentifierSource[];
}

interface RouteDocument {
  path: string;
  source: string;
  contentType: string;
}

interface DiscoveredDocumentRoutes {
  routes: readonly string[];
  crawlableLinks: readonly string[];
}

interface RouteEvidence {
  sources: Set<string>;
  getCallSites: CrawlGetCallSite[];
}

export class RouteDiscovery {
  readonly #origin: string;
  readonly #evidence = new Map<string, RouteEvidence>();

  constructor(origin: string) {
    this.#origin = origin;
  }

  analyzeDocument(document: RouteDocument): DiscoveredDocumentRoutes {
    const found = extractRoutes(document.source, this.#origin, document.contentType);
    for (const route of found.routes) {
      this.#mergeEvidence(route, document.path, found.getCalls.get(route));
    }
    return {
      routes: [...found.routes],
      crawlableLinks: [...found.crawlableLinks],
    };
  }

  routeDetails(): CrawlRouteDetail[] {
    const details: CrawlRouteDetail[] = [...this.#evidence.entries()].map(([path, detail]) => ({
      path,
      sources: [...detail.sources].sort(),
      getCallSites: detail.getCallSites,
      identifierSources: [],
    }));
    const getSources = details.filter((detail) => detail.getCallSites.length > 0);
    for (const detail of details) {
      for (const parameter of routeParameters(detail.path)) {
        const prefix = detail.path.slice(0, parameter.index).replace(/\/$/, "");
        const source = getSources
          .filter(
            (candidate) =>
              candidate.path !== detail.path &&
              !routeParameters(candidate.path).length &&
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
    return details
      .filter(
        (detail) =>
          !/^\/(?:\{|<|:)/.test(detail.path) &&
          (detail.getCallSites.length > 0 || detail.identifierSources.length > 0),
      )
      .sort((left, right) => left.path.localeCompare(right.path));
  }

  #mergeEvidence(route: string, documentPath: string, authentication?: "likely" | "unknown"): void {
    const detail = this.#evidence.get(route) ?? {
      sources: new Set<string>(),
      getCallSites: [],
    };
    detail.sources.add(documentPath);
    if (authentication) detail.getCallSites.push({ documentPath, authentication });
    this.#evidence.set(route, detail);
  }
}

function extractRoutes(
  source: string,
  origin: string,
  contentType: string,
): {
  routes: Set<string>;
  crawlableLinks: Set<string>;
  getCalls: Map<string, "likely" | "unknown">;
} {
  const routes = new Set<string>();
  const crawlableLinks = new Set<string>();
  const getCalls = new Map<string, "likely" | "unknown">();

  if (contentType.includes("html")) {
    for (const match of source.matchAll(/\b(?:href|src|action)\s*=\s*["']([^"']+)["']/gi)) {
      const route = sameOriginPath(match[1]!, origin);
      if (!route) continue;
      routes.add(route);
      if (isCrawlableDocument(route)) crawlableLinks.add(route);
    }
  }

  for (const match of source.matchAll(/["'`]((?:\/)[A-Za-z0-9_?&=./{}:<>,%-]{2,})["'`]/g)) {
    const route = sameOriginPath(match[1]!, origin);
    if (route) routes.add(route);
  }

  if (contentType.includes("javascript") || contentType.includes("ecmascript")) {
    for (const route of deriveComposedRoutes(source)) routes.add(route);
    for (const call of extractDirectGetCalls(source, origin)) {
      routes.add(call.path);
      getCalls.set(call.path, call.authentication);
    }
  }

  return { routes, crawlableLinks, getCalls };
}

function extractDirectGetCalls(
  source: string,
  origin: string,
): Array<{ path: string; authentication: "likely" | "unknown" }> {
  const calls: Array<{ path: string; authentication: "likely" | "unknown" }> = [];
  for (const match of source.matchAll(
    /\bfetch\s*\(\s*([^,()]{1,300})(?:,\s*([\s\S]{0,500}?))?\)/g,
  )) {
    const options = match[2] ?? "";
    const method = /\bmethod\s*:\s*["']([A-Za-z]+)["']/i.exec(options)?.[1]?.toUpperCase();
    if (method && method !== "GET") continue;
    const sourceBeforeCall = source.slice(Math.max(0, (match.index ?? 0) - 12_000), match.index);
    const resolved = resolveRouteExpression(match[1]!, sourceBeforeCall, source);
    if (!resolved) continue;
    const path = sameOriginPath(normalizeRouteTemplate(resolved), origin);
    if (!path) continue;
    calls.push({
      path,
      authentication: likelyUsesAuthentication(options, sourceBeforeCall) ? "likely" : "unknown",
    });
  }
  return calls;
}

function resolveRouteExpression(
  expression: string,
  sourceBeforeCall: string,
  definitionsSource: string,
  depth = 0,
): string | undefined {
  if (depth >= 8) return undefined;
  const trimmed = expression.trim();
  const literal = /^(?:["'`]([\s\S]*)["'`])$/.exec(trimmed)?.[1];
  if (literal !== undefined) return literal;

  const identifier = /^([A-Za-z_$][\w$]*)$/.exec(trimmed)?.[1];
  if (identifier) {
    const pattern = () => new RegExp(`\\b${escapeRegExp(identifier)}\\s*=\\s*([^;,]{1,500})`, "g");
    const assignment =
      lastMatch(sourceBeforeCall, pattern()) ?? lastMatch(definitionsSource, pattern());
    return assignment
      ? resolveRouteExpression(assignment[1]!, sourceBeforeCall, definitionsSource, depth + 1)
      : undefined;
  }

  const parts = splitConcatenation(trimmed);
  if (parts.length < 2) return undefined;
  const resolved: string[] = [];
  for (const part of parts) {
    const member = /^([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)$/.exec(part);
    if (member) {
      const pattern = () =>
        new RegExp(`\\b${escapeRegExp(member[1]!)}\\s*=\\s*\\{([^{}]{1,12000})\\}`, "g");
      const object =
        lastMatch(sourceBeforeCall, pattern()) ?? lastMatch(definitionsSource, pattern());
      const value = object
        ? new RegExp(`\\b${escapeRegExp(member[2]!)}\\s*:\\s*["'\`]([^"'\`]+)["'\`]`).exec(
            object[1]!,
          )?.[1]
        : undefined;
      if (!value) return undefined;
      resolved.push(value);
      continue;
    }
    const value = resolveRouteExpression(part, sourceBeforeCall, definitionsSource, depth + 1);
    if (!value) return undefined;
    resolved.push(value);
  }
  return resolved.join("");
}

function splitConcatenation(expression: string): string[] {
  return expression.split(/\s*\+\s*/).filter(Boolean);
}

function likelyUsesAuthentication(options: string, sourceBeforeCall: string): boolean {
  if (/\b(?:authorization|bearer)\b/i.test(options)) return true;
  const headersVariable =
    /\bheaders\s*:\s*([A-Za-z_$][\w$]*)/.exec(options)?.[1] ??
    (/\bheaders\b/.test(options) ? "headers" : undefined);
  if (!headersVariable) return false;
  const assignment = lastMatch(
    sourceBeforeCall,
    new RegExp(`\\b${escapeRegExp(headersVariable)}\\s*=\\s*([^;]{1,2000})`, "g"),
  );
  return /\b(?:authorization|bearer)\b/i.test(assignment?.[1] ?? "");
}

function lastMatch(source: string, pattern: RegExp): RegExpMatchArray | undefined {
  let last: RegExpMatchArray | undefined;
  for (const match of source.matchAll(pattern)) last = match;
  return last;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeRouteTemplate(route: string): string {
  return route.replaceAll(/\$\{\s*([A-Za-z_$][\w$]*)\s*\}/g, "{$1}");
}

function routeParameters(path: string): Array<{ name: string; index: number }> {
  const parameters: Array<{ name: string; index: number }> = [];
  for (const match of path.matchAll(/\{([^/{}]+)\}|<([^/<>]+)>|:([A-Za-z_$][\w$]*)/g)) {
    parameters.push({ name: match[1] ?? match[2] ?? match[3]!, index: match.index });
  }
  return parameters;
}

function deriveComposedRoutes(source: string): Set<string> {
  const strings = new Map<string, string>();
  for (const match of source.matchAll(/\b([A-Za-z_$][\w$]*)\s*=\s*["'`]([^"'`]{1,200})["'`]/g)) {
    strings.set(match[1]!, match[2]!);
  }

  const objects = new Map<string, Map<string, string>>();
  for (const match of source.matchAll(/\b([A-Za-z_$][\w$]*)\s*=\s*\{([^{}]{1,12000})\}/g)) {
    const members = new Map<string, string>();
    for (const member of match[2]!.matchAll(/\b([A-Za-z_$][\w$]*)\s*:\s*["'`]([^"'`]+)["'`]/g)) {
      members.set(member[1]!, member[2]!);
    }
    if (members.size > 0) objects.set(match[1]!, members);
  }

  const routes = new Set<string>();
  for (const usage of source.matchAll(
    /\b([A-Za-z_$][\w$]*)\s*\+\s*([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)/g,
  )) {
    const prefix = strings.get(usage[1]!);
    const suffix = objects.get(usage[2]!)?.get(usage[3]!);
    if (!prefix || !suffix) continue;
    const combined = `/${prefix}${suffix}`.replaceAll("//", "/");
    if (combined.includes("/api/")) routes.add(combined);
  }
  return routes;
}

function sameOriginPath(candidate: string, origin: string): string | undefined {
  if (candidate.startsWith("/>") || candidate.includes("><") || candidate.endsWith(",")) {
    return undefined;
  }
  try {
    const url = new URL(candidate, origin);
    if (url.origin !== origin) return undefined;
    return restoreRouteTemplates(`${url.pathname}${url.search}`);
  } catch {
    return undefined;
  }
}

function restoreRouteTemplates(path: string): string {
  return path.replaceAll(/%7B([^/%]+)%7D/gi, "{$1}").replaceAll(/%3C([^/%]+)%3E/gi, "<$1>");
}

function isCrawlableDocument(path: string): boolean {
  const pathname = new URL(path, "http://scope.invalid").pathname;
  const extension = pathname.match(/\.([A-Za-z0-9]+)$/)?.[1]?.toLowerCase();
  return !extension || extension === "html" || extension === "htm" || extension === "js";
}
