import { normalizeEndpoint } from "./endpoint.ts";
import {
  extractOpenApiRequestBodies,
  resolveOpenApiTargets,
  type OpenApiObject,
  type OpenApiValue,
} from "./discovery/openapi.ts";
import { safeExample } from "./discovery/request-evidence.ts";
import type { AttackSurfaceState } from "./attack-surface-state.ts";
import type {
  AttackSurfaceCallSite,
  AttackSurfaceGraphqlOperation,
  AttackSurfaceMap,
  AttackSurfaceRequestBody,
  AttackSurfaceRouteDetail,
  AttackSurfaceScope,
} from "./attack-surface-types.ts";

const HTTP_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

export function addOpenApi<T>(state: AttackSurfaceState, input: T): void {
  const document = safeExample(input);
  if (!isRecord(document) || !isRecord(document.paths)) return;
  for (const [path, rawPathItem] of Object.entries(document.paths)) {
    if (!path.startsWith("/") || !isRecord(rawPathItem)) continue;
    for (const [method, rawOperation] of Object.entries(rawPathItem)) {
      const upperMethod = method.toUpperCase();
      if (!HTTP_METHODS.has(upperMethod) || !isRecord(rawOperation)) continue;
      const targets = resolveOpenApiTargets(
        document,
        rawPathItem,
        rawOperation,
        state.options.origin,
        state.scopes,
      );
      const bodies = extractOpenApiRequestBodies(document, rawPathItem, rawOperation);
      for (const target of targets) {
        const operationPath = `${target.prefix}${path}`.replaceAll(/\/{2,}/g, "/");
        const url = new URL(operationPath, target.origin);
        const metadata = {
          summary: isString(rawOperation.summary) ? rawOperation.summary : undefined,
          scope: target.scope,
          routePath: operationPath,
        };
        if (bodies.length === 0)
          mergeEvidence(state, url, upperMethod, "openapi", undefined, metadata);
        for (const body of bodies)
          mergeEvidence(state, url, upperMethod, "openapi", undefined, { ...metadata, body });
        state.options.onOperationDiscovered?.(upperMethod, operationPath, "openapi", {
          automaticInteraction: false,
          allowed: true,
          origin: target.origin,
          scope: target.scope,
        });
      }
    }
  }
}

interface EvidenceMetadata {
  summary?: string;
  examplePath?: string;
  body?: AttackSurfaceRequestBody;
  graphql?: AttackSurfaceGraphqlOperation[];
  scope?: AttackSurfaceScope;
  routePath?: string;
}

export function mergeEvidence(
  state: AttackSurfaceState,
  url: URL,
  method: string,
  source: string,
  callSite?: AttackSurfaceCallSite,
  metadata?: EvidenceMetadata,
): void {
  const path = metadata?.routePath ?? normalizeEndpoint(url.pathname);
  const key = `${url.origin} ${path}`;
  const evidence = state.evidence.get(key) ?? {
    origin: url.origin,
    path,
    scope: metadata?.scope ?? state.scopes.get(url.origin) ?? "visit-only",
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
  if (metadata?.body && !containsJson(evidence.requestBodies, metadata.body))
    evidence.requestBodies.push(metadata.body);
  for (const operation of metadata?.graphql ?? [])
    if (!containsJson(evidence.graphqlOperations, operation))
      evidence.graphqlOperations.push(operation);
  if (callSite && !containsJson(evidence.callSites, callSite)) evidence.callSites.push(callSite);
  evidence.summary ??= metadata?.summary;
  state.evidence.set(key, evidence);
}

export function buildAttackSurfaceResult(state: AttackSurfaceState): AttackSurfaceMap {
  const routeDetails: AttackSurfaceRouteDetail[] = [...state.evidence.values()]
    .map((evidence) => {
      const detail: AttackSurfaceRouteDetail = {
        path:
          evidence.origin === state.options.origin
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
      };
      if (evidence.requestBodies.length > 0) detail.requestBodies = evidence.requestBodies;
      if (evidence.graphqlOperations.length > 0)
        detail.graphqlOperations = evidence.graphqlOperations;
      if (evidence.summary) detail.summary = evidence.summary;
      return detail;
    })
    .sort((left, right) => left.path.localeCompare(right.path));
  addIdentifierSources(routeDetails);
  return {
    startPath: state.options.startPath,
    documents: [...state.documents.values()],
    routes: routeDetails.map(({ path }) => path),
    routeDetails,
    forms: state.forms,
    webSockets: state.webSockets,
  };
}

function addIdentifierSources(details: AttackSurfaceRouteDetail[]): void {
  const parameters = details.flatMap((detail) =>
    routeParameters(detail.path).map((parameter) => ({ detail, parameter })),
  );
  for (const { detail, parameter } of parameters) {
    const prefix = detail.path.slice(0, parameter.index).replace(/\/$/, "");
    const source = details
      .filter(
        (candidate) =>
          candidate.methods.includes("GET") &&
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

function routeParameters(path: string): Array<{ name: string; index: number }> {
  const parameters: Array<{ name: string; index: number }> = [];
  for (const match of path.matchAll(/\{([^/{}]+)\}|<([^/<>]+)>|:([A-Za-z_$][\w$]*)/g))
    parameters.push({ name: match[1] ?? match[2] ?? match[3]!, index: match.index });
  return parameters;
}
function containsJson<T>(values: readonly T[], candidate: T): boolean {
  const json = JSON.stringify(candidate);
  return values.some((value) => JSON.stringify(value) === json);
}
function isString(value: OpenApiValue): value is string {
  return Object.prototype.toString.call(value) === "[object String]";
}
function isRecord(value: OpenApiValue): value is OpenApiObject {
  return value instanceof Object && !Array.isArray(value);
}
