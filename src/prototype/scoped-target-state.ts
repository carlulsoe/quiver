import { BrowserAttackSurfaceMapper } from "./attack-surface.ts";
import {
  collectBrowserEffect,
  collectBrowserStateTransition,
  type BrowserProofProbe,
  type BrowserStateTransitionProbe,
} from "./browser-proof.ts";
import type {
  BrowserEffectEvidence,
  BrowserStateTransitionEvidence,
  ImpactLevel,
} from "./state.ts";
import type { RuntimeSafetyController } from "./runtime-safety.ts";
import { actorIds, InMemorySessions, type ActorId, type Sessions } from "./sessions.ts";
import { TargetScopeError } from "./scoped-target-errors.ts";
import { operationKey } from "./scoped-target-policy.ts";
import type { AttackSurfaceMap, AttackSurfaceOrigin } from "./attack-surface.ts";
import type {
  AttackSurfaceMapperOptions,
  HttpTransport,
  ScopedTargetOptions,
  TargetRequestEvent,
} from "./scoped-target-types.ts";

export interface ScopedTargetState {
  readonly origin: string;
  readonly originScopes: ReadonlyMap<string, import("./attack-surface.ts").AttackSurfaceScope>;
  readonly startPath: string;
  requestBudget: number;
  readonly allowedRequests: Set<string>;
  readonly setupRequests: Set<string>;
  readonly browserAllowedOperations: Set<string>;
  readonly mappedOperations: Set<string>;
  readonly deniedRequests: Set<string>;
  readonly onRequest?: (request: TargetRequestEvent) => void;
  readonly transport: HttpTransport;
  readonly timeoutMs: number;
  readonly maxResponseChars: number;
  readonly openApi?: unknown;
  readonly attackSurfaceOrigins?: AttackSurfaceOrigin[];
  readonly browserExecutablePath?: string;
  readonly attackSurfaceMapper: (options: AttackSurfaceMapperOptions) => Promise<AttackSurfaceMap>;
  readonly browserEffectCollector: (
    probe: BrowserProofProbe,
  ) => Promise<BrowserEffectEvidence | undefined>;
  readonly browserStateTransitionCollector: (
    probe: BrowserStateTransitionProbe,
  ) => Promise<BrowserStateTransitionEvidence | undefined>;
  readonly maximumImpactLevel: ImpactLevel;
  readonly runtimeSafety?: RuntimeSafetyController;
  readonly sessions: Sessions;
  readonly inMemorySessions?: InMemorySessions;
  setupAccess: boolean;
  requestsUsed: number;
  browserActorId: ActorId;
  attackSurfaceResult?: Promise<AttackSurfaceMap>;
}

export function createScopedTargetState(options: ScopedTargetOptions): ScopedTargetState {
  assertLoopbackConfiguration(options);
  const origin = options.target.origin;
  const sessions = options.sessions ?? new InMemorySessions();
  const allowedRequests = new Set(
    options.allowedRequests?.map(({ method, path }) => operationKey(method, path)) ?? [],
  );
  return {
    origin,
    originScopes: new Map([
      ...(options.attackSurfaceOrigins ?? []).map(
        ({ origin: configured, scope }) => [new URL(configured).origin, scope] as const,
      ),
      [origin, "attackable" as const],
    ]),
    startPath: `${options.target.pathname}${options.target.search}`,
    requestBudget: options.requestBudget,
    allowedRequests,
    setupRequests: new Set(
      (options.setupRequests ?? options.allowedRequests)?.map(({ method, path }) =>
        operationKey(method, path),
      ) ?? [],
    ),
    browserAllowedOperations: new Set(allowedRequests),
    mappedOperations: new Set(),
    deniedRequests: new Set(
      options.deniedRequests?.map(({ method, path }) => `${method} ${path}`) ?? [],
    ),
    onRequest: options.onRequest,
    transport: options.transport ?? fetch,
    timeoutMs: options.timeoutMs ?? 10_000,
    maxResponseChars: options.maxResponseChars ?? 12_000,
    openApi: options.openApi,
    attackSurfaceOrigins: options.attackSurfaceOrigins,
    browserExecutablePath: options.browserExecutablePath,
    attackSurfaceMapper:
      options.attackSurfaceMapper ??
      ((mapperOptions) => new BrowserAttackSurfaceMapper(mapperOptions).map()),
    browserEffectCollector: options.browserEffectCollector ?? collectBrowserEffect,
    browserStateTransitionCollector:
      options.browserStateTransitionCollector ?? collectBrowserStateTransition,
    maximumImpactLevel: options.maximumImpactLevel ?? "state-change",
    runtimeSafety: options.runtimeSafety,
    sessions,
    inMemorySessions: sessions instanceof InMemorySessions ? sessions : undefined,
    setupAccess: false,
    requestsUsed: 0,
    browserActorId: options.browserActorId ?? actorIds.anonymous,
  };
}

function assertLoopbackConfiguration(options: ScopedTargetOptions): void {
  const localHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
  if (
    !localHosts.has(options.target.hostname) ||
    !["http:", "https:"].includes(options.target.protocol)
  ) {
    throw new TargetScopeError("Only loopback HTTP(S) targets are allowed");
  }
  for (const configured of options.attackSurfaceOrigins ?? []) {
    const origin = new URL(configured.origin);
    if (
      !localHosts.has(origin.hostname) ||
      !["http:", "https:"].includes(origin.protocol) ||
      `${origin.origin}/` !== origin.href
    ) {
      throw new TargetScopeError("Discovery origins must be exact loopback HTTP(S) origins");
    }
  }
}
