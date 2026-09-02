import type { AttackSurfaceMap } from "./attack-surface.ts";
import {
  observeBrowserEffect,
  observeBrowserStateTransition,
} from "./scoped-target-browser-proof.ts";
import { mapAttackSurface } from "./scoped-target-mapping.ts";
import { assertImpactLevel, operationKey } from "./scoped-target-policy.ts";
import { scopedRequest, setupRequest } from "./scoped-target-request.ts";
import { createScopedTargetState, type ScopedTargetState } from "./scoped-target-state.ts";
import {
  actorIds,
  type ActorId,
  type SessionProvider,
  type Sessions,
  type StoredSession,
} from "./sessions.ts";
import type {
  BrowserEffectEvidence,
  BrowserStateTransitionEvidence,
  ImpactLevel,
} from "./state.ts";
import type {
  AllowedRequest,
  BrowserEffectRequest,
  BrowserStateTransitionRequest,
  CrawlMap,
  HttpObservation,
  ScopedRequest,
  ScopedTargetOptions,
  SetupHttpObservation,
} from "./scoped-target-types.ts";

export type {
  AttackSurfaceCallSite as CrawlGetCallSite,
  AttackSurfaceIdentifierSource as CrawlIdentifierSource,
  AttackSurfaceOrigin,
  AttackSurfaceRouteDetail as CrawlRouteDetail,
} from "./attack-surface.ts";
export type {
  HttpTransport,
  HttpObservation,
  SetupHttpObservation,
  TargetRequestEvent,
  AllowedRequest,
  DeniedRequest,
  ScopedTargetOptions,
  AttackSurfaceMapperOptions,
  ScopedRequest,
  BrowserEffectRequest,
  BrowserStateTransitionRequest,
  RestMethod,
  CrawlDocument,
  CrawlMap,
} from "./scoped-target-types.ts";
export { RequestBudgetExceededError, TargetScopeError } from "./scoped-target-errors.ts";
export {
  hasPotentialAuthenticationHeaders,
  isCredentialCapableHeader,
} from "./scoped-target-policy.ts";

export class ScopedTarget {
  readonly #state: ScopedTargetState;

  constructor(options: ScopedTargetOptions) {
    this.#state = createScopedTargetState(options);
  }

  get origin(): string {
    return this.#state.origin;
  }
  get startPath(): string {
    return this.#state.startPath;
  }
  get sessions(): Sessions {
    return this.#state.sessions;
  }
  get requestsUsed(): number {
    return this.#state.requestsUsed;
  }
  get requestBudget(): number {
    return this.#state.requestBudget;
  }
  get remainingRequests(): number {
    return Math.max(0, this.#state.requestBudget - this.#state.requestsUsed);
  }

  extendRequestBudget(additionalRequests: number): void {
    if (!Number.isInteger(additionalRequests) || additionalRequests < 0)
      throw new Error("Additional request budget must be a non-negative integer");
    this.#state.requestBudget += additionalRequests;
  }

  allowRequests(requests: readonly AllowedRequest[]): void {
    for (const { method, path } of requests) {
      const key = operationKey(method, path);
      this.#state.allowedRequests.add(key);
      this.#state.browserAllowedOperations.add(key);
    }
  }

  assertImpactLevel(level: ImpactLevel): void {
    assertImpactLevel(this.#state, level);
  }

  async runProfileSetup<T>(setup: () => Promise<T>): Promise<T> {
    this.#state.setupAccess = true;
    try {
      return await setup();
    } finally {
      this.#state.setupAccess = false;
    }
  }

  setSession(actorId: ActorId, session: StoredSession): void {
    const sessions = this.#state.inMemorySessions;
    if (!sessions) throw new Error("Sessions are managed by the configured session adapter");
    sessions.set(actorId, session);
    this.#selectBrowserActor(actorId);
  }

  setSessionProvider(actorId: ActorId, provider: SessionProvider): void {
    const sessions = this.#state.inMemorySessions;
    if (!sessions) throw new Error("Sessions are managed by the configured session adapter");
    sessions.setProvider(actorId, provider);
    this.#selectBrowserActor(actorId);
  }

  async request(request: ScopedRequest): Promise<HttpObservation> {
    return scopedRequest(
      this.#state,
      request,
      this.#state.maxResponseChars,
    ) as Promise<HttpObservation>;
  }

  async setupRequest(request: ScopedRequest): Promise<SetupHttpObservation> {
    return setupRequest(this.#state, request);
  }

  async observeBrowserEffect(
    request: BrowserEffectRequest,
  ): Promise<BrowserEffectEvidence | undefined> {
    return observeBrowserEffect(this.#state, request);
  }

  async observeBrowserStateTransition(
    request: BrowserStateTransitionRequest,
  ): Promise<BrowserStateTransitionEvidence | undefined> {
    return observeBrowserStateTransition(this.#state, request);
  }

  mapAttackSurface(options: { maxDocuments?: number } = {}): Promise<AttackSurfaceMap> {
    return mapAttackSurface(this.#state, options);
  }

  /** @deprecated Use mapAttackSurface. */
  crawl(options: { maxDocuments?: number } = {}): Promise<CrawlMap> {
    return this.mapAttackSurface(options);
  }

  #selectBrowserActor(actorId: ActorId): void {
    if (this.#state.browserActorId === actorIds.anonymous && actorId !== actorIds.anonymous)
      this.#state.browserActorId = actorId;
  }
}
