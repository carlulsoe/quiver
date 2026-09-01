import type { BrowserCookie } from "./attack-surface.ts";

export const actorIds = {
  anonymous: "anonymous",
  userA: "ordinary-user",
  userB: "second-user",
  administrator: "privileged-user",
  /** @deprecated Use userA. */
  ordinary: "ordinary-user",
  /** @deprecated Use userB. */
  second: "second-user",
  /** @deprecated Use administrator. */
  privileged: "privileged-user",
} as const;

/** A stable principal reference. Profiles may add target-specific actor IDs. */
export type ActorId = (typeof actorIds)[keyof typeof actorIds] | (string & {});

export interface ActorSession {
  actorId: ActorId;
  headers: Record<string, string>;
}

export interface BrowserState {
  headers?: Record<string, string>;
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
  cookies?: BrowserCookie[];
}

/** Resolves opaque actor references into protocol-specific session material. */
export interface Sessions {
  acquire(actorId: ActorId): Promise<ActorSession>;
  browserState(actorId: ActorId): Promise<BrowserState>;
}

export interface StoredSession {
  headers?: Record<string, string>;
  browserState?: Omit<BrowserState, "headers">;
}

export type SessionProvider = () => Promise<StoredSession>;

/** Current process-local session adapter used by scoped targets. */
export class InMemorySessions implements Sessions {
  readonly #sessions = new Map<ActorId, StoredSession>();
  readonly #providers = new Map<ActorId, SessionProvider>();

  constructor() {
    this.#sessions.set(actorIds.anonymous, {});
  }

  set(actorId: ActorId, session: StoredSession): void {
    if (actorId === actorIds.anonymous && Object.keys(session.headers ?? {}).length > 0) {
      throw new Error("The anonymous actor cannot carry authentication headers");
    }
    this.#sessions.set(actorId, cloneStoredSession(session));
  }

  setProvider(actorId: ActorId, provider: SessionProvider): void {
    if (actorId === actorIds.anonymous) {
      throw new Error("The anonymous actor cannot use an authentication provider");
    }
    this.#providers.set(actorId, provider);
  }

  has(actorId: ActorId): boolean {
    return this.#sessions.has(actorId);
  }

  async acquire(actorId: ActorId): Promise<ActorSession> {
    const session = await this.#resolve(actorId);
    if (!session) throw new Error(`This target has no session for actor ${actorId}`);
    return { actorId, headers: session.headers ? { ...session.headers } : {} };
  }

  async browserState(actorId: ActorId): Promise<BrowserState> {
    const session = await this.#resolve(actorId);
    if (!session) throw new Error(`This target has no browser session for actor ${actorId}`);
    return {
      ...(session.headers ? { headers: { ...session.headers } } : {}),
      ...(session.browserState?.localStorage
        ? { localStorage: { ...session.browserState.localStorage } }
        : {}),
      ...(session.browserState?.sessionStorage
        ? { sessionStorage: { ...session.browserState.sessionStorage } }
        : {}),
      cookies: session.browserState?.cookies?.map((cookie) => ({ ...cookie })),
    };
  }

  async #resolve(actorId: ActorId): Promise<StoredSession | undefined> {
    const provider = this.#providers.get(actorId);
    if (!provider) return this.#sessions.get(actorId);
    const session = cloneStoredSession(await provider());
    this.#sessions.set(actorId, session);
    return session;
  }
}

function cloneStoredSession(session: StoredSession): StoredSession {
  return {
    ...(session.headers ? { headers: { ...session.headers } } : {}),
    browserState: {
      ...(session.browserState?.localStorage
        ? { localStorage: { ...session.browserState.localStorage } }
        : {}),
      ...(session.browserState?.sessionStorage
        ? { sessionStorage: { ...session.browserState.sessionStorage } }
        : {}),
      cookies: session.browserState?.cookies?.map((cookie) => ({ ...cookie })),
    },
  };
}
