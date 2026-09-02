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
  acquire(actorId: ActorId, requestUrl?: URL): Promise<ActorSession>;
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

  async acquire(actorId: ActorId, requestUrl?: URL): Promise<ActorSession> {
    const session = await this.#resolve(actorId);
    if (!session) throw new Error(`This target has no session for actor ${actorId}`);
    const headers = session.headers ? { ...session.headers } : {};
    if (requestUrl && !Object.keys(headers).some((name) => name.toLowerCase() === "cookie")) {
      const cookie = session.browserState?.cookies
        ?.filter((candidate) => cookieMatchesRequest(candidate, requestUrl))
        .map(({ name, value }) => `${name}=${value}`)
        .join("; ");
      if (cookie) headers.cookie = cookie;
    }
    return { actorId, headers };
  }

  async browserState(actorId: ActorId): Promise<BrowserState> {
    const session = await this.#resolve(actorId);
    if (!session) throw new Error(`This target has no browser session for actor ${actorId}`);
    const state: BrowserState = {
      cookies: session.browserState?.cookies?.map((cookie) => ({ ...cookie })),
    };
    if (session.headers) state.headers = { ...session.headers };
    if (session.browserState?.localStorage)
      state.localStorage = { ...session.browserState.localStorage };
    if (session.browserState?.sessionStorage)
      state.sessionStorage = { ...session.browserState.sessionStorage };
    return state;
  }

  async #resolve(actorId: ActorId): Promise<StoredSession | undefined> {
    const provider = this.#providers.get(actorId);
    if (!provider) return this.#sessions.get(actorId);
    const session = cloneStoredSession(await provider());
    this.#sessions.set(actorId, session);
    return session;
  }
}

function cookieMatchesRequest(cookie: BrowserCookie, requestUrl: URL): boolean {
  if (cookie.secure && requestUrl.protocol !== "https:") return false;
  if (cookie.expires !== undefined && cookie.expires >= 0 && cookie.expires <= Date.now() / 1_000) {
    return false;
  }
  if ("url" in cookie && cookie.url) {
    const cookieUrl = new URL(cookie.url);
    return (
      cookieUrl.origin === requestUrl.origin && pathMatches(cookieUrl.pathname, requestUrl.pathname)
    );
  }
  const domain = cookie.domain?.replace(/^\./, "").toLowerCase();
  const hostname = requestUrl.hostname.toLowerCase();
  if (domain && hostname !== domain && !hostname.endsWith(`.${domain}`)) return false;
  return pathMatches(cookie.path ?? "/", requestUrl.pathname);
}

function pathMatches(cookiePath: string, requestPath: string): boolean {
  if (cookiePath === "/") return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return (
    requestPath.length === cookiePath.length ||
    cookiePath.endsWith("/") ||
    requestPath[cookiePath.length] === "/"
  );
}

function cloneStoredSession(session: StoredSession): StoredSession {
  const browserState: Omit<BrowserState, "headers"> = {
    cookies: session.browserState?.cookies?.map((cookie) => ({ ...cookie })),
  };
  if (session.browserState?.localStorage)
    browserState.localStorage = { ...session.browserState.localStorage };
  if (session.browserState?.sessionStorage)
    browserState.sessionStorage = { ...session.browserState.sessionStorage };
  const clone: StoredSession = { browserState };
  if (session.headers) clone.headers = { ...session.headers };
  return clone;
}
