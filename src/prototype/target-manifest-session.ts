import type { BrowserCookie } from "./attack-surface.ts";
import type { StoredSession } from "./sessions.ts";
import type { MaterializedCredentials, SessionAdapterManifest } from "./target-manifest-types.ts";
import { renderRecord, renderTemplate } from "./target-manifest-values.ts";

export function materializeSession(
  adapter: SessionAdapterManifest,
  credentials: MaterializedCredentials,
  origin: string,
): StoredSession {
  if (adapter.kind === "header-token") {
    return {
      headers: {
        [adapter.headerName ?? "authorization"]: renderTemplate(
          adapter.headerValue ?? "Bearer {{credential}}",
          credentials,
        ),
      },
    };
  }
  if (adapter.kind === "cookie") {
    return {
      browserState: {
        cookies: [materializeCookie(adapter.cookie, credentials.credential, origin)],
      },
    };
  }
  return {
    headers: renderRecord(adapter.session.headers, credentials),
    browserState: {
      localStorage: renderRecord(adapter.session.localStorage, credentials),
      sessionStorage: renderRecord(adapter.session.sessionStorage, credentials),
      cookies: adapter.session.cookies?.map((cookie) =>
        materializeCookie(cookie, renderTemplate(cookie.value, credentials), origin),
      ),
    },
  };
}

export function materializeCookie(
  cookie: Omit<BrowserCookie, "value">,
  value: string,
  origin: string,
): BrowserCookie {
  if (/[;\r\n]/.test(value)) throw new Error("Cookie credentials may not contain separators");
  if (("url" in cookie && cookie.url) || ("domain" in cookie && cookie.domain)) {
    return { ...cookie, value } as BrowserCookie;
  }
  const target = new URL(origin);
  return {
    ...cookie,
    name: cookie.name,
    value,
    domain: target.hostname,
    path: cookie.path ?? "/",
    secure: cookie.secure ?? target.protocol === "https:",
  } as BrowserCookie;
}
