import type { BrowserCookie } from "./attack-surface.ts";

export function browserCookieTargetsOrigin(cookie: BrowserCookie, target: URL): boolean {
  if (cookie.secure && target.protocol !== "https:") return false;
  if (cookie.url) {
    try {
      return new URL(cookie.url).origin === target.origin;
    } catch {
      return false;
    }
  }
  const domain = cookie.domain?.replace(/^\./, "").toLowerCase();
  const hostname = target.hostname.toLowerCase();
  return domain !== undefined && (hostname === domain || hostname.endsWith(`.${domain}`));
}
