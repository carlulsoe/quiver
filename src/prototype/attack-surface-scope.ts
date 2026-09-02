import { access } from "node:fs/promises";
import { chromium, type Browser, type Request } from "playwright-core";
import type { AttackSurfaceState } from "./attack-surface-state.ts";
import { isCredentialHeaderName } from "./security/credentials.ts";

export function attackSurfaceIdentifier(state: AttackSurfaceState, url: URL): string {
  const path = `${url.pathname}${url.search}`;
  return url.origin === state.options.origin ? path : `${url.origin}${path}`;
}

export async function requestHeaders(
  state: AttackSurfaceState,
  request: Request,
  requestOrigin: string,
  documentOrigin: string,
): Promise<Record<string, string>> {
  const headers = await request.allHeaders();
  if (requestOrigin === state.options.origin && documentOrigin === state.options.origin) {
    return { ...headers, ...state.options.authenticationHeaders };
  }
  return {
    ...Object.fromEntries(
      Object.entries(headers).filter(([name]) => !isCredentialHeaderName(name)),
    ),
    cookie: "",
  };
}

export function scopedUrl(
  state: AttackSurfaceState,
  input: string,
):
  | {
      url: URL;
      origin: string;
      scope: import("./attack-surface-types.ts").AttackSurfaceScope;
    }
  | undefined {
  let url: URL;
  try {
    url = new URL(input, state.options.origin);
  } catch {
    return undefined;
  }
  const origin =
    url.protocol === "ws:"
      ? `http://${url.host}`
      : url.protocol === "wss:"
        ? `https://${url.host}`
        : url.origin;
  const scope = state.scopes.get(origin);
  return scope && scope !== "blocked" && scope !== "auth-only" ? { url, origin, scope } : undefined;
}

export async function launchChromium(executablePath: string): Promise<Browser> {
  return chromium.launch({ executablePath, headless: true });
}

export async function findBrowserExecutable(): Promise<string> {
  const candidates = [
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ];
  for (const candidate of candidates) {
    if (
      await access(candidate)
        .then(() => true)
        .catch(() => false)
    )
      return candidate;
  }
  throw new Error(
    "No Chromium browser found. Install Chromium or set QUIVER_BROWSER_PATH to its executable.",
  );
}

export function isExpectedNavigationInterruption<T>(error: T): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /ERR_ABORTED|ERR_BLOCKED_BY_CLIENT|ERR_FAILED|Timeout/i.test(message);
}
