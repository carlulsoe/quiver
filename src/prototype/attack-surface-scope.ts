import { constants } from "node:fs";
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

type BrowserLauncher = (options: { executablePath: string; headless: true }) => Promise<Browser>;

interface BrowserResolutionDependencies {
  environmentPath: string | undefined;
  managedPath: string;
  canAccess: (path: string) => Promise<boolean>;
}

export async function launchChromium(
  executablePath: string,
  launch: BrowserLauncher = (options) => chromium.launch(options),
  report: (message: string) => void = console.error,
): Promise<Browser> {
  try {
    const browser = await launch({ executablePath, headless: true });
    report(`[quiver] Chromium ${browser.version()} (${executablePath})`);
    return browser;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to launch Chromium at ${executablePath}: ${reason}`, { cause: error });
  }
}

export async function findBrowserExecutable(
  configuredPath?: string,
  dependencies: BrowserResolutionDependencies = {
    environmentPath: process.env.QUIVER_BROWSER_PATH,
    managedPath: chromium.executablePath(),
    canAccess: async (path) =>
      access(path, constants.X_OK)
        .then(() => true)
        .catch(() => false),
  },
): Promise<string> {
  const executablePath = configuredPath ?? dependencies.environmentPath ?? dependencies.managedPath;
  if (await dependencies.canAccess(executablePath)) return executablePath;
  const source =
    configuredPath !== undefined
      ? "configured browser"
      : dependencies.environmentPath !== undefined
        ? "QUIVER_BROWSER_PATH override"
        : "Playwright-managed browser";
  throw new Error(
    `The ${source} was not found at ${executablePath}. Run \`bun run browser:install\` ` +
      "or set QUIVER_BROWSER_PATH to a Playwright-compatible Chromium executable.",
  );
}

export function isExpectedNavigationInterruption<T>(error: T): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /ERR_ABORTED|ERR_BLOCKED_BY_CLIENT|ERR_FAILED|Timeout/i.test(message);
}
