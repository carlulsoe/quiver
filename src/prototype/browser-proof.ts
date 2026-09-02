import type { Browser, Request } from "playwright-core";
import { findBrowserExecutable, launchChromium, type BrowserCookie } from "./attack-surface.ts";
import type { BrowserEffectEvidence } from "./state.ts";
import { classifyHttpStatus, type RuntimeRequestLease } from "./runtime-safety.ts";

export interface BrowserProofProbe {
  probeId: string;
  origin: string;
  path: string;
  marker: string;
  kind: BrowserEffectEvidence["kind"];
  timeoutMs: number;
  authenticationHeaders?: Record<string, string>;
  cookies?: BrowserCookie[];
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
  executablePath?: string;
  decideRequest: (method: string, path: string) => boolean;
  acquireRequest?: () => Promise<RuntimeRequestLease>;
  commitRequest?: (method: string, path: string) => boolean;
}

/** Observes a visible browser effect while blocking cross-origin and unauthorized requests. */
export async function collectBrowserEffect(
  probe: BrowserProofProbe,
  launch: (executablePath: string) => Promise<Browser> = launchChromium,
): Promise<BrowserEffectEvidence | undefined> {
  const executablePath =
    probe.executablePath ?? process.env.QUIVER_BROWSER_PATH ?? (await findBrowserExecutable());
  const browser = await launch(executablePath);
  const requestLeases = new Map<Request, RuntimeRequestLease>();
  try {
    const context = await browser.newContext({
      extraHTTPHeaders: probe.authenticationHeaders,
      serviceWorkers: "block",
    });
    if (probe.cookies?.length) await context.addCookies(probe.cookies);
    if (probe.localStorage || probe.sessionStorage) {
      await context.addInitScript(
        (storage) => {
          for (const [name, value] of Object.entries(storage.local))
            localStorage.setItem(name, value);
          for (const [name, value] of Object.entries(storage.session))
            sessionStorage.setItem(name, value);
        },
        { local: probe.localStorage ?? {}, session: probe.sessionStorage ?? {} },
      );
    }
    const page = await context.newPage();
    context.on("requestfinished", (request) => {
      const lease = requestLeases.get(request);
      if (!lease) return;
      requestLeases.delete(request);
      void request
        .response()
        .then((response) => lease.finish(classifyHttpStatus(response?.status() ?? 0)))
        .catch(() => lease.fail());
    });
    context.on("requestfailed", (request) => {
      const lease = requestLeases.get(request);
      if (!lease) return;
      requestLeases.delete(request);
      lease.fail();
    });
    context.on("page", (candidate) => {
      if (candidate !== page) void candidate.close();
    });
    const expectedUrl = new URL(probe.path, probe.origin).href;
    await context.route("**/*", async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const path = `${url.pathname}${url.search}`;
      const expected = new URL(probe.path, probe.origin);
      const isNavigationRequest = request.isNavigationRequest();
      let isMainFrame = false;
      if (isNavigationRequest) {
        try {
          isMainFrame = request.frame() === page.mainFrame();
        } catch {
          // Unframed popup/service-worker navigation is never the policy document.
        }
      }
      const isUnexpectedNavigation = !isExpectedDocumentNavigation(
        isNavigationRequest,
        isMainFrame,
        url,
        expected,
      );
      if (
        isUnexpectedNavigation ||
        url.origin !== probe.origin ||
        !probe.decideRequest(request.method(), path)
      ) {
        await route.abort("blockedbyclient");
        return;
      }
      let lease: RuntimeRequestLease | undefined;
      try {
        lease = await probe.acquireRequest?.();
        if (lease) requestLeases.set(request, lease);
        if (probe.commitRequest && !probe.commitRequest(request.method(), path)) {
          requestLeases.delete(request);
          lease?.release();
          await route.abort("blockedbyclient");
          return;
        }
        await route.continue();
      } catch {
        requestLeases.delete(request);
        lease?.fail();
        await route.abort("blockedbyclient").catch(() => undefined);
      }
    });
    await context.routeWebSocket("**/*", (route) =>
      route.close({ code: 1008, reason: "Quiver browser proof blocks WebSockets" }),
    );
    let markerObserved = false;
    page.on("dialog", (dialog) => {
      if (dialog.message() === probe.marker && page.url() === expectedUrl) markerObserved = true;
      void dialog.dismiss();
    });
    try {
      const response = await page.goto(expectedUrl, {
        waitUntil: "networkidle",
        timeout: probe.timeoutMs,
      });
      if (response?.request().redirectedFrom() || page.url() !== expectedUrl) return undefined;
    } catch {
      return undefined;
    }
    await page.waitForTimeout(50);
    return markerObserved && page.url() === expectedUrl
      ? { probeId: probe.probeId, path: probe.path, kind: probe.kind, value: probe.marker }
      : undefined;
  } finally {
    for (const lease of requestLeases.values()) lease.fail();
    requestLeases.clear();
    await browser.close();
  }
}

export function isExpectedDocumentNavigation(
  isNavigationRequest: boolean,
  isMainFrame: boolean,
  url: URL,
  expected: URL,
): boolean {
  return (
    !isNavigationRequest ||
    (isMainFrame &&
      url.origin === expected.origin &&
      `${url.pathname}${url.search}` === `${expected.pathname}${expected.search}`)
  );
}
