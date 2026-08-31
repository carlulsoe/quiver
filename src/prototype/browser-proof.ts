import type { Browser } from "playwright-core";
import { findBrowserExecutable, launchChromium, type BrowserCookie } from "./attack-surface.ts";
import type { BrowserEffectEvidence } from "./state.ts";

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
}

/** Observes a visible browser effect while blocking cross-origin and unauthorized requests. */
export async function collectBrowserEffect(
  probe: BrowserProofProbe,
  launch: (executablePath: string) => Promise<Browser> = launchChromium,
): Promise<BrowserEffectEvidence | undefined> {
  const executablePath =
    probe.executablePath ?? process.env.QUIVER_BROWSER_PATH ?? (await findBrowserExecutable());
  const browser = await launch(executablePath);
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
    await context.route("**/*", async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const path = `${url.pathname}${url.search}`;
      if (url.origin !== probe.origin || !probe.decideRequest(request.method(), path)) {
        await route.abort("blockedbyclient");
        return;
      }
      await route.continue();
    });
    await context.routeWebSocket("**/*", (route) =>
      route.close({ code: 1008, reason: "Quiver browser proof blocks WebSockets" }),
    );
    const page = await context.newPage();
    context.on("page", (candidate) => {
      if (candidate !== page) void candidate.close();
    });
    let markerObserved = false;
    page.on("dialog", (dialog) => {
      if (dialog.message() === probe.marker) markerObserved = true;
      void dialog.dismiss();
    });
    await page.goto(new URL(probe.path, probe.origin).href, {
      waitUntil: "networkidle",
      timeout: probe.timeoutMs,
    });
    await page.waitForTimeout(50);
    return markerObserved
      ? { probeId: probe.probeId, path: probe.path, kind: probe.kind, value: probe.marker }
      : undefined;
  } finally {
    await browser.close();
  }
}
