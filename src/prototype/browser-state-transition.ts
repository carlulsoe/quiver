import type { Browser, Request as BrowserRequest } from "playwright-core";
import { findBrowserExecutable, launchChromium } from "./attack-surface.ts";
import { isCompletedTransition } from "./browser-navigation.ts";
import type { BrowserStateTransitionProbe } from "./browser-proof-types.ts";
import type { BrowserStateTransitionEvidence } from "./state.ts";
import { classifyHttpStatus, type RuntimeRequestLease } from "./runtime-safety.ts";

/** Observes one cookie-authenticated mutation initiated by an exact cross-origin policy page. */
export async function collectBrowserStateTransition(
  probe: BrowserStateTransitionProbe,
  launch: (executablePath: string) => Promise<Browser> = launchChromium,
): Promise<BrowserStateTransitionEvidence | undefined> {
  const executablePath =
    probe.executablePath ?? process.env.QUIVER_BROWSER_PATH ?? (await findBrowserExecutable());
  const browser = await launch(executablePath);
  const requestLeases = new Map<BrowserRequest, RuntimeRequestLease>();
  try {
    const context = await browser.newContext({ serviceWorkers: "block" });
    await context.addCookies(probe.cookies);
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
    const sourceUrl = new URL(probe.sourcePath, probe.sourceOrigin);
    const targetUrl = new URL(probe.targetPath, probe.targetOrigin);
    let transitionRequest: BrowserRequest | undefined;
    let resolveTransitionStatus!: (status: number) => void;
    const transitionStatus = new Promise<number>((resolve) => {
      resolveTransitionStatus = resolve;
    });
    const deadline = performance.now() + probe.timeoutMs;
    await context.route("**/*", async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const method = request.method();
      const isTarget =
        url.origin === targetUrl.origin &&
        `${url.pathname}${url.search}` === `${targetUrl.pathname}${targetUrl.search}` &&
        method === probe.method;
      if (isTarget) {
        let sourceDocument = false;
        try {
          sourceDocument = request.frame().url() === sourceUrl.href;
        } catch {
          // Requests without the policy page's frame are not attributable to the CSRF workflow.
        }
        if (
          transitionRequest ||
          !sourceDocument ||
          request.headers()["origin"] !== probe.sourceOrigin ||
          !probe.decideRequest(method, url)
        ) {
          await route.abort("blockedbyclient");
          return;
        }
        let lease: RuntimeRequestLease | undefined;
        try {
          lease = await probe.acquireRequest?.();
          if (lease) requestLeases.set(request, lease);
          if (probe.commitRequest && !probe.commitRequest(method, url)) {
            requestLeases.delete(request);
            lease?.release();
            await route.abort("blockedbyclient");
            return;
          }
          transitionRequest = request;
          await route.continue();
        } catch {
          if (transitionRequest === request) transitionRequest = undefined;
          requestLeases.delete(request);
          lease?.fail();
          await route.abort("blockedbyclient").catch(() => undefined);
        }
        return;
      }
      const isSourceRead =
        url.origin === sourceUrl.origin &&
        ["GET", "HEAD"].includes(method) &&
        (!request.isNavigationRequest() ||
          (request.frame() === page.mainFrame() && url.href === sourceUrl.href));
      if (!isSourceRead || !probe.decideRequest(method, url)) {
        await route.abort("blockedbyclient");
        return;
      }
      let lease: RuntimeRequestLease | undefined;
      try {
        lease = await probe.acquireRequest?.();
        if (lease) requestLeases.set(request, lease);
        if (probe.commitRequest && !probe.commitRequest(method, url)) {
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
      route.close({ code: 1008, reason: "Quiver browser state proof blocks WebSockets" }),
    );
    page.on("response", (response) => {
      const request = response.request();
      if (request !== transitionRequest) return;
      const lease = requestLeases.get(request);
      if (lease) {
        requestLeases.delete(request);
        lease.finish(classifyHttpStatus(response.status()));
      }
      resolveTransitionStatus(response.status());
    });
    try {
      const sourceResponse = await page.goto(sourceUrl.href, {
        waitUntil: "domcontentloaded",
        timeout: probe.timeoutMs,
      });
      if (sourceResponse?.request().redirectedFrom()) return undefined;
    } catch {
      // An auto-submitting CSRF form can replace the source document before goto settles.
      // Continue only when the exact, source-attributed policy transition is already underway.
      if (!transitionRequest) return undefined;
    }
    const remainingMs = Math.max(0, deadline - performance.now());
    const observedStatus = await Promise.race([
      transitionStatus,
      page.waitForTimeout(remainingMs).then(() => undefined),
    ]);
    return transitionRequest &&
      observedStatus !== undefined &&
      isCompletedTransition(observedStatus)
      ? {
          policyId: probe.policyId,
          sourceOrigin: probe.sourceOrigin,
          sourcePath: probe.sourcePath,
          targetPath: probe.targetPath,
          method: probe.method,
          status: observedStatus,
        }
      : undefined;
  } finally {
    for (const lease of requestLeases.values()) lease.fail();
    requestLeases.clear();
    await browser.close();
  }
}
