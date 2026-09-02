import type { BrowserContext, Page } from "playwright-core";
import { inspectForms } from "./discovery/forms.ts";
import { attachAttackSurfaceNetwork } from "./attack-surface-network.ts";
import { recordForms } from "./attack-surface-observation.ts";
import {
  attackSurfaceIdentifier,
  isExpectedNavigationInterruption,
  scopedUrl,
} from "./attack-surface-scope.ts";
import type { AttackSurfaceState, CurrentDocument } from "./attack-surface-state.ts";
import type { AttackSurfaceScope, BrowserCookie } from "./attack-surface-types.ts";
import { exploreWorkflow } from "./attack-surface-workflow.ts";

export async function mapBrowserContext(
  state: AttackSurfaceState,
  context: BrowserContext,
): Promise<void> {
  if (state.options.cookies?.length) await context.addCookies(state.options.cookies);
  await installStorage(state, context);
  const current: CurrentDocument = {
    path: attackSurfaceIdentifier(state, new URL(state.options.startPath, state.options.origin)),
    origin: state.options.origin,
    scope: "attackable",
  };
  const page = await context.newPage();
  const pendingResponses: Promise<void>[] = [];
  await attachAttackSurfaceNetwork(state, context, page, current, pendingResponses);
  await crawlDocuments(state, context, page, current);
  state.automaticInteraction = false;
  await Promise.all(pendingResponses);
}

async function installStorage(state: AttackSurfaceState, context: BrowserContext): Promise<void> {
  if (!state.options.localStorage && !state.options.sessionStorage) return;
  await context.addInitScript(
    (storage) => {
      if (location.origin !== storage.origin) return;
      for (const [name, value] of Object.entries(storage.local)) localStorage.setItem(name, value);
      for (const [name, value] of Object.entries(storage.session))
        sessionStorage.setItem(name, value);
    },
    {
      origin: state.options.origin,
      local: state.options.localStorage ?? {},
      session: state.options.sessionStorage ?? {},
    },
  );
}

async function crawlDocuments(
  state: AttackSurfaceState,
  context: BrowserContext,
  page: Page,
  current: CurrentDocument,
): Promise<void> {
  const cookieJars = new Map<string, BrowserCookie[]>();
  let activeCookieOrigin = state.options.origin;
  const selectCookieJar = async (origin: string) => {
    if (origin === activeCookieOrigin) return;
    cookieJars.set(activeCookieOrigin, await context.cookies());
    await context.clearCookies();
    const cookies = cookieJars.get(origin);
    if (cookies?.length) await context.addCookies(cookies);
    activeCookieOrigin = origin;
  };
  const start = new URL(state.options.startPath, state.options.origin).href;
  const queue = [start];
  const queued = new Set(queue);
  let visited = 0;
  while (queue.length > 0 && visited < state.options.maxDocuments) {
    const scoped = scopedUrl(state, queue.shift()!);
    if (!scoped) continue;
    visited += 1;
    current.path = attackSurfaceIdentifier(state, scoped.url);
    current.origin = scoped.origin;
    current.scope = scoped.scope;
    state.automaticInteraction = false;
    await selectCookieJar(scoped.origin);
    try {
      await page.goto(scoped.url.href, {
        waitUntil: "domcontentloaded",
        timeout: state.options.timeoutMs,
      });
    } catch (error) {
      if (!isExpectedNavigationInterruption(error)) throw error;
    }
    await page
      .waitForLoadState("networkidle", {
        timeout: Math.min(state.options.timeoutMs, 1_000),
      })
      .catch(() => undefined);
    await page.waitForTimeout(75);
    const discoveredLinks = await scopedLinks(page, state.scopes);
    if (scoped.scope === "attackable") {
      await exploreWorkflow(state, page, current.path, (path, origin, scope) => {
        current.path = path;
        current.origin = origin;
        current.scope = scope;
      });
    } else recordForms(state, await inspectForms(page), current.path);
    for (const href of [...discoveredLinks, ...(await scopedLinks(page, state.scopes))]) {
      if (!queued.has(href)) {
        queued.add(href);
        queue.push(href);
      }
    }
    const location = scopedUrl(state, page.url());
    if (location && !queued.has(location.url.href)) {
      queued.add(location.url.href);
      queue.push(location.url.href);
    }
  }
}

async function scopedLinks(
  page: Page,
  scopes: ReadonlyMap<string, AttackSurfaceScope>,
): Promise<string[]> {
  const visitableOrigins = [...scopes]
    .filter(([, scope]) => scope === "attackable" || scope === "visit-only")
    .map(([origin]) => origin);
  return page
    .locator("a[href]")
    .evaluateAll(
      (anchors, origins) => [
        ...new Set(
          anchors.flatMap((anchor) => {
            try {
              const href = (anchor as HTMLAnchorElement).href;
              return origins.includes(new URL(href).origin) ? [href] : [];
            } catch {
              return [];
            }
          }),
        ),
      ],
      visitableOrigins,
    )
    .catch(() => []);
}
