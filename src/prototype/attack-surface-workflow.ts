import type { Page } from "playwright-core";
import { fillForm, inspectForms } from "./discovery/forms.ts";
import { recordForms } from "./attack-surface-observation.ts";
import {
  attackSurfaceIdentifier,
  isExpectedNavigationInterruption,
  scopedUrl,
} from "./attack-surface-scope.ts";
import type { AttackSurfaceState } from "./attack-surface-state.ts";
import type { AttackSurfaceScope } from "./attack-surface-types.ts";

export async function exploreWorkflow(
  state: AttackSurfaceState,
  page: Page,
  initialDocument: string,
  setCurrentDocument: (path: string, origin: string, scope: AttackSurfaceScope) => void,
): Promise<void> {
  const exercised = new Set<string>();
  let documentPath = initialDocument;
  for (let step = 0; step < 4; step += 1) {
    const candidates = await inspectForms(page);
    recordForms(state, candidates, documentPath);
    const candidate = candidates.find((form) => {
      const key = `${page.url()} ${form.index} ${form.action} ${form.method}`;
      return (
        !exercised.has(key) &&
        form.purposeful &&
        !form.destructive &&
        new URL(form.action).origin === new URL(page.url()).origin &&
        form.fields.length > 0
      );
    });
    if (!candidate) return;
    const key = `${page.url()} ${candidate.index} ${candidate.action} ${candidate.method}`;
    const form = page.locator("form").nth(candidate.index);
    await fillForm(form, candidate);
    const oldUrl = page.url();
    state.automaticInteraction = true;
    const action = new URL(candidate.action);
    let settleRequest!: () => void;
    const requestDecision = new Promise<void>((resolve) => {
      settleRequest = resolve;
    });
    state.activeFormRequest = {
      method: candidate.method,
      origin: action.origin,
      pathname: action.pathname,
      allowed: false,
      observed: false,
      settle: settleRequest,
    };
    const navigation = page
      .waitForNavigation({ waitUntil: "domcontentloaded", timeout: state.options.timeoutMs })
      .catch(() => undefined);
    await form
      .evaluate((element: HTMLFormElement, submitterIndex) => {
        const submitters = [
          ...element.querySelectorAll<HTMLButtonElement | HTMLInputElement>(
            'button:not([disabled]), input[type="submit"]:not([disabled]), input[type="image"]:not([disabled])',
          ),
        ].filter(
          (control) =>
            control instanceof HTMLInputElement || control.type.toLowerCase() === "submit",
        );
        element.requestSubmit(submitterIndex < 0 ? undefined : submitters[submitterIndex]);
      }, candidate.submitterIndex)
      .catch(() => undefined);
    await Promise.race([
      navigation,
      requestDecision,
      page.waitForTimeout(Math.min(500, state.options.timeoutMs)),
    ]);
    const active = state.activeFormRequest;
    if (!active) return;
    if (active.observed) exercised.add(key);
    if (active.allowed) await navigation;
    await page.waitForTimeout(75);
    const attempted = active.observed;
    const submitted = active.allowed;
    state.activeFormRequest = undefined;
    state.automaticInteraction = false;
    const recorded = state.forms.findLast(
      (item) =>
        item.documentPath === documentPath &&
        item.index === candidate.index &&
        item.action === candidate.action &&
        item.method === candidate.method,
    );
    if (recorded) {
      recorded.attempted = attempted;
      recorded.submitted = submitted;
    }
    if (!submitted) {
      if (attempted) await navigation;
      if (page.url() !== oldUrl) {
        try {
          await page.goto(oldUrl, {
            waitUntil: "domcontentloaded",
            timeout: state.options.timeoutMs,
          });
        } catch (error) {
          if (!isExpectedNavigationInterruption(error)) throw error;
        }
      }
      await page.waitForTimeout(75);
      continue;
    }
    if (page.url() !== oldUrl) {
      const current = scopedUrl(state, page.url());
      if (!current || current.scope !== "attackable") return;
      documentPath = attackSurfaceIdentifier(state, current.url);
      setCurrentDocument(documentPath, current.origin, current.scope);
    }
  }
}
