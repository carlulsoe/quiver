import type { Browser } from "playwright-core";
import { describe, expect, it } from "vitest";
import {
  collectBrowserEffect,
  collectBrowserStateTransition,
  isExpectedDocumentNavigation,
} from "./browser-proof.ts";

describe("browser-visible proof collector", () => {
  it("attributes a cookie-backed transition only to the exact cross-origin policy page", async () => {
    type SyntheticRequest = {
      url: () => string;
      method: () => string;
      frame: () => { url: () => string };
      headers: () => Record<string, string>;
      isNavigationRequest: () => boolean;
    };
    type SyntheticRoute = {
      request: () => SyntheticRequest;
      continue: () => Promise<void>;
      abort: () => Promise<void>;
    };
    let routeHandler: ((route: SyntheticRoute) => Promise<void>) | undefined;
    let responseHandler:
      | ((response: { request: () => SyntheticRequest; status: () => number }) => void)
      | undefined;
    const sourceUrl = "http://127.0.0.1:9999/csrf/email";
    const frame = { url: () => sourceUrl };
    const sourceRequest: SyntheticRequest = {
      url: () => sourceUrl,
      method: () => "GET",
      frame: () => frame,
      headers: () => ({}),
      isNavigationRequest: () => true,
    };
    const transitionRequest: SyntheticRequest = {
      url: () => "http://127.0.0.1:8888/account/email",
      method: () => "POST",
      frame: () => frame,
      headers: () => ({ origin: "http://127.0.0.1:9999" }),
      isNavigationRequest: () => true,
    };
    const continueRequest = async (_request: SyntheticRequest) => undefined;
    const page = {
      mainFrame: () => frame,
      on: (event: string, handler: typeof responseHandler) => {
        if (event === "response") responseHandler = handler;
      },
      goto: async () => {
        await routeHandler?.({
          request: () => sourceRequest,
          continue: () => continueRequest(sourceRequest),
          abort: async () => undefined,
        });
        await routeHandler?.({
          request: () => transitionRequest,
          continue: () => continueRequest(transitionRequest),
          abort: async () => undefined,
        });
        throw new Error("source navigation interrupted by the submitted form");
      },
      waitForTimeout: async (timeoutMs: number) => {
        expect(timeoutMs).toBeGreaterThan(100);
        responseHandler?.({ request: () => transitionRequest, status: () => 302 });
      },
    };
    const context = {
      addCookies: async () => undefined,
      route: async (_pattern: string, handler: typeof routeHandler) => {
        routeHandler = handler;
      },
      routeWebSocket: async () => undefined,
      newPage: async () => page,
      on: () => undefined,
    };
    const browser = {
      newContext: async () => context,
      close: async () => undefined,
    } as unknown as Browser;

    await expect(
      collectBrowserStateTransition(
        {
          policyId: "email-csrf",
          targetOrigin: "http://127.0.0.1:8888",
          sourceOrigin: "http://127.0.0.1:9999",
          sourcePath: "/csrf/email",
          targetPath: "/account/email",
          method: "POST",
          timeoutMs: 1_000,
          cookies: [{ name: "session", value: "victim", url: "http://127.0.0.1:8888" }],
          executablePath: "/synthetic/chromium",
          decideRequest: () => true,
        },
        async () => browser,
      ),
    ).resolves.toEqual({
      policyId: "email-csrf",
      sourceOrigin: "http://127.0.0.1:9999",
      sourcePath: "/csrf/email",
      targetPath: "/account/email",
      method: "POST",
      status: 302,
    });
  });

  it("allows assets but blocks every child-frame document", () => {
    const expected = new URL("http://127.0.0.1:8888/victim");
    expect(
      isExpectedDocumentNavigation(false, false, new URL("/asset.js", expected), expected),
    ).toBe(true);
    expect(isExpectedDocumentNavigation(true, false, new URL("/frame", expected), expected)).toBe(
      false,
    );
    expect(isExpectedDocumentNavigation(true, true, expected, expected)).toBe(true);
  });

  it("does not attribute a dialog observed after a redirect to the policy page", async () => {
    let dialogHandler:
      | ((dialog: { message: () => string; dismiss: () => Promise<void> }) => void)
      | undefined;
    const page = {
      on: (event: string, handler: typeof dialogHandler) => {
        if (event === "dialog") dialogHandler = handler;
      },
      goto: async () => {
        dialogHandler?.({
          message: () => "QUIVER-BROWSER-1",
          dismiss: async () => undefined,
        });
        return { request: () => ({ redirectedFrom: () => ({}) }) };
      },
      url: () => "http://127.0.0.1:8888/landing",
      waitForTimeout: async () => undefined,
    };
    const context = {
      addCookies: async () => undefined,
      addInitScript: async () => undefined,
      route: async () => undefined,
      routeWebSocket: async () => undefined,
      newPage: async () => page,
      on: () => undefined,
    };
    const browser = {
      newContext: async () => context,
      close: async () => undefined,
    } as unknown as Browser;

    await expect(
      collectBrowserEffect(
        {
          probeId: "probe-1",
          origin: "http://127.0.0.1:8888",
          path: "/victim",
          marker: "QUIVER-BROWSER-1",
          kind: "dialog",
          timeoutMs: 1_000,
          executablePath: "/synthetic/chromium",
          decideRequest: () => true,
        },
        async () => browser,
      ),
    ).resolves.toBeUndefined();
  });

  it("does not accept a dialog emitted on another SPA route before URL restoration", async () => {
    type Dialog = { message: () => string; dismiss: () => Promise<void> };
    let dialogHandler: ((dialog: Dialog) => void) | undefined;
    let currentUrl = "http://127.0.0.1:8888/victim";
    const page = {
      on: (event: string, handler: typeof dialogHandler) => {
        if (event === "dialog") dialogHandler = handler;
      },
      goto: async () => {
        currentUrl = "http://127.0.0.1:8888/other";
        dialogHandler?.({
          message: () => "QUIVER-BROWSER-1",
          dismiss: async () => undefined,
        });
        currentUrl = "http://127.0.0.1:8888/victim";
        return { request: () => ({ redirectedFrom: () => null }) };
      },
      url: () => currentUrl,
      waitForTimeout: async () => undefined,
    };
    const context = {
      addCookies: async () => undefined,
      addInitScript: async () => undefined,
      route: async () => undefined,
      routeWebSocket: async () => undefined,
      newPage: async () => page,
      on: () => undefined,
    };
    const browser = {
      newContext: async () => context,
      close: async () => undefined,
    } as unknown as Browser;

    await expect(
      collectBrowserEffect(
        {
          probeId: "probe-1",
          origin: "http://127.0.0.1:8888",
          path: "/victim",
          marker: "QUIVER-BROWSER-1",
          kind: "dialog",
          timeoutMs: 1_000,
          executablePath: "/synthetic/chromium",
          decideRequest: () => true,
        },
        async () => browser,
      ),
    ).resolves.toBeUndefined();
  });
});
