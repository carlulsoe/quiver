import type { Browser } from "playwright-core";
import { describe, expect, it } from "vitest";
import { collectBrowserEffect, isExpectedDocumentNavigation } from "./browser-proof.ts";

describe("browser-visible proof collector", () => {
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
