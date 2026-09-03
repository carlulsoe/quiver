import { describe, expect, it, vi } from "vitest";
import { findBrowserExecutable, launchChromium } from "./attack-surface-scope.ts";
import { browserStubSchema } from "./browser-test-helpers.ts";
import * as v from "valibot";

const inaccessible = async (): Promise<boolean> => false;

describe("browser runtime", () => {
  it("uses Playwright's matching managed Chromium by default", async () => {
    await expect(
      findBrowserExecutable(undefined, {
        environmentPath: undefined,
        managedPath: "/managed/chromium",
        canAccess: async (path) => path === "/managed/chromium",
      }),
    ).resolves.toBe("/managed/chromium");
  });

  it("retains explicit configuration and QUIVER_BROWSER_PATH override precedence", async () => {
    const dependencies = {
      environmentPath: "/environment/chromium",
      managedPath: "/managed/chromium",
      canAccess: async () => true,
    };
    await expect(findBrowserExecutable(undefined, dependencies)).resolves.toBe(
      "/environment/chromium",
    );
    await expect(findBrowserExecutable("/configured/chromium", dependencies)).resolves.toBe(
      "/configured/chromium",
    );
  });

  it("explains how to provision a missing managed browser", async () => {
    await expect(
      findBrowserExecutable(undefined, {
        environmentPath: undefined,
        managedPath: "/missing/chromium",
        canAccess: inaccessible,
      }),
    ).rejects.toThrow(
      "Playwright-managed browser was not found at /missing/chromium. Run `bun run browser:install`",
    );
  });

  it("identifies an inaccessible override without silently falling back", async () => {
    await expect(
      findBrowserExecutable(undefined, {
        environmentPath: "/missing/override",
        managedPath: "/managed/chromium",
        canAccess: inaccessible,
      }),
    ).rejects.toThrow("QUIVER_BROWSER_PATH override was not found at /missing/override");
  });

  it("reports the selected browser version and path after launch", async () => {
    const browser = v.parse(browserStubSchema, {
      async newContext() {},
      async close() {},
      version: () => "142.0.0",
    });
    const launch = vi.fn(async () => browser);
    const report = vi.fn();

    await expect(launchChromium("/managed/chromium", launch, report)).resolves.toBe(browser);
    expect(launch).toHaveBeenCalledWith({ executablePath: "/managed/chromium", headless: true });
    expect(report).toHaveBeenCalledWith("[quiver] Chromium 142.0.0 (/managed/chromium)");
  });

  it("adds the selected path to launch failures", async () => {
    await expect(
      launchChromium(
        "/override/chromium",
        async () => {
          throw new Error("unsupported revision");
        },
        () => undefined,
      ),
    ).rejects.toThrow("Failed to launch Chromium at /override/chromium: unsupported revision");
  });
});
