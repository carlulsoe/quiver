import * as v from "valibot";
import { describe, expect, it } from "vitest";
import { collectBrowserStateTransition } from "./browser-proof.ts";
import { browserStubSchema } from "./browser-test-helpers.ts";

describe("browser state-transition proof collector", () => {
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
    const committedRequests: string[] = [];
    const leaseOutcomes: string[] = [];
    let leaseSequence = 0;
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
    const browser = v.parse(browserStubSchema, {
      newContext: async () => context,
      close: async () => undefined,
    });

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
          executablePath: process.execPath,
          decideRequest: () => true,
          acquireRequest: async () => {
            const leaseId = leaseSequence++;
            let finished = false;
            const record = (outcome: string) => {
              if (finished) return;
              finished = true;
              leaseOutcomes.push(`${leaseId}:${outcome}`);
            };
            return {
              finish: (outcome = "success") => record(outcome),
              fail: (disruptive = false) => record(disruptive ? "disruptive" : "failure"),
              release: () => record("released"),
            };
          },
          commitRequest: (method, url) => {
            committedRequests.push(`${method} ${url.href}`);
            return true;
          },
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
    expect(committedRequests).toEqual([
      "GET http://127.0.0.1:9999/csrf/email",
      "POST http://127.0.0.1:8888/account/email",
    ]);
    expect(leaseOutcomes).toEqual(["1:success", "0:failure"]);
  });
});
