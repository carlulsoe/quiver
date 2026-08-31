import { describe, expect, it } from "vitest";
import { RequestBudgetExceededError, ScopedTarget, TargetScopeError } from "./scoped-target.ts";

function response(body: string, contentType: string): Response {
  return new Response(body, { status: 200, headers: { "content-type": contentType } });
}

describe("scoped target", () => {
  it("crawls linked frontend code and derives routes from string composition", async () => {
    const requested: string[] = [];
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888/start"),
      requestBudget: 5,
      transport: async (input) => {
        const url = new URL(String(input));
        requested.push(url.pathname);
        if (url.pathname === "/start") {
          return response(
            '<a href="/docs">Docs</a><script src="/assets/app.js"></script><a href="https://example.com/escape">elsewhere</a>',
            "text/html",
          );
        }
        if (url.pathname === "/assets/app.js") {
          return response(
            'const noise="/><svg></svg>";const service="identity/",routes={LOGIN:"api/auth/login",DASHBOARD:"api/v2/user/dashboard"};fetch(service+routes.LOGIN);fetch(service+routes.DASHBOARD)',
            "application/javascript",
          );
        }
        return response("documentation", "text/html");
      },
    });

    const map = await target.crawl({ maxDocuments: 3 });

    expect(requested).toEqual(["/start", "/docs", "/assets/app.js"]);
    expect(map.documents.map((document) => document.path)).toEqual([
      "/start",
      "/docs",
      "/assets/app.js",
    ]);
    expect(map.routes).toEqual(
      expect.arrayContaining(["/identity/api/auth/login", "/identity/api/v2/user/dashboard"]),
    );
    expect(map.routes).not.toContain("https://example.com/escape");
    expect(map.routes.some((route) => route.includes("svg"))).toBe(false);
  });

  it("enforces one request budget across crawling and direct requests", async () => {
    const target = new ScopedTarget({
      target: new URL("http://localhost:8888"),
      requestBudget: 1,
      transport: async () => response("ok", "text/plain"),
    });

    await target.request({ path: "/first" });

    await expect(target.request({ path: "/second" })).rejects.toBeInstanceOf(
      RequestBudgetExceededError,
    );
  });

  it("shares one crawl map across concurrent explorers", async () => {
    let requests = 0;
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      transport: async () => {
        requests += 1;
        return response("<main>target</main>", "text/html");
      },
    });

    const [first, second] = await Promise.all([target.crawl(), target.crawl()]);

    expect(requests).toBe(1);
    expect(second).toBe(first);
  });

  it("rejects non-loopback targets and cross-origin request paths", async () => {
    expect(
      () =>
        new ScopedTarget({
          target: new URL("https://example.com"),
          requestBudget: 1,
        }),
    ).toThrow(TargetScopeError);

    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
    });
    await expect(target.request({ path: "//example.com/escape" })).rejects.toBeInstanceOf(
      TargetScopeError,
    );
  });

  it("blocks profile-denied GET routes before transport or budget use", async () => {
    let requests = 0;
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
      deniedRequests: [{ method: "GET", path: "/api/state-changing-read" }],
      transport: async () => {
        requests += 1;
        return response("unexpected", "text/plain");
      },
    });

    await expect(target.request({ path: "/api/state-changing-read?value=1" })).rejects.toThrow(
      "GET /api/state-changing-read is denied by the target profile",
    );
    expect(requests).toBe(0);
    await expect(target.request({ path: "/safe" })).resolves.toMatchObject({ status: 200 });
  });

  it("discovers but does not crawl profile-denied links", async () => {
    const requested: string[] = [];
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 2,
      deniedRequests: [{ method: "GET", path: "/api/state-changing-read" }],
      transport: async (input) => {
        requested.push(new URL(String(input)).pathname);
        return response('<a href="/api/state-changing-read">unsafe</a>', "text/html");
      },
    });

    const map = await target.crawl();

    expect(map.routes).toContain("/api/state-changing-read");
    expect(requested).toEqual(["/"]);
  });

  it("caps response bodies before exposing them", async () => {
    const target = new ScopedTarget({
      target: new URL("http://127.0.0.1:8888"),
      requestBudget: 1,
      maxResponseChars: 5,
      transport: async () => response("abcdefgh", "text/plain"),
    });

    await expect(target.request({ path: "/large" })).resolves.toMatchObject({
      body: "abcde",
      truncated: true,
    });
  });
});
