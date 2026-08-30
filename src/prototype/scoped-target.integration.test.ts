import { describe, expect, it } from "vitest";
import { ScopedTarget } from "./scoped-target.ts";

const targetUrl = new URL(process.env.XBOW_TARGET ?? "http://127.0.0.1:8888");

describe("live target discovery", () => {
  it("derives crAPI endpoints from the frontend instead of a supplied route list", async () => {
    const target = new ScopedTarget({ target: targetUrl, requestBudget: 5 });

    const map = await target.crawl({ maxDocuments: 3 });

    expect(map.routes).toEqual(
      expect.arrayContaining([
        "/identity/api/auth/login",
        "/identity/api/v2/user/dashboard",
        "/identity/api/v2/vehicle/vehicles",
        "/community/api/v2/community/posts/recent",
      ]),
    );
  });
});
