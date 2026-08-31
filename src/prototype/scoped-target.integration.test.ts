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
    expect(map.routeDetails).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: "/identity/api/v2/vehicle/vehicles",
          getCallSites: [
            expect.objectContaining({
              documentPath: expect.stringMatching(/^\/static\/js\/main\..+\.js$/),
              authentication: "likely",
            }),
          ],
        }),
        expect.objectContaining({
          path: "/identity/api/v2/vehicle/<carId>/location",
          identifierSources: [
            { parameter: "carId", sourcePath: "/identity/api/v2/vehicle/vehicles" },
          ],
        }),
      ]),
    );
  });
});
