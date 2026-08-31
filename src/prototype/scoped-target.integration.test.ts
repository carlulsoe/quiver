import { describe, expect, it } from "vitest";
import { ScopedTarget } from "./scoped-target.ts";
import { crapiProfile } from "../targets/crapi.ts";

const targetUrl = new URL(process.env.XBOW_TARGET ?? "http://127.0.0.1:8888");

describe("live target discovery", () => {
  it("observes crAPI operations from an authenticated browser session", async () => {
    const target = new ScopedTarget({
      target: targetUrl,
      requestBudget: 20,
      allowedRequests: crapiProfile.allowedRequests,
    });
    await crapiProfile.authenticate!(target);

    const map = await target.mapAttackSurface({ maxDocuments: 3 });

    expect(map.routeDetails).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: "/identity/api/v2/user/dashboard",
          callSites: [
            expect.objectContaining({
              documentPath: "/",
              method: "GET",
              authentication: "likely",
            }),
          ],
        }),
        expect.objectContaining({ path: "/identity/api/auth/verify", methods: ["POST"] }),
      ]),
    );
  });
});
