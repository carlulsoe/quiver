import { describe, expect, it } from "vitest";
import { ScopedTarget } from "../prototype/scoped-target.ts";
import { crapiProfile } from "./crapi.ts";

const targetUrl = new URL(process.env.XBOW_TARGET ?? "http://127.0.0.1:8888");

describe("live crAPI target profile", () => {
  it("establishes an opaque ordinary-user session for generic campaign requests", async () => {
    const target = new ScopedTarget({
      target: targetUrl,
      requestBudget: 2,
      allowedRequests: crapiProfile.allowedRequests,
    });

    await expect(crapiProfile.authenticate!(target)).resolves.toEqual({
      authContext: "ordinary-test-user",
    });
    await expect(
      target.request({ path: "/identity/api/v2/user/dashboard", authenticated: true }),
    ).resolves.toMatchObject({ status: 200 });
  });
});
