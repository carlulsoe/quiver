import { describe, expect, it } from "vitest";
import { ScopedTarget } from "../prototype/scoped-target.ts";
import { crapiProfile } from "./crapi.ts";

interface RecentPostsResponse {
  posts?: Array<{ author?: { vehicleid?: unknown } }>;
}

const targetUrl = new URL(process.env.XBOW_TARGET ?? "http://127.0.0.1:8888");

function createTarget(): ScopedTarget {
  return new ScopedTarget({
    target: targetUrl,
    requestBudget: 10,
    allowedRequests: crapiProfile.allowedRequests,
  });
}

describe("live crAPI target profile", () => {
  it("rejects the seeded user's own vehicle as a BOLA", async () => {
    const target = createTarget();
    const candidate = await crapiProfile.createNegativeControl!(target);

    const result = await crapiProfile.validate(target, candidate);

    expect(result).toMatchObject({ confirmed: false, reason: "same-owner" });
  });

  it("confirms a vehicle published by another community user", async () => {
    const target = createTarget();
    await crapiProfile.authenticate!(target);
    const recent = await target.request({
      path: "/community/api/v2/community/posts/recent",
      authenticated: true,
    });
    const posts = recent.body as RecentPostsResponse;
    const vehicleId = posts.posts
      ?.map((post) => post.author?.vehicleid)
      .find((value): value is string => typeof value === "string");
    expect(vehicleId).toBeDefined();

    const result = await crapiProfile.validate(target, {
      agentId: "integration-test",
      title: "Cross-owner vehicle location",
      category: "BOLA",
      resource: vehicleId!,
      sourcePath: "/community/api/v2/community/posts/recent",
      proofPath: `/identity/api/v2/vehicle/${vehicleId}/location`,
      rationale: "A different user's public post disclosed the identifier.",
    });

    expect(result).toMatchObject({ confirmed: true, reason: "cross-owner-coordinates" });
  });
});
