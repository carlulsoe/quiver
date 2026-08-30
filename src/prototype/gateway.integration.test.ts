import { describe, expect, it } from "vitest";
import { LocalCrapiGateway } from "./gateway.ts";

interface RecentPostsResponse {
  posts?: Array<{ author?: { vehicleid?: unknown } }>;
}

const target = new URL(process.env.XBOW_TARGET ?? "http://127.0.0.1:8888");

function liveGateway(): LocalCrapiGateway {
  return new LocalCrapiGateway({ target, requestBudget: 10 });
}

describe("live crAPI gateway", () => {
  it("rejects the seeded user's own vehicle as a BOLA", async () => {
    const gateway = liveGateway();
    await gateway.healthcheck();
    const ownVehicleId = await gateway.getOwnVehicleId();

    const result = await gateway.reproduceBola(ownVehicleId);

    expect(result).toMatchObject({ confirmed: false, reason: "same-owner" });
  });

  it("confirms a vehicle published by another community user", async () => {
    const gateway = liveGateway();
    await gateway.healthcheck();
    const recent = await gateway.get("/community/api/v2/community/posts/recent", true);
    const posts = recent.body as RecentPostsResponse;
    const publishedVehicleId = posts.posts
      ?.map((post) => post.author?.vehicleid)
      .find((vehicleId): vehicleId is string => typeof vehicleId === "string");

    expect(publishedVehicleId).toBeDefined();
    const result = await gateway.reproduceBola(publishedVehicleId!);

    expect(result).toMatchObject({
      confirmed: true,
      reason: "cross-owner-coordinates",
      facts: { differentOwner: true, hasCoordinates: true },
    });
  });
});
