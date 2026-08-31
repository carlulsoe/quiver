import { describe, expect, it } from "vitest";
import { scoreCrapiReadOnlyBenchmark } from "./crapi-benchmark.ts";

describe("crAPI read-only benchmark", () => {
  it("scores unique known findings, explicit safe-control claims, and efficiency", () => {
    const score = scoreCrapiReadOnlyBenchmark({
      confirmedFindings: [
        {
          category: "broken-object-authorization",
          endpoint: "/identity/api/v2/vehicle/48ad1f93-4eb8-4f8f-a5bc-8f780e142bf9/location",
        },
        {
          category: "broken-object-authorization",
          endpoint: "/identity/api/v2/vehicle/b14cddce-e1ba-4d3a-ae43-69a1644ea264/location",
        },
        {
          category: "excessive-data-exposure",
          endpoint: "/community/api/v2/community/posts/recent?limit=30",
        },
        {
          category: "broken-object-authorization",
          endpoint: "/identity/api/v2/vehicle/vehicles",
        },
        {
          category: "other",
          endpoint: "/newly-discovered/read-only-issue",
        },
      ],
      requestsUsed: 20,
    });

    expect(score).toEqual({
      expectedCount: 4,
      truePositiveCount: 2,
      falsePositiveCount: 1,
      missedCount: 2,
      unscoredCount: 1,
      coverage: 0.5,
      precision: 2 / 3,
      requestsPerTruePositive: 10,
      matchedBenchmarkIds: ["vehicle-location-bola", "community-author-data-exposure"],
      missedBenchmarkIds: ["profile-video-internal-property", "unauthenticated-order-access"],
      falsePositiveFingerprints: [
        "broken-object-authorization:GET:/identity/api/v2/vehicle/vehicles",
      ],
      unscoredFingerprints: ["other:GET:/newly-discovered/read-only-issue"],
    });
  });

  it("returns defined zero-result metrics", () => {
    expect(scoreCrapiReadOnlyBenchmark({ confirmedFindings: [], requestsUsed: 12 })).toMatchObject({
      truePositiveCount: 0,
      falsePositiveCount: 0,
      missedCount: 4,
      coverage: 0,
      precision: 0,
      requestsPerTruePositive: null,
    });
  });

  it("matches route-template placeholders emitted by the live crawler", () => {
    const score = scoreCrapiReadOnlyBenchmark({
      confirmedFindings: [
        {
          category: "broken-object-authorization",
          endpoint: "/identity/api/v2/vehicle/<carId>/location",
        },
      ],
      requestsUsed: 5,
    });

    expect(score.matchedBenchmarkIds).toEqual(["vehicle-location-bola"]);
  });
});
