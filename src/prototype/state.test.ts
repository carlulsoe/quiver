import { describe, expect, it } from "vitest";
import { createCampaignBudget, createCampaignState, reduceCampaign } from "./state.ts";

const firstFinding = {
  agentId: "explorer-1",
  title: "Cross-owner vehicle location",
  category: "broken-object-authorization" as const,
  endpoint: "/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
  resource: "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
  rationale: "Another user's coordinates were returned.",
  reproduction: [
    { path: "/community/api/v2/community/posts/recent", authenticated: true },
    {
      path: "/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
      authenticated: true,
    },
  ],
};

describe("campaign state", () => {
  it("reserves one third of the total request budget for independent validation", () => {
    expect(createCampaignBudget(30)).toEqual({ total: 30, exploration: 20, validation: 10 });
  });

  it("deduplicates resources affected by the same vulnerability fingerprint", () => {
    const initial = createCampaignState("http://127.0.0.1:8888", {
      total: 30,
      exploration: 20,
      validation: 10,
    });
    const withFirst = reduceCampaign(initial, { type: "finding", finding: firstFinding });
    const withDuplicate = reduceCampaign(withFirst, {
      type: "finding",
      finding: {
        ...firstFinding,
        agentId: "explorer-2",
        endpoint: "/identity/api/v2/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location",
        resource: "f89b5f21-7829-45cb-a650-299a61090378",
      },
    });

    expect(withDuplicate.findings).toHaveLength(1);
    expect(withDuplicate.findings[0]).toMatchObject({
      fingerprint: "broken-object-authorization:GET:/identity/api/v2/vehicle/{id}/location",
      resource: "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
    });
  });

  it("canonicalizes route-template placeholders from the live crawler", () => {
    const initial = createCampaignState("http://127.0.0.1:8888", {
      total: 30,
      exploration: 20,
      validation: 10,
    });
    const withFinding = reduceCampaign(initial, {
      type: "finding",
      finding: {
        ...firstFinding,
        endpoint: "/identity/api/v2/vehicle/<carId>/location",
      },
    });

    expect(withFinding.findings[0]!.fingerprint).toBe(
      "broken-object-authorization:GET:/identity/api/v2/vehicle/{id}/location",
    );
  });

  it("records outcomes for multiple findings before campaign completion", () => {
    const initial = createCampaignState("http://127.0.0.1:8888", {
      total: 30,
      exploration: 20,
      validation: 10,
    });
    const exploring = reduceCampaign(initial, { type: "phase", phase: "exploring" });
    const withFinding = reduceCampaign(exploring, { type: "finding", finding: firstFinding });
    const validating = reduceCampaign(withFinding, { type: "phase", phase: "validating" });
    const validated = reduceCampaign(validating, {
      type: "validation",
      validation: {
        fingerprint: withFinding.findings[0]!.fingerprint,
        status: "confirmed",
        evidence: "Independent replay returned cross-owner coordinates.",
      },
    });

    expect(validated.phase).toBe("validating");
    expect(validated.validations).toHaveLength(1);
    expect(reduceCampaign(validated, { type: "phase", phase: "complete" }).phase).toBe("complete");
  });

  it("tracks exploration and validation requests against one total budget", () => {
    const initial = createCampaignState("http://127.0.0.1:8888", {
      total: 30,
      exploration: 20,
      validation: 10,
    });
    const explored = reduceCampaign(initial, { type: "request", phase: "exploration" });
    const validated = reduceCampaign(explored, { type: "request", phase: "validation" });

    expect(validated.requests).toEqual({ total: 2, exploration: 1, validation: 1 });
  });
});
