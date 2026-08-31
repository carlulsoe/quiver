import { describe, expect, it } from "vitest";
import { createCampaignBudget, createCampaignState, reduceCampaign } from "./state.ts";

const firstFinding = {
  agentId: "explorer-1",
  title: "Cross-owner vehicle location",
  category: "broken-object-authorization" as const,
  severity: "high" as const,
  cwe: "CWE-639",
  endpoint: "/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
  resource: "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
  rationale: "Another user's coordinates were returned.",
  impact: "An attacker can track another user's vehicle.",
  mitigation: "Check vehicle ownership before returning its location.",
  reproduction: [
    { path: "/community/api/v2/community/posts/recent", authenticated: true },
    {
      path: "/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
      authenticated: true,
    },
  ],
  proof: {
    type: "cross-principal-access" as const,
    actor: { requestIndex: 0, jsonPointer: "/viewer/email" },
    resourceOwner: { requestIndex: 1, jsonPointer: "/email" },
    accessRequestIndex: 1,
    evidencePointers: ["/vehicleLocation/latitude"],
  },
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

  it("deduplicates findings whose endpoints differ only by a trailing slash", () => {
    const initial = createCampaignState("http://127.0.0.1:8888", {
      total: 30,
      exploration: 20,
      validation: 10,
    });
    const withFirst = reduceCampaign(initial, { type: "finding", finding: firstFinding });
    const withTrailingSlash = reduceCampaign(withFirst, {
      type: "finding",
      finding: { ...firstFinding, endpoint: `${firstFinding.endpoint}/` },
    });

    expect(withTrailingSlash.findings).toHaveLength(1);
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
        proof: {
          predicate: "cross-principal-access",
          passed: true,
          summary: "All checks passed.",
          checks: [],
        },
        observations: [],
        reviewer: { assessment: "supported", evidence: "Replay supports the claim." },
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

  it("reclaims unused exploration requests for validation", () => {
    let state = createCampaignState("http://127.0.0.1:8888", {
      total: 30,
      exploration: 20,
      validation: 10,
    });
    state = reduceCampaign(state, { type: "request", phase: "exploration" });
    state = reduceCampaign(state, { type: "request", phase: "exploration" });

    const rebalanced = reduceCampaign(state, { type: "reclaim-exploration-budget" });

    expect(rebalanced.budget).toEqual({ total: 30, exploration: 2, validation: 28 });
  });

  it("exposes completed exploration tests to campaign observers", () => {
    const initial = createCampaignState("http://127.0.0.1:8888", {
      total: 30,
      exploration: 20,
      validation: 10,
    });
    const tested = reduceCampaign(initial, {
      type: "request-tested",
      request: {
        agentId: "explorer-1",
        path: "/api/items/42",
        authenticated: true,
        status: 200,
      },
    });

    expect(tested.testedRequests).toEqual([
      {
        agentId: "explorer-1",
        path: "/api/items/42",
        authenticated: true,
        status: 200,
      },
    ]);
  });
});
