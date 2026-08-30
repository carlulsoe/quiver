import { describe, expect, it } from "vitest";
import { createRunReport } from "./report.ts";
import type { CampaignRun } from "./runner.ts";
import { createCampaignState, reduceCampaign } from "./state.ts";

describe("campaign report", () => {
  it("reports confirmed, rejected, and unvalidated findings with budget usage", () => {
    let state = createCampaignState(
      "http://127.0.0.1:8888",
      { total: 30, exploration: 20, validation: 10 },
      1,
    );
    state = reduceCampaign(state, { type: "phase", phase: "exploring" });
    state = reduceCampaign(state, {
      type: "finding",
      finding: {
        agentId: "explorer-1",
        title: "Cross-owner vehicle location",
        category: "broken-object-authorization",
        endpoint: "/vehicles/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
        resource: "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
        rationale: "Cross-owner coordinates returned.",
        reproduction: [{ path: "/vehicles/other/location", authenticated: true }],
      },
    });
    state = reduceCampaign(state, { type: "phase", phase: "validating" });
    state = reduceCampaign(state, {
      type: "validation",
      validation: {
        fingerprint: state.findings[0]!.fingerprint,
        status: "confirmed",
        evidence: "Fresh replay returned another owner's coordinates.",
      },
    });
    state = reduceCampaign(state, { type: "phase", phase: "complete" });
    const run: CampaignRun = {
      profileId: "crapi",
      model: "openrouter/z-ai/glm-5.3-flash",
      durationMs: 1234,
      state,
      events: [],
    };

    const report = createRunReport(run, new Date("2026-08-31T00:00:00.000Z"));

    expect(report).toMatchObject({
      schemaVersion: 3,
      generatedAt: "2026-08-31T00:00:00.000Z",
      profileId: "crapi",
      outcome: {
        phase: "complete",
        budget: { total: 30, exploration: 20, validation: 10 },
        requests: { total: 0, exploration: 0, validation: 0 },
        findingCount: 1,
        confirmedCount: 1,
        rejectedCount: 0,
        unvalidatedCount: 0,
      },
    });
    expect(report.findings[0]).toMatchObject({
      title: "Cross-owner vehicle location",
      validation: { status: "confirmed" },
    });
  });
});
