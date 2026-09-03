import { describe, expect, it } from "vitest";
import { createRunReport } from "./report.ts";
import { confirmedCampaignRun, reportCredentialSentinel } from "./report-test-fixture.ts";

describe("campaign report", () => {
  it("reports outcomes, budget usage, and redacted evidence", () => {
    const report = createRunReport(confirmedCampaignRun(), new Date("2026-09-02T12:00:00Z"));
    expect(report).toMatchObject({
      schemaVersion: 9,
      generatedAt: "2026-09-02T12:00:00.000Z",
      outcome: { findingCount: 1, confirmedCount: 1, rejectedCount: 0, unvalidatedCount: 0 },
      findings: [{ title: "Cross-owner vehicle location", validation: { status: "confirmed" } }],
    });
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain("report-secret");
    expect(serialized).not.toContain("body-secret");
    expect(serialized).not.toContain("event-secret");
    expect(serialized).not.toContain(reportCredentialSentinel);
    expect(serialized).toContain('"actual":"[REDACTED] == [REDACTED]"');
    expect(serialized).toContain(
      '"redirectLocation":"https://redirect.invalid/landing?access_token=%5BREDACTED%5D"',
    );
    expect(serialized).toContain('"buildId":"build-7"');
    expect(serialized).toContain('"status":200');
    expect(serialized).toContain('"author":"Ada"');
  });
});
