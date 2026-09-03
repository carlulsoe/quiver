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
    expect(report.findings[0]?.validation).toMatchObject({
      reviewer: {
        evidence:
          "Fresh replay supports the claim. Credential [REDACTED], PIN [REDACTED], OTP [REDACTED], and token [REDACTED] were present.",
      },
      observations: [
        {
          status: 200,
          truncated: false,
          redirected: false,
          body: {
            pin: "[REDACTED]",
            otp: "[REDACTED]",
            token: "[REDACTED]",
            counter: "[REDACTED]",
            diagnosticCount: "[REDACTED]",
            enabled: "[REDACTED]",
          },
        },
      ],
    });
    expect(report.events[0]).toMatchObject({
      sequence: 1,
      elapsedMs: 10,
      data: {
        requestsUsed: 200,
        findingCount: 1,
        durationMs: 200,
        input: {
          body: '{"accessToken":"[REDACTED]","pin":"[REDACTED]","otp":"[REDACTED]"}',
        },
      },
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
    expect(serialized).toContain('"findingCount":1');
    expect(serialized).toContain('"truncated":false');
    expect(serialized).toContain('"redirected":false');
    expect(serialized).toContain('"author":"Ada"');
  });
});
