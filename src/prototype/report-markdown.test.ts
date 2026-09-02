import { describe, expect, it } from "vitest";
import { createRunReport, renderMarkdownReport } from "./report.ts";
import { confirmedCampaignRun } from "./report-test-fixture.ts";

describe("Markdown campaign report", () => {
  it("renders an evidence-first handoff with reproducible requests", () => {
    const markdown = renderMarkdownReport(createRunReport(confirmedCampaignRun()));
    expect(markdown).toContain("# Quiver security campaign report");
    expect(markdown).toContain("| Confirmed | 1 |");
    expect(markdown).toContain("## Model routing by mission");
    expect(markdown).toContain("| explorer-1 | explorer | cheap |");
    expect(markdown).toContain("## Confirmed findings");
    expect(markdown).toContain("### Cross-owner vehicle location");
    expect(markdown).toContain("Fresh replay supports the claim.");
    expect(markdown).toContain("Severity: **high**");
    expect(markdown).toContain("Raw replay evidence:");
    expect(markdown).toContain('"owner@example.com"');
    expect(markdown).toContain("## Authentication for reproduction");
    expect(markdown).toContain("export QUIVER_TARGET='http://127.0.0.1:8888'");
    expect(markdown).toContain(`--header 'Authorization: Bearer '"$QUIVER_TOKEN_ORDINARY_USER"`);
    expect(markdown).toContain("--header 'accept: application/json'");
    expect(markdown).toContain(`--header 'x-api-key: '"$QUIVER_HEADER_X_API_KEY"`);
    expect(markdown).toContain('--data-raw "$QUIVER_REQUEST_BODY"');
    expect(markdown).not.toContain("report-secret");
    expect(markdown).not.toContain("body-secret");
  });
});
