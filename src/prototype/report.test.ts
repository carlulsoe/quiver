import { describe, expect, it } from "vitest";
import { createRunReport, renderMarkdownReport } from "./report.ts";
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
        severity: "high",
        cwe: "CWE-639",
        endpoint: "/vehicles/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
        resource: "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
        rationale: "Cross-owner coordinates returned.",
        impact: "Another user's vehicle can be tracked.",
        mitigation: "Check vehicle ownership before returning location data.",
        reproduction: [{ path: "/vehicles/other/location", authenticated: true }],
        proof: {
          type: "cross-principal-access",
          actor: { requestIndex: 0, jsonPointer: "/viewer" },
          resourceOwner: { requestIndex: 0, jsonPointer: "/owner" },
          accessRequestIndex: 0,
          evidencePointers: ["/location"],
        },
      },
    });
    state = reduceCampaign(state, { type: "phase", phase: "validating" });
    state = reduceCampaign(state, {
      type: "validation",
      validation: {
        fingerprint: state.findings[0]!.fingerprint,
        status: "confirmed",
        evidence: "Deterministic cross-principal-access predicate passed 4/4 checks.",
        proof: {
          predicate: "cross-principal-access",
          passed: true,
          summary: "Deterministic cross-principal-access predicate passed 4/4 checks.",
          checks: [],
        },
        observations: [],
        reviewer: {
          assessment: "supported",
          evidence: "Fresh replay returned another owner's coordinates.",
        },
      },
    });
    state = reduceCampaign(state, { type: "phase", phase: "complete" });
    const run: CampaignRun = {
      profileId: "crapi",
      model: "openrouter/z-ai/glm-5.3-flash",
      durationMs: 1234,
      usage: {
        input: 10,
        output: 5,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 15,
        cost: { input: 0.01, output: 0.02, cacheRead: 0, cacheWrite: 0, total: 0.03 },
      },
      state,
      events: [],
    };

    const report = createRunReport(run, new Date("2026-08-31T00:00:00.000Z"));

    expect(report).toMatchObject({
      schemaVersion: 7,
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

  it("renders an evidence-first Markdown handoff with reproducible requests", () => {
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
        severity: "high",
        cwe: "CWE-639",
        endpoint: "/vehicles/{id}/location",
        resource: "vehicle-2",
        rationale: "An ordinary user received another owner's location.",
        impact: "Another user's vehicle can be tracked.",
        mitigation: "Check vehicle ownership before returning location data.",
        reproduction: [
          { path: "/vehicles/mine", authenticated: true },
          {
            path: "/vehicles/vehicle-2/location?token=url-secret&view=full",
            authenticated: true,
            headers: {
              accept: "application/json",
              authorization: "Bearer report-secret",
              "x-api-key": "report-secret",
              "`id`-auth": "report-secret",
            },
            body: JSON.stringify({
              vehicle: "vehicle-2",
              newPassword: "body-secret",
              "access-token": "body-token",
              private_key: "body-key",
            }),
          },
        ],
        proof: {
          type: "cross-principal-access",
          actor: { requestIndex: 0, jsonPointer: "/email" },
          resourceOwner: { requestIndex: 1, jsonPointer: "/email" },
          accessRequestIndex: 1,
          evidencePointers: ["/latitude"],
        },
      },
    });
    state = reduceCampaign(state, { type: "phase", phase: "validating" });
    state = reduceCampaign(state, {
      type: "validation",
      validation: {
        fingerprint: state.findings[0]!.fingerprint,
        status: "confirmed",
        evidence: "Deterministic cross-principal-access predicate passed 4/4 checks.",
        proof: {
          predicate: "cross-principal-access",
          passed: true,
          summary: "Deterministic cross-principal-access predicate passed 4/4 checks.",
          checks: [
            {
              description: "actor and resource owner are different principals",
              passed: true,
              actual: "me@example.com != owner@example.com",
            },
          ],
        },
        observations: [
          {
            status: 200,
            path: "/vehicles/mine",
            authenticated: true,
            body: { email: "me@example.com" },
            truncated: false,
          },
          {
            status: 200,
            path: "/vehicles/vehicle-2/location",
            authenticated: true,
            body: { email: "owner@example.com", latitude: "12.34" },
            truncated: false,
          },
        ],
        reviewer: {
          assessment: "supported",
          evidence: "Fresh replay returned another owner's coordinates.",
        },
      },
    });
    state = reduceCampaign(state, { type: "phase", phase: "complete" });
    const report = createRunReport({
      profileId: "crapi",
      reproductionAuthentication: {
        description: "Log in as an ordinary test user.",
        commands: ["export QUIVER_TOKEN='example-token'"],
      },
      model: "openrouter/z-ai/glm-5.3-flash",
      durationMs: 1234,
      usage: {
        input: 10,
        output: 5,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 15,
        cost: { input: 0.01, output: 0.02, cacheRead: 0, cacheWrite: 0, total: 0.03 },
      },
      state,
      events: [
        {
          sequence: 1,
          elapsedMs: 10,
          type: "tool-call",
          data: {
            input: {
              headers: { "content-type": "application/json", authorization: "secret" },
              body: "query=vehicle-2&access_token=event-secret",
            },
          },
        },
      ],
    });

    const markdown = renderMarkdownReport(report);

    expect(markdown).toContain("# Quiver security campaign report");
    expect(markdown).toContain("| Confirmed | 1 |");
    expect(markdown).toContain("## Confirmed findings");
    expect(markdown).toContain("### Cross-owner vehicle location");
    expect(markdown).toContain("Fresh replay returned another owner's coordinates.");
    expect(markdown).toContain("Severity: **high**");
    expect(markdown).toContain("CWE-639");
    expect(markdown).toContain("Raw replay evidence:");
    expect(markdown).toContain('"owner@example.com"');
    expect(markdown).toContain("## Authentication for reproduction");
    expect(markdown).toContain("export QUIVER_TARGET='http://127.0.0.1:8888'");
    expect(markdown).toContain("export QUIVER_TOKEN='example-token'");
    expect(markdown).toContain("--header 'Authorization: Bearer $QUIVER_TOKEN'");
    expect(markdown).toContain("--header 'accept: application/json'");
    expect(markdown).toContain(`--header 'x-api-key: '"$QUIVER_HEADER_X_API_KEY"`);
    expect(markdown).toContain(`--header '\`id\`-auth: '"$QUIVER_HEADER_ID_AUTH"`);
    expect(markdown).toContain('--data-raw "$QUIVER_REQUEST_BODY"');
    const customHeaderCommand = markdown
      .split("\n")
      .find((line) => line.startsWith("curl ") && line.includes("/vehicles/vehicle-2/location"))!;
    expect(customHeaderCommand.match(/Authorization: Bearer \$QUIVER_TOKEN/g)).toHaveLength(1);
    expect(markdown).not.toContain("authorization: [REDACTED]");
    expect(JSON.stringify(report)).not.toContain("report-secret");
    expect(JSON.stringify(report)).not.toContain("body-secret");
    expect(JSON.stringify(report)).not.toContain("body-token");
    expect(JSON.stringify(report)).not.toContain("body-key");
    expect(JSON.stringify(report)).not.toContain("event-secret");
    expect(JSON.stringify(report)).not.toContain("url-secret");
    expect(JSON.stringify(report)).not.toContain("query=vehicle-2");
    expect(JSON.stringify(report)).not.toContain('authorization":"secret');
  });
});
