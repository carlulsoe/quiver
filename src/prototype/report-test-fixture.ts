import type { CampaignRun } from "./runner.ts";
import { createCampaignState, reduceCampaign } from "./state.ts";

export const reportCredentialSentinel = "derived-report-credential-sentinel";

export function confirmedCampaignRun(): CampaignRun {
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
        { path: "/vehicles/mine", actorId: "ordinary-user" },
        {
          path: "/vehicles/vehicle-2/location?token=url-secret",
          actorId: "ordinary-user",
          headers: {
            accept: "application/json",
            authorization: "Bearer report-secret",
            "x-api-key": "report-secret",
          },
          body: JSON.stringify({ newPassword: "body-secret" }),
        },
        { path: "/vehicles/second/location", actorId: "second-user" },
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
      evidence: `Predicate passed without exposing ${reportCredentialSentinel}.`,
      proof: {
        predicate: "cross-principal-access",
        passed: true,
        summary: "passed",
        checks: [
          { description: "selected credential", passed: true, actual: reportCredentialSentinel },
          {
            description: "credential differential",
            passed: true,
            actual: `${reportCredentialSentinel} == ${reportCredentialSentinel}`,
          },
          { description: "different principals", passed: true, actual: "me != owner" },
        ],
      },
      observations: [
        {
          status: 200,
          path: "/vehicles/vehicle-2/location",
          actorId: "ordinary-user",
          body: {
            email: "owner@example.com",
            apiToken: reportCredentialSentinel,
            buildId: "build-7",
            pin: 200,
            otp: 1,
            token: false,
            counter: 200,
            diagnosticCount: 1,
            enabled: false,
          },
          truncated: false,
          redirectLocation: `https://redirect.invalid/landing?access_token=${reportCredentialSentinel}`,
          redirected: false,
        },
      ],
      reviewer: {
        assessment: "supported",
        evidence: `Fresh replay supports the claim. Credential ${reportCredentialSentinel}, PIN 200, OTP 1, and token false were present.`,
      },
    },
  });
  state = reduceCampaign(state, { type: "phase", phase: "complete" });
  const usage = {
    input: 10,
    output: 5,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens: 15,
    cost: { input: 0.01, output: 0.02, cacheRead: 0, cacheWrite: 0, total: 0.03 },
  };
  return {
    profileId: "crapi",
    reproductionAuthentication: {
      description: "Log in as an ordinary test user.",
      commands: ["export QUIVER_TOKEN='example-token'"],
      actors: {
        "second-user": {
          description: "Log in as second user.",
          commands: ["export QUIVER_TOKEN='second-token'"],
        },
      },
    },
    model: "openrouter/z-ai/glm-5.3-flash",
    durationMs: 1234,
    usage,
    missionUsage: [
      {
        missionId: "explorer-1",
        role: "explorer",
        requirements: {
          kind: "route-triage",
          capabilities: [],
          costPreference: "cheap",
          estimatedInputTokens: 1_000,
        },
        attemptedModels: ["openrouter/z-ai/glm-5.3-flash"],
        usage,
      },
    ],
    state,
    events: [
      {
        sequence: 1,
        elapsedMs: 10,
        type: "tool-call",
        data: {
          author: "Ada",
          requestsUsed: 200,
          findingCount: 1,
          durationMs: 200,
          input: {
            body: JSON.stringify({ accessToken: "event-secret", pin: 200, otp: 1 }),
          },
        },
      },
    ],
  };
}
