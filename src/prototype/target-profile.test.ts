import { describe, expect, it } from "vitest";
import { assertValidTargetProfile, type TargetProfile } from "./target-profile.ts";

describe("target profile proof policy validation", () => {
  it("rejects state-transition policies that mutate through a read method", () => {
    const profile = {
      id: "invalid",
      displayName: "Invalid profile",
      objective: "Exercise runtime profile validation.",
      proofPolicies: [
        {
          id: "mutating-get",
          kind: "state-transition",
          category: "business-logic",
          description: "Invalid mutating GET policy.",
          endpoint: "/toggle",
          method: "GET",
          jsonPointer: "/enabled",
          before: false,
          after: true,
          readEndpoint: "/state",
          readMethod: "GET",
        },
      ],
    } as unknown as TargetProfile;

    expect(() => assertValidTargetProfile(profile)).toThrow(
      "must use POST/PUT/PATCH with a GET/HEAD state read",
    );
  });

  it("requires reset hooks to declare their exact scoped-request cost", () => {
    expect(() =>
      assertValidTargetProfile({
        id: "missing-reset-budget",
        displayName: "Missing reset budget",
        objective: "Exercise reset budget validation.",
        prepareValidation: async () => undefined,
      }),
    ).toThrow("must declare validationResetRequestBudget");
  });

  it("bounds target-owned browser collector budgets", () => {
    expect(() =>
      assertValidTargetProfile({
        id: "invalid-browser-budget",
        displayName: "Invalid browser budget",
        objective: "Exercise browser budget validation.",
        proofPolicies: [
          {
            id: "dialog",
            kind: "browser-effect",
            category: "cross-site-scripting",
            description: "Synthetic dialog.",
            effect: "dialog",
            markerPattern: "^QUIVER-BROWSER-",
            pagePath: "/preview",
            payloadTemplate: "<script>alert('{{challenge}}')</script>",
            challenge: {
              location: "json-body",
              parameter: "payload",
              template: "<script>alert('{{challenge}}')</script>",
            },
            pageActorId: "anonymous",
            requestBudget: 21,
          },
        ],
      }),
    ).toThrow("requestBudget must be from 1 to 20");
  });

  it("requires reflected browser request and page mutations to be identical", () => {
    expect(() =>
      assertValidTargetProfile({
        id: "inconsistent-reflection",
        displayName: "Inconsistent reflection",
        objective: "Exercise reflected mutation validation.",
        proofPolicies: [
          {
            id: "dialog",
            kind: "browser-effect",
            category: "cross-site-scripting",
            description: "Synthetic reflected dialog.",
            effect: "dialog",
            markerPattern: "^QUIVER-BROWSER-",
            pagePath: "/preview?payload=old#/result",
            payloadTemplate: "{{challenge}}",
            challenge: { location: "json-body", parameter: "payload", template: "{{challenge}}" },
            pageActorId: "anonymous",
            pageChallenge: { location: "query", parameter: "payload", template: "{{challenge}}" },
            requestBudget: 1,
          },
        ],
      }),
    ).toThrow("pageChallenge must replace one declared query parameter");
  });
});
