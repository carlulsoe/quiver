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

  it("requires CSRF proof pages to be configured as visit-only origins", () => {
    const policy = {
      id: "email-csrf",
      kind: "browser-state-transition",
      category: "cross-site-request-forgery",
      description: "Cross-origin email fixture.",
      endpoint: "/account/email",
      method: "POST",
      sourceOrigin: "http://127.0.0.1:9999",
      sourcePath: "/csrf/email",
      pageActorId: "ordinary-user",
      requestBudget: 2,
      readEndpoint: "/account",
      readMethod: "GET",
      jsonPointer: "/email",
      before: "before@example.test",
      after: "after@example.test",
    } as const;
    const base = {
      id: "csrf-profile",
      displayName: "CSRF profile",
      objective: "Exercise browser state proof validation.",
      proofPolicies: [policy],
    };

    expect(() => assertValidTargetProfile(base)).toThrow("configured visit-only origin");
    expect(() =>
      assertValidTargetProfile({
        ...base,
        attackSurfaceOrigins: [{ origin: "http://127.0.0.1:9999", scope: "visit-only" as const }],
      }),
    ).toThrow("fresh-state reset hook");
    expect(() =>
      assertValidTargetProfile({
        ...base,
        attackSurfaceOrigins: [{ origin: "http://127.0.0.1:9999", scope: "visit-only" as const }],
        prepareValidation: async () => undefined,
        validationResetRequestBudget: 0,
      }),
    ).not.toThrow();
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
            workflow: "stored",
            endpoint: "/comments",
            method: "POST",
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
            submissionActorId: "anonymous",
            pageActorId: "anonymous",
            requestBudget: 21,
          },
        ],
      }),
    ).toThrow("requestBudget must be from 1 to 20");
  });

  it("requires DOM browser request and page mutations to be fragment-only and identical", () => {
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
            workflow: "dom",
            endpoint: "/preview",
            method: "GET",
            description: "Synthetic reflected dialog.",
            effect: "dialog",
            markerPattern: "^QUIVER-BROWSER-",
            pagePath: "/preview?payload=old#/result",
            payloadTemplate: "{{challenge}}",
            challenge: { location: "fragment", parameter: "payload", template: "{{challenge}}" },
            submissionActorId: "anonymous",
            pageActorId: "anonymous",
            pageChallenge: { location: "query", parameter: "payload", template: "{{challenge}}" },
            requestBudget: 1,
          },
        ],
      }),
    ).toThrow("fragment-only DOM workflow");
  });
});
