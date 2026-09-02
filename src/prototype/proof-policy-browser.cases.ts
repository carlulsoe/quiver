import { describe, expect, it } from "vitest";
import type { ProofPolicy } from "./target-profile.ts";
import { evaluateWithPolicy, observation, policyFinding } from "./proof-policy-test-helpers.ts";

describe("target-owned browser proof policies", () => {
  it("confirms a fragment-only DOM workflow without server reflection", () => {
    const marker = "QUIVER-BROWSER-DOM-1";
    const path = `/app#payload=${marker}`;
    const finding = policyFinding(
      "cross-site-scripting",
      "/app",
      "GET",
      [{ path, actorId: "anonymous" }],
      {
        type: "browser-visible-effect",
        policyId: "dom-dialog",
        probeId: "dom-probe",
        marker,
        requestIndex: 0,
        pagePath: path,
        kind: "dialog",
        challenge: { location: "fragment", parameter: "payload", template: "{{challenge}}" },
        pageActorId: "anonymous",
        pageChallenge: {
          location: "fragment",
          parameter: "payload",
          template: "{{challenge}}",
        },
        collectorRequestBudget: 1,
      },
    );
    const policy: ProofPolicy = {
      id: "dom-dialog",
      kind: "browser-effect",
      category: "cross-site-scripting",
      workflow: "dom",
      endpoint: "/app",
      method: "GET",
      description: "The client must not execute a fragment payload.",
      effect: "dialog",
      markerPattern: "^QUIVER-BROWSER-DOM-",
      pagePath: "/app#payload=old",
      payloadTemplate: "{{challenge}}",
      challenge: { location: "fragment", parameter: "payload", template: "{{challenge}}" },
      submissionActorId: "anonymous",
      pageActorId: "anonymous",
      pageChallenge: { location: "fragment", parameter: "payload", template: "{{challenge}}" },
      requestBudget: 1,
    };
    const artifacts = {
      browserEffects: [{ probeId: "dom-probe", path, kind: "dialog" as const, value: marker }],
      browserStateTransitions: [],
      oastCallbacks: [],
    };

    expect(
      evaluateWithPolicy(finding, [observation(path, "static application shell")], policy, {
        artifacts,
      }).passed,
    ).toBe(true);
    expect(
      evaluateWithPolicy(finding, [observation(path, `reflected ${marker}`)], policy, {
        artifacts,
      }).passed,
    ).toBe(false);
  });

  it("confirms CSRF only from a fresh policy-backed browser state transition", () => {
    const finding = policyFinding(
      "cross-site-request-forgery",
      "/account/email",
      "POST",
      [
        { path: "/account", actorId: "ordinary-user", sampleId: "before" },
        { path: "/account", actorId: "ordinary-user", sampleId: "after" },
      ],
      {
        type: "browser-state-transition",
        policyId: "email-csrf",
        beforeRequestIndex: 0,
        afterRequestIndex: 1,
        pageActorId: "ordinary-user",
        collectorRequestBudget: 2,
      },
    );
    const policy: ProofPolicy = {
      id: "email-csrf",
      kind: "browser-state-transition",
      category: "cross-site-request-forgery",
      description: "A cross-origin fixture attempts the protected email transition.",
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
    };
    const observations = [
      { ...observation("/account", { email: "before@example.test" }), actorId: "ordinary-user" },
      { ...observation("/account", { email: "after@example.test" }), actorId: "ordinary-user" },
    ];
    const transition = {
      policyId: policy.id,
      sourceOrigin: policy.sourceOrigin,
      sourcePath: policy.sourcePath,
      targetPath: policy.endpoint,
      method: policy.method,
      status: 302,
    };

    expect(
      evaluateWithPolicy(finding, observations, policy, {
        stateResetAvailable: true,
        artifacts: {
          browserEffects: [],
          browserStateTransitions: [transition],
          oastCallbacks: [],
        },
      }).passed,
    ).toBe(true);
    expect(
      evaluateWithPolicy(finding, observations, policy, {
        stateResetAvailable: true,
        artifacts: { browserEffects: [], browserStateTransitions: [], oastCallbacks: [] },
      }).passed,
    ).toBe(false);
  });
});
