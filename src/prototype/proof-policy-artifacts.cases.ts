import { describe, expect, it } from "vitest";
import type { ProofPolicy } from "./target-profile.ts";
import { evaluateWithPolicy, observation, policyFinding } from "./proof-policy-test-helpers.ts";

describe("target-owned artifact proof policies", () => {
  it("requires fresh policy-matched browser and OAST execution artifacts", () => {
    const marker = "QUIVER-BROWSER-123";
    const payloadTemplate = '<script>alert("{{challenge}}")</script>';
    const payload = payloadTemplate.replace("{{challenge}}", marker);
    const browserFinding = policyFinding(
      "cross-site-scripting",
      "/comments",
      "POST",
      [
        {
          path: "/comments",
          method: "POST",
          body: JSON.stringify({ payload }),
          actorId: "ordinary-user",
        },
      ],
      {
        type: "browser-visible-effect",
        policyId: "comment-dialog",
        probeId: "browser-1",
        marker,
        requestIndex: 0,
        pagePath: "/comments/latest",
        kind: "dialog",
        challenge: { location: "json-body", parameter: "payload", template: payloadTemplate },
        pageActorId: "ordinary-user",
        collectorRequestBudget: 3,
      },
    );
    const browserPolicy: ProofPolicy = {
      id: "comment-dialog",
      kind: "browser-effect",
      category: "cross-site-scripting",
      workflow: "stored",
      endpoint: "/comments",
      method: "POST",
      description: "Synthetic comments must never execute a dialog marker.",
      effect: "dialog",
      markerPattern: "^QUIVER-BROWSER-[A-Z0-9-]+$",
      pagePath: "/comments/latest",
      payloadTemplate,
      challenge: { location: "json-body", parameter: "payload", template: payloadTemplate },
      submissionActorId: "ordinary-user",
      pageActorId: "ordinary-user",
      requestBudget: 3,
    };
    expect(
      evaluateWithPolicy(
        browserFinding,
        [observation("/comments", { ok: true }, "POST")],
        browserPolicy,
        {
          artifacts: {
            browserEffects: [
              { probeId: "browser-1", path: "/comments/latest", kind: "dialog", value: marker },
            ],
            browserStateTransitions: [],
            oastCallbacks: [],
          },
        },
      ).passed,
    ).toBe(true);
    expect(
      evaluateWithPolicy(
        {
          ...browserFinding,
          reproduction: [
            {
              ...browserFinding.reproduction[0]!,
              body: JSON.stringify({ payload: marker }),
            },
          ],
          proof: {
            type: "browser-visible-effect",
            policyId: "comment-dialog",
            probeId: "browser-1",
            marker,
            requestIndex: 0,
            pagePath: "/comments/latest",
            kind: "dialog",
            challenge: { location: "json-body", parameter: "payload", template: "{{challenge}}" },
            pageActorId: "ordinary-user",
            collectorRequestBudget: 3,
          },
        },
        [observation("/comments", { ok: true }, "POST")],
        browserPolicy,
        {
          artifacts: {
            browserEffects: [
              { probeId: "browser-1", path: "/comments/latest", kind: "dialog", value: marker },
            ],
            browserStateTransitions: [],
            oastCallbacks: [],
          },
        },
      ).passed,
    ).toBe(false);

    const token = "token-123";
    const callbackUrl = `http://oast/${token}`;
    const oastFinding = policyFinding(
      "server-side-request-forgery",
      "/preview",
      "POST",
      [
        {
          path: "/preview",
          method: "POST",
          body: JSON.stringify({ url: callbackUrl }),
          actorId: "ordinary-user",
        },
      ],
      {
        type: "oast-callback",
        policyId: "preview-fetch",
        probeId: "oast-1",
        token,
        requestIndex: 0,
        callbackUrl,
        challenge: { location: "json-body", parameter: "url", template: "{{challenge}}" },
      },
    );
    const oastPolicy: ProofPolicy = {
      id: "preview-fetch",
      kind: "oast",
      category: "server-side-request-forgery",
      description: "Preview must not fetch user-provided callback URLs.",
      protocol: "http",
      endpoint: "/preview",
      method: "POST",
      challenge: { location: "json-body", parameter: "url", template: "{{challenge}}" },
    };
    expect(
      evaluateWithPolicy(
        oastFinding,
        [observation("/preview", { queued: true }, "POST")],
        oastPolicy,
        {
          artifacts: {
            browserEffects: [],
            browserStateTransitions: [],
            oastCallbacks: [
              {
                probeId: "oast-1",
                token,
                protocol: "http",
                method: "GET",
                path: `/callback/oast-1/${token}`,
                observedAt: "2026-08-31T00:00:00.000Z",
              },
            ],
          },
        },
      ).passed,
    ).toBe(true);
    expect(
      evaluateWithPolicy(oastFinding, [observation("/preview", {}, "POST")], oastPolicy).passed,
    ).toBe(false);
  });
});
