import { describe, expect, it } from "vitest";
import { evaluateProof, type ProofEvaluationContext } from "./proof.ts";
import type { Finding, ProofPredicate, ValidationObservation } from "./state.ts";
import type { ProofPolicy } from "./target-profile.ts";

function policyFinding(
  category: Finding["category"],
  endpoint: string,
  method: Finding["method"],
  reproduction: Finding["reproduction"],
  proof: ProofPredicate,
): Finding {
  return {
    fingerprint: `${category}:${method ?? "GET"}:${endpoint}`,
    agentId: "explorer-1",
    title: "Policy-backed proof",
    category,
    severity: "high",
    cwe: "CWE-1",
    endpoint,
    method,
    resource: "synthetic",
    rationale: "A target-owned proof contract was satisfied.",
    impact: "Synthetic impact.",
    mitigation: "Enforce the declared contract.",
    reproduction,
    proof,
  };
}

function observation(path: string, body: unknown, method = "GET"): ValidationObservation {
  return {
    path,
    method: method as "GET",
    status: 200,
    authenticated: false,
    body,
    truncated: false,
  };
}

function evaluateWithPolicy(
  finding: Finding,
  observations: ValidationObservation[],
  policy: ProofPolicy,
  context: Omit<ProofEvaluationContext, "policies"> = {},
) {
  return evaluateProof(finding, observations, { ...context, policies: [policy] });
}

describe("target-owned proof policies", () => {
  it("confirms retrieval only when the selected value matches a declared canary", () => {
    const finding = policyFinding(
      "sensitive-data-exposure",
      "/files/report",
      "GET",
      [{ path: "/files/report", authenticated: false }],
      {
        type: "canary-retrieval",
        policyId: "report-canary",
        requestIndex: 0,
        jsonPointer: "/content",
      },
    );
    const policy: ProofPolicy = {
      id: "report-canary",
      kind: "canary",
      category: "sensitive-data-exposure",
      description: "Synthetic file marker",
      endpoint: "/files/report",
      method: "GET",
      verify: (value) => value === "QUIVER-CANARY-A1",
      source: "immutable-fixture",
      jsonPointer: "/content",
    };

    expect(
      evaluateWithPolicy(
        finding,
        [observation("/files/report", { content: "QUIVER-CANARY-A1" })],
        policy,
      ).passed,
    ).toBe(true);
    expect(
      evaluateProof(finding, [observation("/files/report", { content: "public" })]).passed,
    ).toBe(false);
    const reflected = policyFinding(
      "sensitive-data-exposure",
      "/echo",
      "POST",
      [
        {
          path: "/echo",
          method: "POST",
          authenticated: false,
          body: '{"value":"QUIVER-\\u0043ANARY-A1"}',
        },
      ],
      {
        type: "canary-retrieval",
        policyId: "report-canary",
        requestIndex: 0,
        jsonPointer: "/content",
      },
    );
    expect(
      evaluateWithPolicy(
        reflected,
        [observation("/echo", { content: "QUIVER-CANARY-A1" }, "POST")],
        { ...policy, endpoint: "/echo", method: "POST" },
      ).passed,
    ).toBe(false);
  });

  it("confirms an exact protected state transition declared by the profile", () => {
    const finding = policyFinding(
      "business-logic",
      "/settings/email",
      "POST",
      [
        { path: "/settings", authenticated: true },
        { path: "/settings/email", method: "POST", body: '{"public":true}', authenticated: true },
        { path: "/settings", authenticated: true },
      ],
      {
        type: "state-transition",
        policyId: "email-public",
        transitionRequestIndex: 1,
        beforeRequestIndex: 0,
        afterRequestIndex: 2,
      },
    );
    const policy: ProofPolicy = {
      id: "email-public",
      kind: "state-transition",
      category: "business-logic",
      description: "Email visibility must not change through this operation.",
      endpoint: "/settings/email",
      method: "POST",
      jsonPointer: "/emailPublic",
      before: false,
      after: true,
      readEndpoint: "/settings",
      readMethod: "GET",
    };

    expect(
      evaluateWithPolicy(
        finding,
        [
          observation("/settings", { emailPublic: false }),
          observation("/settings/email", { ok: true }, "POST"),
          observation("/settings", { emailPublic: true }),
        ],
        policy,
        { stateResetAvailable: true },
      ).passed,
    ).toBe(true);
    expect(
      evaluateWithPolicy(
        finding,
        [
          { ...observation("/settings", { emailPublic: false }), status: 500 },
          observation("/settings/email", { ok: true }, "POST"),
          observation("/settings", { emailPublic: true }),
        ],
        policy,
        { stateResetAvailable: true },
      ).passed,
    ).toBe(false);
    expect(
      evaluateWithPolicy(
        {
          ...finding,
          proof: {
            type: "state-transition",
            policyId: "email-public",
            beforeRequestIndex: 2,
            transitionRequestIndex: 1,
            afterRequestIndex: 0,
          },
        },
        [
          observation("/settings", { emailPublic: false }),
          observation("/settings/email", { ok: true }, "POST"),
          observation("/settings", { emailPublic: true }),
        ],
        policy,
        { stateResetAvailable: true },
      ).passed,
    ).toBe(false);
    expect(
      evaluateWithPolicy(
        {
          ...finding,
          reproduction: [
            { path: "/settings?account=a", authenticated: true },
            finding.reproduction[1]!,
            { path: "/settings?account=b", authenticated: true },
          ],
        },
        [
          observation("/settings?account=a", { emailPublic: false }),
          observation("/settings/email", { ok: true }, "POST"),
          observation("/settings?account=b", { emailPublic: true }),
        ],
        policy,
        { stateResetAvailable: true },
      ).passed,
    ).toBe(false);
    expect(
      evaluateWithPolicy(
        {
          ...finding,
          reproduction: [
            finding.reproduction[0]!,
            { path: "/settings/other", method: "POST", authenticated: true },
            finding.reproduction[1]!,
            finding.reproduction[2]!,
          ],
          proof: {
            type: "state-transition",
            policyId: "email-public",
            beforeRequestIndex: 0,
            transitionRequestIndex: 2,
            afterRequestIndex: 3,
          },
        },
        [
          observation("/settings", { emailPublic: false }),
          observation("/settings/other", { changed: true }, "POST"),
          observation("/settings/email", { ok: true }, "POST"),
          observation("/settings", { emailPublic: true }),
        ],
        policy,
        { stateResetAvailable: true },
      ).passed,
    ).toBe(false);
  });

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
          authenticated: true,
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
        pageAuthenticated: true,
        collectorRequestBudget: 3,
      },
    );
    const browserPolicy: ProofPolicy = {
      id: "comment-dialog",
      kind: "browser-effect",
      category: "cross-site-scripting",
      description: "Synthetic comments must never execute a dialog marker.",
      effect: "dialog",
      markerPattern: "^QUIVER-BROWSER-[A-Z0-9-]+$",
      pagePath: "/comments/latest",
      payloadTemplate,
      pageAuthenticated: true,
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
            pageAuthenticated: true,
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
          authenticated: true,
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
    };
    expect(
      evaluateWithPolicy(
        oastFinding,
        [observation("/preview", { queued: true }, "POST")],
        oastPolicy,
        {
          artifacts: {
            browserEffects: [],
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
