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
    actorId:
      path.startsWith("/settings") || path.startsWith("/comments") || path.startsWith("/preview")
        ? "ordinary-user"
        : "anonymous",
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
  it("confirms only an unfollowed redirect to the exact policy destination", () => {
    const destination = "https://redirect-proof.invalid/landing?campaign=quiver";
    const finding = policyFinding(
      "open-redirect",
      "/leave",
      "GET",
      [{ path: `/leave?next=${encodeURIComponent(destination)}`, actorId: "anonymous" }],
      {
        type: "redirect-destination",
        policyId: "external-leave",
        requestIndex: 0,
        destination,
      },
    );
    const policy: ProofPolicy = {
      id: "external-leave",
      kind: "redirect",
      category: "open-redirect",
      description: "The redirector must not accept an external destination.",
      endpoint: "/leave",
      method: "GET",
      challenge: { location: "query", parameter: "next", template: "{{challenge}}" },
      destination,
    };
    const redirect = {
      ...observation(finding.reproduction[0]!.path, "redirecting"),
      status: 302,
      redirectLocation: destination,
      redirected: false,
    };

    expect(evaluateWithPolicy(finding, [redirect], policy).passed).toBe(true);
    expect(
      evaluateWithPolicy(
        finding,
        [{ ...redirect, redirectLocation: "https://redirect-proof.invalid/other" }],
        policy,
      ).passed,
    ).toBe(false);
    expect(evaluateWithPolicy(finding, [{ ...redirect, redirected: true }], policy).passed).toBe(
      false,
    );
  });

  it("confirms traversal from a verifier-only raw file body, not a JSON canary", () => {
    const traversal = "../../fixtures/quiver-proof.txt";
    const content = "Quiver immutable traversal fixture\nline two\n";
    const finding = policyFinding(
      "path-traversal",
      "/download",
      "GET",
      [{ path: `/download?file=${encodeURIComponent(traversal)}`, actorId: "anonymous" }],
      { type: "file-content-retrieval", policyId: "fixture-file", requestIndex: 0 },
    );
    const policy: ProofPolicy = {
      id: "fixture-file",
      kind: "file-content",
      category: "path-traversal",
      description: "A synthetic immutable text file outside the public root.",
      endpoint: "/download",
      method: "GET",
      request: { location: "query", parameter: "file", value: traversal },
      source: "immutable-fixture",
      contentTypePattern: "^text/plain(?:;|$)",
      verify: (value) => value === content,
    };
    const raw = {
      ...observation(finding.reproduction[0]!.path, content),
      contentType: "text/plain",
    };

    expect(evaluateWithPolicy(finding, [raw], policy).passed).toBe(true);
    expect(
      evaluateWithPolicy(
        finding,
        [{ ...raw, body: { content }, contentType: "application/json" }],
        policy,
      ).passed,
    ).toBe(false);
    expect(
      evaluateWithPolicy(
        { ...finding, reproduction: [{ path: "/download?file=public.txt", actorId: "anonymous" }] },
        [raw],
        policy,
      ).passed,
    ).toBe(false);
  });

  it("confirms retrieval only when the selected value matches a declared canary", () => {
    const finding = policyFinding(
      "sensitive-data-exposure",
      "/files/report",
      "GET",
      [{ path: "/files/report", actorId: "anonymous" }],
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
          actorId: "anonymous",
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
        { path: "/settings", actorId: "ordinary-user" },
        {
          path: "/settings/email",
          method: "POST",
          body: '{"public":true}',
          actorId: "ordinary-user",
        },
        { path: "/settings", actorId: "ordinary-user" },
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
            { path: "/settings?account=a", actorId: "ordinary-user" },
            finding.reproduction[1]!,
            { path: "/settings?account=b", actorId: "ordinary-user" },
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
            { path: "/settings/other", method: "POST", actorId: "ordinary-user" },
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
