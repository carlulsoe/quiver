import { describe, expect, it } from "vitest";
import { evaluateProof } from "./proof.ts";
import type { ProofPolicy } from "./target-profile.ts";
import { evaluateWithPolicy, observation, policyFinding } from "./proof-policy-test-helpers.ts";

describe("target-owned read proof policies", () => {
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
});
