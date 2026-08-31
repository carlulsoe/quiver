import { describe, expect, it } from "vitest";
import { evaluateProof } from "./proof.ts";
import type { Finding, ValidationObservation } from "./state.ts";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    fingerprint: "broken-object-authorization:GET:/orders/{id}",
    agentId: "explorer-1",
    title: "Cross-owner order",
    category: "broken-object-authorization",
    severity: "high",
    cwe: "CWE-639",
    endpoint: "/orders/{id}",
    resource: "order 7",
    rationale: "Another principal's order was returned.",
    impact: "Order data is disclosed.",
    mitigation: "Authorize each lookup.",
    reproduction: [
      { path: "/me", authenticated: true },
      { path: "/orders/7", authenticated: true },
    ],
    proof: {
      type: "cross-principal-access",
      actor: { requestIndex: 0, jsonPointer: "/email" },
      resourceOwner: { requestIndex: 1, jsonPointer: "/order/user/email" },
      accessRequestIndex: 1,
      evidencePointers: ["/order/id"],
    },
    ...overrides,
  };
}

function observation(
  path: string,
  body: unknown,
  overrides: Partial<ValidationObservation> = {},
): ValidationObservation {
  return { status: 200, path, authenticated: true, body, truncated: false, ...overrides };
}

describe("deterministic finding proof", () => {
  it("confirms successful access when actor and resource owner differ", () => {
    const result = evaluateProof(finding(), [
      observation("/me", { email: "actor@example.com" }),
      observation("/orders/7", { order: { id: 7, user: { email: "owner@example.com" } } }),
    ]);

    expect(result.passed).toBe(true);
    expect(result.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          description: "actor and resource owner are different principals",
          passed: true,
        }),
      ]),
    );
  });

  it("rejects same-owner, missing, unsuccessful, or truncated BOLA evidence", () => {
    const result = evaluateProof(finding(), [
      observation("/me", { email: "same@example.com" }),
      observation(
        "/orders/7",
        { order: { id: 7, user: { email: "same@example.com" } } },
        { status: 403, truncated: true },
      ),
    ]);

    expect(result.passed).toBe(false);
    expect(
      result.checks.filter(({ passed }) => !passed).map(({ description }) => description),
    ).toEqual(
      expect.arrayContaining([
        "proof responses were not truncated",
        "actor and resource owner are different principals",
        "cross-principal request returned a successful response",
      ]),
    );
  });

  it("confirms anonymous success only for an actually anonymous request with declared fields", () => {
    const anonymousFinding = finding({
      category: "security-misconfiguration",
      reproduction: [{ path: "/orders/7", authenticated: false }],
      proof: {
        type: "unauthenticated-success",
        requestIndex: 0,
        evidencePointers: ["/order/id", "/payment/card_number"],
      },
    });

    expect(
      evaluateProof(anonymousFinding, [
        observation(
          "/orders/7",
          { order: { id: 7 }, payment: { card_number: "XXXX1234" } },
          { authenticated: false },
        ),
      ]).passed,
    ).toBe(true);
    expect(
      evaluateProof(anonymousFinding, [
        observation("/orders/7", { order: { id: 7 } }, { authenticated: false }),
      ]).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...anonymousFinding,
          reproduction: [
            { path: "/orders/7", authenticated: false, headers: { "x-api-key": "secret" } },
          ],
        },
        [
          observation(
            "/orders/7",
            { order: { id: 7 }, payment: { card_number: "XXXX1234" } },
            { authenticated: false },
          ),
        ],
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...anonymousFinding,
          method: "POST",
          reproduction: [
            {
              path: "/orders/7",
              method: "POST",
              authenticated: false,
              headers: { "content-type": "application/json" },
              body: '{"apiKey":"secret"}',
            },
          ],
        },
        [
          observation(
            "/orders/7",
            { order: { id: 7 }, payment: { card_number: "XXXX1234" } },
            { authenticated: false },
          ),
        ],
      ).passed,
    ).toBe(false);
  });

  it("requires a different subject for cross-principal data exposure", () => {
    const exposed = finding({
      category: "excessive-data-exposure",
      endpoint: "/feed",
      reproduction: [
        { path: "/me", authenticated: true },
        { path: "/feed", authenticated: true },
      ],
      proof: {
        type: "cross-principal-data-exposure",
        actor: { requestIndex: 0, jsonPointer: "/email" },
        exposedSubject: { requestIndex: 1, jsonPointer: "/authors/0/email" },
        responseRequestIndex: 1,
        evidencePointers: ["/authors/0/email", "/authors/0/vehicleId"],
      },
    });

    expect(
      evaluateProof(exposed, [
        observation("/me", { email: "actor@example.com" }),
        observation("/feed", {
          authors: [{ email: "other@example.com", vehicleId: "foreign-vehicle" }],
        }),
      ]).passed,
    ).toBe(true);
    expect(
      evaluateProof(exposed, [
        observation("/me", { email: "actor@example.com" }),
        observation("/feed", {
          authors: [{ email: "actor@example.com", vehicleId: "owned-vehicle" }],
        }),
      ]).passed,
    ).toBe(false);
  });

  it("rejects an affected operation that was not reproduced", () => {
    const result = evaluateProof(finding({ endpoint: "/orders/{id}/audit" }), [
      observation("/me", { email: "actor@example.com" }),
      observation("/orders/7", { order: { id: 7, user: { email: "owner@example.com" } } }),
    ]);

    expect(result.passed).toBe(false);
    expect(result.checks).toContainEqual({
      description: "affected operation matches a reproduction request",
      passed: false,
    });
  });

  it("rejects a proof predicate that is incompatible with the finding category", () => {
    const result = evaluateProof(
      finding({
        category: "excessive-data-exposure",
        proof: {
          type: "cross-principal-access",
          actor: { requestIndex: 0, jsonPointer: "/email" },
          resourceOwner: { requestIndex: 1, jsonPointer: "/order/user/email" },
          accessRequestIndex: 1,
          evidencePointers: ["/order/id"],
        },
      }),
      [
        observation("/me", { email: "actor@example.com" }),
        observation("/orders/7", { order: { id: 7, user: { email: "owner@example.com" } } }),
      ],
    );

    expect(result.passed).toBe(false);
    expect(result.checks[0]).toMatchObject({ passed: false });
  });

  it("uses a response differential for injection-specific validation", () => {
    const differential = finding({
      category: "sql-injection",
      endpoint: "/search",
      reproduction: [
        { path: "/search?q=control", authenticated: false },
        { path: "/search?q=%27", authenticated: false },
      ],
      proof: {
        type: "response-differential",
        controlRequestIndex: 0,
        probeRequestIndex: 1,
        comparison: "json-value",
        expectation: "different",
        jsonPointer: "/error/code",
        mutation: {
          location: "query",
          parameter: "q",
          controlValue: "control",
          probeValue: "'",
        },
      },
    });

    expect(
      evaluateProof(differential, [
        observation("/search?q=control", { error: { code: "none" } }, { authenticated: false }),
        observation(
          "/search?q=%27",
          { error: { code: "You have an error in your SQL syntax" } },
          { authenticated: false },
        ),
      ]).passed,
    ).toBe(false);
    expect(
      evaluateProof(differential, [
        observation("/search?q=control", { error: { code: "none" } }, { authenticated: false }),
        observation("/search?q=%27", { error: {} }, { authenticated: false }),
      ]).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...differential,
          reproduction: [
            { path: "/search?q=control&mode=fast", authenticated: false },
            { path: "/search?q=%27&mode=slow", authenticated: false },
          ],
        },
        [
          observation("/search?q=control&mode=fast", { error: { code: "none" } }),
          observation("/search?q=%27&mode=slow", {
            error: { code: "You have an error in your SQL syntax" },
          }),
        ],
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...differential,
          proof: {
            type: "response-differential",
            controlRequestIndex: 0,
            probeRequestIndex: 1,
            comparison: "body",
            expectation: "different",
            mutation: {
              location: "query",
              parameter: "q",
              controlValue: "control",
              probeValue: "' SQLSTATE 42000",
            },
          },
          reproduction: [
            { path: "/search?q=control", authenticated: false },
            { path: "/search?q=%27+SQLSTATE+42000", authenticated: false },
          ],
        },
        [
          observation("/search?q=control", { value: "control" }),
          observation("/search?q=%27+SQLSTATE+42000", { value: "' SQLSTATE 42000" }),
        ],
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...differential,
          category: "authentication-bypass",
          proof: {
            type: "response-differential",
            controlRequestIndex: 0,
            probeRequestIndex: 1,
            comparison: "body",
            expectation: "equal",
            mutation: {
              location: "query",
              parameter: "q",
              controlValue: "control",
              probeValue: "control",
            },
          },
        },
        [
          observation("/search?q=control", { error: "unauthorized" }, { status: 401 }),
          observation("/search?q=control", { error: "unauthorized" }, { status: 401 }),
        ],
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...differential,
          endpoint: "/victim",
          reproduction: [...differential.reproduction, { path: "/victim", authenticated: false }],
        },
        [
          observation("/search?q=control", { error: { code: "none" } }),
          observation("/search?q=%27", {
            error: { code: "You have an error in your SQL syntax" },
          }),
          observation("/victim", { ok: true }),
        ],
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...differential,
          proof: {
            type: "response-differential",
            controlRequestIndex: 0,
            probeRequestIndex: 2,
            comparison: "json-value",
            expectation: "different",
            jsonPointer: "/error/code",
            mutation: {
              location: "query",
              parameter: "q",
              controlValue: "control",
              probeValue: "'",
            },
          },
          reproduction: [
            differential.reproduction[0]!,
            { path: "/search/reset", method: "POST", authenticated: false },
            differential.reproduction[1]!,
          ],
        },
        [
          observation("/search?q=control", { error: { code: "none" } }),
          observation("/search/reset", { reset: true }),
          observation("/search?q=%27", {
            error: { code: "You have an error in your SQL syntax" },
          }),
        ],
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...differential,
          reproduction: differential.reproduction.map((request) => ({
            ...request,
            headers: { "X-Mode": "a", "x-mode": "b" },
          })),
        },
        [
          observation("/search?q=control", { error: { code: "none" } }),
          observation("/search?q=%27", {
            error: { code: "You have an error in your SQL syntax" },
          }),
        ],
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...differential,
          reproduction: [
            { path: "/search?q=control&message=SQLSTATE%2042000", authenticated: false },
            { path: "/search?q=%27&message=SQLSTATE%2042000", authenticated: false },
          ],
        },
        [
          observation("/search?q=control&message=SQLSTATE%2042000", {
            error: { code: "none" },
          }),
          observation("/search?q=%27&message=SQLSTATE%2042000", {
            error: { code: "SQLSTATE 42000" },
          }),
        ],
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...differential,
          method: "POST",
          reproduction: [
            {
              path: "/search",
              method: "POST",
              authenticated: false,
              body: '{"q":"control"}',
            },
            {
              path: "/search",
              method: "POST",
              authenticated: false,
              body: '{"q":"\' \\u0053QLSTATE 42000"}',
            },
          ],
          proof: {
            type: "response-differential",
            controlRequestIndex: 0,
            probeRequestIndex: 1,
            comparison: "body",
            expectation: "different",
            mutation: {
              location: "json-body",
              parameter: "q",
              controlValue: "control",
              probeValue: "' SQLSTATE 42000",
            },
          },
        },
        [
          observation("/search", { value: "control" }),
          observation("/search", { value: "' SQLSTATE 42000" }),
        ],
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...differential,
          method: "POST",
          reproduction: [
            {
              path: "/search",
              method: "POST",
              authenticated: false,
              body: '{"q":"control"}',
            },
            {
              path: "/search",
              method: "POST",
              authenticated: false,
              body: '{"q":"%53QLSTATE%2042000\'"}',
            },
          ],
          proof: {
            type: "response-differential",
            controlRequestIndex: 0,
            probeRequestIndex: 1,
            comparison: "body",
            expectation: "different",
            mutation: {
              location: "json-body",
              parameter: "q",
              controlValue: "control",
              probeValue: "%53QLSTATE%2042000'",
            },
          },
        },
        [
          observation("/search", { value: "control" }),
          observation("/search", { value: "SQLSTATE 42000'" }),
        ],
      ).passed,
    ).toBe(false);
  });

  it("requires repeated median timing evidence for time-based injection", () => {
    const timing = finding({
      category: "sql-injection",
      endpoint: "/search",
      reproduction: Array.from({ length: 3 }, (_, index) => [
        {
          path: "/search?q=control",
          authenticated: false,
          sampleId: `control-${index + 1}`,
        },
        {
          path: "/search?q=%27%3BSELECT+pg_sleep%281%29--",
          authenticated: false,
          sampleId: `probe-${index + 1}`,
        },
      ]).flat(),
      proof: {
        type: "timing-differential",
        controlRequestIndexes: [0, 2, 4],
        probeRequestIndexes: [1, 3, 5],
        minimumDeltaMs: 500,
        mutation: {
          location: "query",
          parameter: "q",
          controlValue: "control",
          probeValue: "';SELECT pg_sleep(1)--",
        },
      },
    });
    const timings = [95, 760, 110, 720, 100, 740];
    const observations = timing.reproduction.map((request, index) =>
      observation(request.path, { ok: true }, { authenticated: false, durationMs: timings[index] }),
    );

    const supportingTiming = evaluateProof(timing, observations);
    expect(supportingTiming.passed).toBe(false);
    expect(supportingTiming.checks.filter(({ passed }) => !passed)).toEqual([
      expect.objectContaining({ description: expect.stringContaining("compatible with") }),
    ]);
    expect(
      evaluateProof(
        timing,
        observations.map((item) => ({ ...item, durationMs: undefined })),
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...timing,
          reproduction: timing.reproduction.map((request) => ({
            ...request,
            path: "/search?q=ordinary",
          })),
        },
        observations,
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...timing,
          proof: {
            type: "timing-differential",
            controlRequestIndexes: [0, 2, 4],
            probeRequestIndexes: [1, 3, 5],
            minimumDeltaMs: 500,
            mutation: {
              location: "query",
              parameter: "q",
              controlValue: "control",
              probeValue: "';SELECT pg_sleep(0)--",
            },
          },
          reproduction: timing.reproduction.map((request) => ({
            ...request,
            path: request.path.includes("pg_sleep")
              ? "/search?q=%27%3BSELECT+pg_sleep%280%29--"
              : request.path,
          })),
        },
        observations,
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...timing,
          proof: {
            type: "timing-differential",
            controlRequestIndexes: [0, 2, 4],
            probeRequestIndexes: [1, 3, 5],
            minimumDeltaMs: 500,
            mutation: {
              location: "query",
              parameter: "q",
              controlValue: "';SELECT pg_sleep(1)--",
              probeValue: "';SELECT pg_sleep(1)--",
            },
          },
          reproduction: timing.reproduction.map((request) => ({
            ...request,
            path: "/search?q=%27%3BSELECT+pg_sleep%281%29--",
          })),
        },
        observations,
      ).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...timing,
          proof: {
            type: "timing-differential",
            controlRequestIndexes: [0, 2, 4],
            probeRequestIndexes: [3, 5, 1],
            minimumDeltaMs: 500,
            mutation: {
              location: "query",
              parameter: "q",
              controlValue: "control",
              probeValue: "';SELECT pg_sleep(1)--",
            },
          },
        },
        timing.reproduction.map((request, index) =>
          observation(
            request.path,
            { ok: true },
            { durationMs: [900, 800, 0, 1_300, 400, 500][index] },
          ),
        ),
      ).passed,
    ).toBe(false);
  });

  it("does not classify an ordinary anonymous success as authentication bypass", () => {
    const publicEndpoint = finding({
      category: "authentication-bypass",
      endpoint: "/health",
      reproduction: [{ path: "/health", authenticated: false }],
      proof: {
        type: "unauthenticated-success",
        requestIndex: 0,
        evidencePointers: ["/ok"],
      },
    });

    expect(
      evaluateProof(publicEndpoint, [
        observation("/health", { ok: true }, { authenticated: false }),
      ]).passed,
    ).toBe(false);
    expect(
      evaluateProof({ ...publicEndpoint, category: "other" }, [
        observation("/health", { ok: true }, { authenticated: false }),
      ]).passed,
    ).toBe(false);
  });
});
