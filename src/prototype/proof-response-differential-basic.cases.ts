import { describe, expect, it } from "vitest";
import { evaluateProof } from "./proof.ts";
import { observation, sqlDifferentialFinding } from "./proof-test-helpers.ts";

describe("deterministic response differential proof", () => {
  it("uses strict response-differential evidence", () => {
    const differential = sqlDifferentialFinding();
    expect(
      evaluateProof(differential, [
        observation("/search?q=control", { error: { code: "none" } }, { actorId: "anonymous" }),
        observation(
          "/search?q=%27",
          { error: { code: "You have an error in your SQL syntax" } },
          { actorId: "anonymous" },
        ),
      ]).passed,
    ).toBe(false);
    expect(
      evaluateProof(differential, [
        observation("/search?q=control", { error: { code: "none" } }, { actorId: "anonymous" }),
        observation("/search?q=%27", { error: {} }, { actorId: "anonymous" }),
      ]).passed,
    ).toBe(false);
    expect(
      evaluateProof(
        {
          ...differential,
          reproduction: [
            { path: "/search?q=control&mode=fast", actorId: "anonymous" },
            { path: "/search?q=%27&mode=slow", actorId: "anonymous" },
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
            { path: "/search?q=control", actorId: "anonymous" },
            { path: "/search?q=%27+SQLSTATE+42000", actorId: "anonymous" },
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
          reproduction: [...differential.reproduction, { path: "/victim", actorId: "anonymous" }],
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
  });
});
