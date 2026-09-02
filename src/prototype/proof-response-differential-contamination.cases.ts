import { describe, expect, it } from "vitest";
import { evaluateProof } from "./proof.ts";
import { observation, sqlDifferentialFinding } from "./proof-test-helpers.ts";

describe("deterministic response differential contamination", () => {
  it("rejects contaminated response-differential evidence", () => {
    const differential = sqlDifferentialFinding();
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
            { path: "/search/reset", method: "POST", actorId: "anonymous" },
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
            { path: "/search?q=control&message=SQLSTATE%2042000", actorId: "anonymous" },
            { path: "/search?q=%27&message=SQLSTATE%2042000", actorId: "anonymous" },
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
              actorId: "anonymous",
              body: '{"q":"control"}',
            },
            {
              path: "/search",
              method: "POST",
              actorId: "anonymous",
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
              actorId: "anonymous",
              body: '{"q":"control"}',
            },
            {
              path: "/search",
              method: "POST",
              actorId: "anonymous",
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
});
