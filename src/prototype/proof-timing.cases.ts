import { describe, expect, it } from "vitest";
import { evaluateProof } from "./proof.ts";
import { finding, observation } from "./proof-test-helpers.ts";

describe("deterministic timing proof", () => {
  it("requires repeated median timing evidence for time-based injection", () => {
    const timing = finding({
      category: "sql-injection",
      endpoint: "/search",
      reproduction: Array.from({ length: 3 }, (_, index) => [
        {
          path: "/search?q=control",
          actorId: "anonymous",
          sampleId: `control-${index + 1}`,
        },
        {
          path: "/search?q=%27%3BSELECT+pg_sleep%281%29--",
          actorId: "anonymous",
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
      observation(request.path, { ok: true }, { actorId: "anonymous", durationMs: timings[index] }),
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
      reproduction: [{ path: "/health", actorId: "anonymous" }],
      proof: {
        type: "unauthenticated-success",
        requestIndex: 0,
        evidencePointers: ["/ok"],
      },
    });

    expect(
      evaluateProof(publicEndpoint, [
        observation("/health", { ok: true }, { actorId: "anonymous" }),
      ]).passed,
    ).toBe(false);
    expect(
      evaluateProof({ ...publicEndpoint, category: "other" }, [
        observation("/health", { ok: true }, { actorId: "anonymous" }),
      ]).passed,
    ).toBe(false);
  });
});
