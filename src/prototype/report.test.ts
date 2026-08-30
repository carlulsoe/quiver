import { describe, expect, it } from "vitest";
import { createRunReport } from "./report.ts";
import type { PrototypeRun } from "./runner.ts";
import { createState, reduce } from "./state.ts";

describe("run report", () => {
  it("summarizes the security verdict and preserves the ordered trace", () => {
    const validating = reduce(createState("http://127.0.0.1:8888", 30), {
      type: "phase",
      phase: "validating",
    });
    const validated = reduce(validating, {
      type: "validated",
      validation: {
        status: "confirmed",
        vehicleId: "vehicle-2",
        evidence: "cross-owner coordinates returned",
      },
    });
    const state = reduce(validated, { type: "phase", phase: "complete" });
    const run = {
      scenario: "discover",
      model: "openrouter/z-ai/glm-5.3-flash",
      durationMs: 1234,
      state,
      events: [
        {
          sequence: 1,
          elapsedMs: 10,
          type: "request",
          data: { method: "GET", path: "/health", number: 1 },
        },
      ],
    } as PrototypeRun;

    expect(createRunReport(run, new Date("2026-08-30T21:00:00.000Z"))).toEqual({
      schemaVersion: 1,
      generatedAt: "2026-08-30T21:00:00.000Z",
      scenario: "discover",
      model: "openrouter/z-ai/glm-5.3-flash",
      target: "http://127.0.0.1:8888",
      outcome: {
        phase: "complete",
        validation: state.validation,
        requestsUsed: 0,
        requestBudget: 30,
        candidateCount: 0,
        agentFailures: 0,
        durationMs: 1234,
      },
      events: run.events,
    });
  });
});
