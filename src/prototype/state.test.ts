import { describe, expect, it } from "vitest";
import { createState, reduce } from "./state.ts";

describe("prototype state", () => {
  it("does not let a completed run regress to an earlier phase", () => {
    const validating = reduce(createState("http://127.0.0.1:8888", 30), {
      type: "phase",
      phase: "validating",
    });
    const completed = reduce(validating, { type: "phase", phase: "complete" });

    expect(reduce(completed, { type: "phase", phase: "exploring" })).toBe(completed);
  });

  it("keeps failed runs terminal when late agent events arrive", () => {
    const failed = reduce(createState("http://127.0.0.1:8888", 30), {
      type: "failed",
      error: "target unavailable",
    });

    expect(reduce(failed, { type: "request" })).toBe(failed);
    expect(
      reduce(failed, {
        type: "candidate",
        candidate: {
          agentId: "explorer-1",
          title: "late finding",
          category: "access control",
          resource: "vehicle-1",
          sourcePath: "/posts",
          proofPath: "/vehicles/vehicle-1/location",
          rationale: "late result",
        },
      }),
    ).toBe(failed);
  });
});
