import { describe, expect, it } from "vitest";
import type { ModelRoute, RoutedModel } from "./model-routing.ts";
import { RoutedMission } from "./mission-runtime.ts";

describe("routed mission", () => {
  it("retries an availability failure before the first tool invocation", async () => {
    const mission = new RoutedMission(route());
    const attempts: string[] = [];

    const result = await mission.run(async (model) => {
      attempts.push(model.model);
      if (model.model === "provider/first")
        throw Object.assign(new Error("unavailable"), { status: 503 });
      return "completed";
    });

    expect(result).toBe("completed");
    expect(attempts).toEqual(["provider/first", "provider/second"]);
  });

  it("does not replay a mission after its first tool invocation", async () => {
    const mission = new RoutedMission(route());
    const attempts: string[] = [];

    await expect(
      mission.run(async (model, markToolInvoked) => {
        attempts.push(model.model);
        markToolInvoked();
        throw Object.assign(new Error("unavailable after target request"), { status: 503 });
      }),
    ).rejects.toThrow("unavailable after target request");
    expect(attempts).toEqual(["provider/first"]);
  });
});

function route(): ModelRoute {
  return {
    requirements: {
      kind: "route-triage",
      capabilities: [],
      costPreference: "cheap",
      estimatedInputTokens: 1,
    },
    candidates: [model("provider/first"), model("provider/second")],
  };
}

function model(name: string): RoutedModel {
  return {
    model: name,
    thinkingLevel: "medium",
    contextWindow: 1_000,
    capabilities: [],
    inputCostPerMillion: 0,
    outputCostPerMillion: 0,
  };
}
