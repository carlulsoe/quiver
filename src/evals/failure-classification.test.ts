import { describe, expect, it } from "vitest";
import type { CampaignRun } from "../prototype/runner.ts";
import { createCampaignBudget, createCampaignState } from "../prototype/state.ts";
import {
  classifyCampaignFailures,
  classifyTrialFailures,
  type EvalFailureKind,
} from "./failure-classification.ts";

describe("eval failure classification", () => {
  it("separates model, infrastructure, budget, mapping, and validation failures", () => {
    const run = campaignRun();
    run.state.phase = "failed";
    run.state.error = "connect ECONNREFUSED 127.0.0.1:8888";
    run.state.agents[0] = {
      ...run.state.agents[0]!,
      status: "failed",
      summary: "OpenRouter model rate limit exceeded",
    };
    run.state.agents.push({
      id: "explorer-2",
      role: "explorer",
      status: "failed",
      summary: "map_attack_surface browser mapping crashed",
    });
    run.state.findings.push({ fingerprint: "unvalidated" } as never);

    const failures = classifyCampaignFailures(run);

    expect(new Set(failures.map(({ kind }) => kind))).toEqual(
      new Set<EvalFailureKind>(["model", "infrastructure", "mapping", "validation"]),
    );

    run.state.requests.total = run.state.budget.total;
    run.state.requests.validation = run.state.budget.validation;
    expect(classifyCampaignFailures(run).map(({ kind }) => kind)).toContain("budget");
  });

  it("attributes missing artifacts to infrastructure and benchmark contract misses to the model", () => {
    expect(
      classifyTrialFailures({
        passed: false,
        error: "Could not read trial artifact",
      }),
    ).toEqual([
      {
        kind: "infrastructure",
        source: "eval-process",
        message: "Could not read trial artifact",
      },
    ]);

    expect(
      classifyTrialFailures({
        passed: false,
        output: {
          phase: "complete",
          coverage: 0.25,
          precision: 1,
          validationCompleteness: 1,
          benchmarkFalsePositiveCount: 0,
          benchmarkUnscoredCount: 0,
          failureClassifications: [],
        },
      }).map(({ kind }) => kind),
    ).toEqual(["model"]);
  });
});

function campaignRun(): CampaignRun {
  const state = createCampaignState("http://127.0.0.1:8888/", createCampaignBudget(30), 1);
  state.phase = "complete";
  state.discoveredOperations.push({ method: "GET", path: "/health" });
  return {
    profileId: "crapi",
    model: "test-model",
    durationMs: 1,
    usage: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 0,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    },
    state,
    events: [],
  };
}
