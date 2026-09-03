import { describe, expect, it } from "vitest";
import type { CampaignOrchestrationFactory } from "./campaign-orchestration.ts";
import { runCampaign } from "./runner.ts";
import { validationJobId, type FindingInput } from "./state.ts";

const finding: FindingInput = {
  agentId: "explorer-1",
  title: "Account response exposes an internal field",
  category: "excessive-data-exposure",
  severity: "medium",
  cwe: "CWE-200",
  endpoint: "/api/accounts/42",
  method: "GET",
  resource: "account-42",
  rationale: "The response includes an internal risk score.",
  impact: "A caller can inspect internal account metadata.",
  mitigation: "Return only fields intended for the caller.",
  reproduction: [{ path: "/api/accounts/42", actorId: "anonymous" }],
  proof: { type: "internal-field-exposure", requestIndex: 0, evidencePointers: ["/risk"] },
};

describe("successful campaign orchestration", () => {
  it("completes discovery, validation, budget reclamation, and aggregate history", async () => {
    const steps: string[] = [];
    const orchestrationFactory: CampaignOrchestrationFactory = ({ session }) => ({
      async startRuntime() {
        steps.push("runtime-started");
        return {
          async [Symbol.asyncDispose]() {
            steps.push("runtime-disposed");
          },
        };
      },
      async restoreAuthentication(resumedPhase) {
        steps.push(`authentication-restored:${resumedPhase}`);
      },
      async runExploration() {
        steps.push("exploration-started");
        session.dispatch({ type: "phase", phase: "exploring" });
        session.dispatch({ type: "agent", id: "explorer-1", status: "running" });
        session.dispatch({ type: "routes-discovered", routes: ["/api/accounts/42"] });
        session.dispatch({
          type: "operations-discovered",
          operations: [{ method: "GET", path: "/api/accounts/{id}" }],
        });
        session.dispatch({ type: "request", phase: "exploration" });
        session.dispatch({
          type: "request-tested",
          request: {
            agentId: "explorer-1",
            method: "GET",
            path: "/api/accounts/42",
            actorId: "anonymous",
            status: 200,
          },
        });
        session.dispatch({ type: "finding", finding });
        session.dispatch({ type: "agent", id: "explorer-1", status: "finished" });
      },
      async drainValidation() {
        steps.push("validation-drained");
      },
      reclaimExplorationBudget() {
        steps.push("budget-reclaimed");
        session.dispatch({ type: "reclaim-exploration-budget" });
        session.dispatch({ type: "phase", phase: "validating" });
      },
      async runPendingFindings() {
        steps.push("findings-validated");
        const fingerprint = session.state.findings[0]?.fingerprint;
        if (!fingerprint) throw new Error("Expected the exploration finding to be accepted");
        session.dispatch({ type: "agent", id: "validator", status: "running" });
        session.dispatch({ type: "job-started", id: validationJobId(fingerprint) });
        session.dispatch({ type: "request", phase: "validation" });
        session.dispatch({
          type: "validation",
          validation: {
            fingerprint,
            status: "confirmed",
            evidence: "Independent replay returned the internal risk field.",
            proof: {
              predicate: "internal-field-exposure",
              passed: true,
              summary: "The field was exposed.",
              checks: [],
            },
            observations: [],
            reviewer: { assessment: "supported", evidence: "Replay supports the finding." },
          },
        });
        session.dispatch({ type: "agent", id: "validator", status: "finished" });
      },
      async runExploitChains() {
        steps.push("chains-validated");
      },
      assertAllJobsFinished() {
        steps.push("jobs-checked");
        if (session.state.runtime.jobs.some(({ status }) => status !== "completed")) {
          throw new Error("Expected every durable proof job to be completed");
        }
      },
    });

    const run = await runCampaign({
      target: new URL("http://127.0.0.1:8888/"),
      profile: {
        id: "orchestration-test",
        displayName: "Orchestration test",
        objective: "Exercise the deterministic campaign lifecycle.",
      },
      requestBudget: 9,
      explorerCount: 1,
      orchestrationFactory,
    });

    expect(run.state).toMatchObject({
      phase: "complete",
      budget: { total: 9, exploration: 1, validation: 8 },
      requests: { total: 2, exploration: 1, validation: 1 },
    });
    expect(run.state.discoveredRoutes).toEqual(["/api/accounts/42"]);
    expect(run.state.discoveredOperations).toEqual([{ method: "GET", path: "/api/accounts/{id}" }]);
    expect(run.state.findings).toHaveLength(1);
    expect(run.state.validations).toEqual([
      expect.objectContaining({
        status: "confirmed",
        fingerprint: run.state.findings[0]!.fingerprint,
      }),
    ]);
    expect(run.state.runtime.jobs).toEqual([
      expect.objectContaining({ status: "completed", attempts: 1 }),
    ]);
    expect(run.state.agents.every(({ status }) => status === "finished")).toBe(true);
    expect(run.events).toEqual(run.state.history.events);
    expect(run.events.map(({ data }) => data.action)).toContain("reclaim-exploration-budget");
    expect(steps.indexOf("exploration-started")).toBeLessThan(steps.indexOf("budget-reclaimed"));
    expect(steps.indexOf("budget-reclaimed")).toBeLessThan(steps.indexOf("findings-validated"));
    expect(steps.at(-1)).toBe("runtime-disposed");
  });
});
