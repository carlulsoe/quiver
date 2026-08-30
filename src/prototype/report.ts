import { dirname, resolve } from "node:path";
import { mkdir } from "node:fs/promises";
import type { PrototypeRun } from "./runner.ts";

export interface RunReport {
  schemaVersion: 2;
  generatedAt: string;
  scenario: PrototypeRun["scenario"];
  profileId: string;
  model: string;
  target: string;
  outcome: {
    phase: PrototypeRun["state"]["phase"];
    validation: PrototypeRun["state"]["validation"];
    requestsUsed: number;
    requestBudget: number;
    candidateCount: number;
    agentFailures: number;
    durationMs: number;
  };
  events: PrototypeRun["events"];
}

export function createRunReport(run: PrototypeRun, generatedAt = new Date()): RunReport {
  return {
    schemaVersion: 2,
    generatedAt: generatedAt.toISOString(),
    scenario: run.scenario,
    profileId: run.profileId,
    model: run.model,
    target: run.state.target,
    outcome: {
      phase: run.state.phase,
      validation: run.state.validation,
      requestsUsed: run.state.requestsUsed,
      requestBudget: run.state.requestBudget,
      candidateCount: run.state.candidates.length,
      agentFailures: run.state.agents.filter((agent) => agent.status === "failed").length,
      durationMs: run.durationMs,
    },
    events: run.events,
  };
}

export async function writeRunReport(path: string, report: RunReport): Promise<string> {
  const absolutePath = resolve(path);
  await mkdir(dirname(absolutePath), { recursive: true });
  await Bun.write(absolutePath, `${JSON.stringify(report, null, 2)}\n`);
  return absolutePath;
}
