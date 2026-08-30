import { dirname, resolve } from "node:path";
import { mkdir } from "node:fs/promises";
import type { CampaignRun } from "./runner.ts";
import type { Finding, FindingValidation } from "./state.ts";

export interface ReportedFinding extends Finding {
  validation?: FindingValidation;
}

export interface RunReport {
  schemaVersion: 3;
  generatedAt: string;
  profileId: string;
  model: string;
  target: string;
  outcome: {
    phase: CampaignRun["state"]["phase"];
    budget: CampaignRun["state"]["budget"];
    requests: CampaignRun["state"]["requests"];
    findingCount: number;
    confirmedCount: number;
    rejectedCount: number;
    unvalidatedCount: number;
    agentFailures: number;
    durationMs: number;
  };
  findings: ReportedFinding[];
  events: CampaignRun["events"];
}

export function createRunReport(run: CampaignRun, generatedAt = new Date()): RunReport {
  const findings = run.state.findings.map((finding): ReportedFinding => ({
    ...finding,
    validation: run.state.validations.find(
      (validation) => validation.fingerprint === finding.fingerprint,
    ),
  }));
  const confirmedCount = run.state.validations.filter(
    (validation) => validation.status === "confirmed",
  ).length;
  const rejectedCount = run.state.validations.filter(
    (validation) => validation.status === "rejected",
  ).length;

  return {
    schemaVersion: 3,
    generatedAt: generatedAt.toISOString(),
    profileId: run.profileId,
    model: run.model,
    target: run.state.target,
    outcome: {
      phase: run.state.phase,
      budget: run.state.budget,
      requests: run.state.requests,
      findingCount: findings.length,
      confirmedCount,
      rejectedCount,
      unvalidatedCount: findings.length - confirmedCount - rejectedCount,
      agentFailures: run.state.agents.filter((agent) => agent.status === "failed").length,
      durationMs: run.durationMs,
    },
    findings,
    events: run.events,
  };
}

export async function writeRunReport(path: string, report: RunReport): Promise<string> {
  const absolutePath = resolve(path);
  await mkdir(dirname(absolutePath), { recursive: true });
  await Bun.write(absolutePath, `${JSON.stringify(report, null, 2)}\n`);
  return absolutePath;
}
