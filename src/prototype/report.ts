import { dirname, extname, resolve } from "node:path";
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

export function renderMarkdownReport(report: RunReport): string {
  const lines = [
    "# Quiver security campaign report",
    "",
    `Generated: ${report.generatedAt}`,
    `Target: ${report.target}`,
    `Profile: ${report.profileId}`,
    `Model: ${report.model}`,
    "",
    "## Campaign summary",
    "",
    "| Metric | Value |",
    "| --- | ---: |",
    `| Confirmed | ${report.outcome.confirmedCount} |`,
    `| Rejected | ${report.outcome.rejectedCount} |`,
    `| Unvalidated | ${report.outcome.unvalidatedCount} |`,
    `| Requests | ${report.outcome.requests.total}/${report.outcome.budget.total} |`,
    `| Duration | ${(report.outcome.durationMs / 1_000).toFixed(1)}s |`,
    "",
  ];

  const sections = [
    { title: "Confirmed findings", status: "confirmed" },
    { title: "Rejected findings", status: "rejected" },
    { title: "Unvalidated findings", status: undefined },
  ] as const;
  for (const section of sections) {
    const findings = report.findings.filter(
      (finding) => finding.validation?.status === section.status,
    );
    lines.push(`## ${section.title}`, "");
    if (findings.length === 0) {
      lines.push("_None._", "");
      continue;
    }
    for (const finding of findings) {
      lines.push(
        `### ${finding.title}`,
        "",
        `- Category: \`${finding.category}\``,
        `- Endpoint: \`${finding.endpoint}\``,
        `- Fingerprint: \`${finding.fingerprint}\``,
        `- Resource tested: \`${finding.resource}\``,
        "",
        finding.rationale,
        "",
      );
      if (finding.validation) {
        lines.push("Validation evidence:", "", `> ${finding.validation.evidence}`, "");
      }
      lines.push("Reproduction:", "", "```sh");
      for (const request of finding.reproduction) {
        const url = new URL(request.path, report.target).href;
        const auth = request.authenticated ? " --header 'Authorization: Bearer $QUIVER_TOKEN'" : "";
        lines.push(`curl --silent --show-error${auth} ${shellQuote(url)}`);
      }
      lines.push("```", "");
    }
  }

  return `${lines.join("\n").trimEnd()}\n`;
}

export async function writeRunReport(path: string, report: RunReport): Promise<string> {
  const absolutePath = resolve(path);
  await mkdir(dirname(absolutePath), { recursive: true });
  const contents =
    extname(absolutePath).toLowerCase() === ".md"
      ? renderMarkdownReport(report)
      : `${JSON.stringify(report, null, 2)}\n`;
  await Bun.write(absolutePath, contents);
  return absolutePath;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}
