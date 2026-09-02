import type { RunReport } from "./report-create.ts";
import { renderFindingSections } from "./report-markdown-findings.ts";
import {
  actorAuthenticationCommands,
  credentialVariables,
  escapeTable,
  inlineValue,
  reproductionActorIds,
} from "./report-markdown-helpers.ts";

export function renderMarkdownReport(report: RunReport): string {
  const namedActors = reproductionActorIds(report);
  const variables = credentialVariables(namedActors);
  const lines = renderSummary(report);
  if (report.coordination.hypotheses.length)
    lines.push(
      "## Coordinator decision record",
      "",
      ...report.coordination.hypotheses.flatMap((hypothesis) => [
        `- **${hypothesis.status}** \`${hypothesis.method} ${hypothesis.route}\` — ${hypothesis.title} (${hypothesis.specialty}, ${(hypothesis.confidence * 100).toFixed(0)}%)`,
        `  ${hypothesis.nextStep}`,
      ]),
      "",
    );
  if (namedActors.length)
    lines.push(
      "## Authentication for reproduction",
      "",
      ...(report.reproductionAuthentication
        ? [report.reproductionAuthentication.description, ""]
        : []),
      "Prepare one credential variable for each named actor used by the reproduction:",
      "",
      "```sh",
      `export QUIVER_TARGET='${new URL(report.target).origin}'`,
      ...actorAuthenticationCommands(namedActors, variables, report.reproductionAuthentication),
      "```",
      "",
    );
  lines.push(
    ...renderFindingSections(report, variables),
    ...renderChains(report),
    ...renderTrace(report),
  );
  return `${lines.join("\n").trimEnd()}\n`;
}

function renderSummary(report: RunReport): string[] {
  return [
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
    `| Confirmed exploit chains | ${report.outcome.confirmedChainCount} |`,
    `| Rejected exploit chains | ${report.outcome.rejectedChainCount} |`,
    `| Requests | ${report.outcome.requests.total}/${report.outcome.budget.total} |`,
    `| Actionable operation coverage | ${(report.outcome.operationCoverage.coverage * 100).toFixed(1)}% (${report.outcome.operationCoverage.tested}/${report.outcome.operationCoverage.discovered}) |`,
    `| Access-mode coverage | ${(report.coordination.coverage.accessModeCoverage * 100).toFixed(1)}% (${report.coordination.coverage.testedAccessModes}/${report.coordination.coverage.totalAccessModes}) |`,
    `| Retained hypotheses | ${report.coordination.hypotheses.length} |`,
    `| Spawned specialists | ${report.coordination.specialists.length} |`,
    `| Duration | ${(report.outcome.durationMs / 1_000).toFixed(1)}s |`,
    `| Model tokens | ${report.usage.totalTokens} |`,
    `| Approximate model cost | $${report.usage.cost.total.toFixed(4)} |`,
    "",
    "## Model routing by mission",
    "",
    "| Mission | Role | Requirements | Models attempted | Tokens | Approximate cost |",
    "| --- | --- | --- | --- | ---: | ---: |",
    ...(report.missionUsage.length
      ? report.missionUsage.map(
          (mission) =>
            `| ${mission.missionId} | ${mission.role} | ${mission.requirements.capabilities.join(", ") || mission.requirements.costPreference} | ${mission.attemptedModels.join(" → ")} | ${mission.usage.totalTokens} | $${mission.usage.cost.total.toFixed(4)} |`,
        )
      : ["| None | — | — | — | 0 | $0.0000 |"]),
    "",
  ];
}

function renderChains(report: RunReport): string[] {
  const lines = ["## Exploit-chain proofs", ""];
  if (!report.exploitChains.length) return [...lines, "_None._", ""];
  for (const chain of report.exploitChains) {
    lines.push(
      `### ${chain.title}`,
      "",
      `- Outcome: **${chain.validation?.status ?? "unvalidated"}**`,
      `- Impact level: \`${chain.impactLevel}\``,
      `- Steps: ${chain.steps.map((step) => `\`${step}\``).join(" → ")}`,
      `- Result: ${chain.validation?.summary ?? "No fresh chain validation was recorded."}`,
      "",
    );
    for (const check of chain.validation?.checks ?? [])
      lines.push(
        `- ${check.passed ? "PASS" : "FAIL"}: ${check.description}${check.actual === undefined ? "" : ` (observed: \`${inlineValue(check.actual)}\`)`}`,
      );
    lines.push("");
  }
  return lines;
}

function renderTrace(report: RunReport): string[] {
  const lines = [
    "## Campaign trace",
    "",
    "Chronological request and agent-tool activity. The JSON report contains the complete state trace.",
    "",
    "| Event | Time | Type | Agent/phase | Detail |",
    "| ---: | ---: | --- | --- | --- |",
  ];
  for (const event of report.events.filter(({ type }) => type !== "state")) {
    const actor = event.data.agentId ?? event.data.phase ?? "campaign";
    const detail =
      event.data.toolName ?? event.data.path ?? event.data.error ?? event.data.toolCallId ?? "";
    lines.push(
      `<a id="trace-event-${event.sequence}"></a>| ${event.sequence} | ${event.elapsedMs}ms | ${event.type} | ${escapeTable(actor)} | ${escapeTable(detail)} |`,
    );
  }
  lines.push("");
  return lines;
}
