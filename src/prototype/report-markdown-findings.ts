import { actorIds } from "./sessions.ts";
import type { ReportedFinding, RunReport } from "./report-create.ts";
import { curlCommand, inlineValue } from "./report-markdown-helpers.ts";

export function renderFindingSections(
  report: RunReport,
  variables: ReadonlyMap<string, string>,
): string[] {
  const lines: string[] = [];
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
    for (const finding of findings) renderFinding(lines, finding, report, variables);
  }
  return lines;
}

function renderFinding(
  lines: string[],
  finding: ReportedFinding,
  report: RunReport,
  variables: ReadonlyMap<string, string>,
): void {
  lines.push(
    `### ${finding.title}`,
    "",
    `- Category: \`${finding.category}\``,
    `- Severity: **${finding.severity}**`,
    `- Impact level: \`${finding.impactLevel}\``,
    `- CWE: \`${finding.cwe}\``,
    `- Operation: \`${finding.method ?? "GET"} ${finding.endpoint}\``,
    `- Fingerprint: \`${finding.fingerprint}\``,
    `- Resource tested: \`${finding.resource}\``,
    `- Trace: ${finding.traceEventSequences.length ? finding.traceEventSequences.map((sequence) => `[#${sequence}](#trace-event-${sequence})`).join(", ") : "_No validator tool event recorded._"}`,
    "",
    finding.rationale,
    "",
    `**Impact.** ${finding.impact}`,
    "",
    `**Mitigation.** ${finding.mitigation}`,
    "",
  );
  if (finding.validation) renderValidation(lines, finding);
  lines.push("Reproduction:", "", "```sh");
  for (const request of finding.validation?.reproduction ?? finding.reproduction)
    lines.push(curlCommand(request, report, variables));
  lines.push("```", "");
  renderArtifactInstructions(lines, finding, report);
}

function renderValidation(lines: string[], finding: ReportedFinding): void {
  const validation = finding.validation!;
  lines.push(
    "Deterministic validation:",
    "",
    `- Outcome: **${validation.status}**`,
    `- Predicate: \`${validation.proof.predicate}\``,
    `- Result: ${validation.evidence}`,
  );
  for (const check of validation.proof.checks)
    lines.push(
      `- ${check.passed ? "PASS" : "FAIL"}: ${check.description}${check.actual === undefined ? "" : ` (observed: \`${inlineValue(check.actual)}\`)`}`,
    );
  lines.push(
    "",
    `Informational LLM review: **${validation.reviewer.assessment}** — ${validation.reviewer.evidence}`,
    "",
    "Raw replay evidence:",
    "",
  );
  validation.observations.forEach((observation, index) =>
    lines.push(
      `${index + 1}. \`${observation.actorId} ${observation.method ?? "GET"} ${observation.path}\` → **${observation.status}**${observation.truncated ? " (truncated)" : ""}`,
      "",
      "```json",
      JSON.stringify(observation.body, null, 2),
      "```",
      "",
    ),
  );
}

function renderArtifactInstructions(
  lines: string[],
  finding: ReportedFinding,
  report: RunReport,
): void {
  const proof = finding.validation?.replayedProof;
  if (proof?.type === "browser-visible-effect")
    lines.push(
      "Artifact collection:",
      "",
      `1. Open \`${new URL(proof.pagePath, report.target).href}\` in a constrained Chromium session${proof.pageActorId === actorIds.anonymous ? " without authentication" : ` as ${proof.pageActorId}`}.`,
      `2. Block cross-origin requests, WebSockets, and popups; observe a dialog whose complete message is \`${proof.marker}\`.`,
      "",
    );
  else if (proof?.type === "oast-callback")
    lines.push(
      "Artifact collection:",
      "",
      "1. Start a fresh HTTP OAST listener reachable from the target (for Docker, configure a host-gateway advertised address).",
      `2. Replace the expired campaign callback \`${proof.callbackUrl}\` in the request with the fresh listener URL, then replay the request.`,
      "3. Confirm the listener receives the fresh unguessable token; historical callback metadata is retained below as validation evidence.",
      "",
    );
  if (finding.validation?.artifacts)
    lines.push(
      "Collected artifacts:",
      "",
      "```json",
      JSON.stringify(finding.validation.artifacts, null, 2),
      "```",
      "",
    );
}
