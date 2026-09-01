import { dirname, extname, resolve } from "node:path";
import { mkdir } from "node:fs/promises";
import type { CampaignRun, RunEvent } from "./runner.ts";
import { actorIds } from "./sessions.ts";
import { isCredentialCapableHeader } from "./scoped-target.ts";
import {
  campaignOperationCoverage,
  type ExploitChain,
  type ExploitChainValidation,
  type Finding,
  type FindingValidation,
} from "./state.ts";

export interface ReportedFinding extends Finding {
  validation?: FindingValidation;
  traceEventSequences: number[];
}

export interface ReportedExploitChain extends ExploitChain {
  validation?: ExploitChainValidation;
}

export interface RunReport {
  schemaVersion: 8;
  generatedAt: string;
  profileId: string;
  reproductionAuthentication?: CampaignRun["reproductionAuthentication"];
  model: string;
  usage: CampaignRun["usage"];
  target: string;
  coordination: CampaignRun["state"]["coordination"];
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
    operationCoverage: ReturnType<typeof campaignOperationCoverage>;
    confirmedChainCount: number;
    rejectedChainCount: number;
  };
  findings: ReportedFinding[];
  exploitChains: ReportedExploitChain[];
  events: CampaignRun["events"];
}

export function createRunReport(run: CampaignRun, generatedAt = new Date()): RunReport {
  const findings = run.state.findings.map((finding): ReportedFinding => {
    const reported = {
      ...finding,
      validation: run.state.validations.find(
        (validation) => validation.fingerprint === finding.fingerprint,
      ),
      traceEventSequences: run.events
        .filter(
          (event) =>
            typeof event.data.agentId === "string" &&
            event.data.agentId.startsWith("validator") &&
            (event.data.input as { fingerprint?: unknown } | undefined)?.fingerprint ===
              finding.fingerprint,
        )
        .map(({ sequence }) => sequence),
    };
    return redactCredentials(reported) as ReportedFinding;
  });
  const confirmedCount = run.state.validations.filter(
    (validation) => validation.status === "confirmed",
  ).length;
  const rejectedCount = run.state.validations.filter(
    (validation) => validation.status === "rejected",
  ).length;
  const exploitChains = run.state.exploitChains.map((chain) => ({
    ...chain,
    validation: run.state.exploitChainValidations.find(
      ({ fingerprint }) => fingerprint === chain.fingerprint,
    ),
  }));

  return {
    schemaVersion: 8,
    generatedAt: generatedAt.toISOString(),
    profileId: run.profileId,
    reproductionAuthentication: run.reproductionAuthentication,
    model: run.model,
    usage: run.usage,
    target: run.state.target,
    coordination: run.state.coordination,
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
      operationCoverage: campaignOperationCoverage(run.state),
      confirmedChainCount: run.state.exploitChainValidations.filter(
        ({ status }) => status === "confirmed",
      ).length,
      rejectedChainCount: run.state.exploitChainValidations.filter(
        ({ status }) => status === "rejected",
      ).length,
    },
    findings,
    exploitChains: redactCredentials(exploitChains) as ReportedExploitChain[],
    events: redactCredentials(run.events) as RunEvent[],
  };
}

function redactCredentials(value: unknown, insideHeaders = false): unknown {
  if (Array.isArray(value)) return value.map((item) => redactCredentials(item));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([name, entry]) => [
      name,
      insideHeaders && isCredentialCapableHeader(name)
        ? "[REDACTED]"
        : isCredentialField(name)
          ? "[REDACTED]"
          : name.toLowerCase() === "body" && typeof entry === "string"
            ? redactCredentialBody(entry)
            : ["endpoint", "path", "target", "url"].includes(name.toLowerCase()) &&
                typeof entry === "string"
              ? redactCredentialUrl(entry)
              : redactCredentials(entry, name.toLowerCase() === "headers"),
    ]),
  );
}

function redactCredentialUrl(value: string): string {
  try {
    const absolute = /^[a-z][a-z\d+.-]*:/i.test(value);
    const url = new URL(value, "http://redaction.invalid");
    if (url.username || url.password) {
      url.username = "REDACTED";
      url.password = "REDACTED";
    }
    for (const name of new Set(url.searchParams.keys())) {
      if (isCredentialField(name)) url.searchParams.set(name, "[REDACTED]");
    }
    return absolute ? url.href : `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return "[REDACTED]";
  }
}

function redactCredentialBody(body: string): string {
  try {
    const parsed: unknown = JSON.parse(body);
    return parsed !== null && typeof parsed === "object"
      ? JSON.stringify(redactCredentials(parsed))
      : "[REDACTED]";
  } catch {
    // Unsupported body formats cannot be sanitized reliably enough for persistent reports.
    return "[REDACTED]";
  }
}

function isCredentialField(name: string): boolean {
  const normalized = name
    .replaceAll(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .replaceAll(/[^a-z0-9]+/g, "_");
  const parts = normalized.split("_").filter(Boolean);
  if (
    [
      "authorization",
      "cookie",
      "credential",
      "password",
      "passwd",
      "passphrase",
      "secret",
      "signature",
      "token",
    ].some((marker) => normalized.includes(marker))
  ) {
    return true;
  }
  if (["key", "cookie", "session", "otp"].some((marker) => parts.includes(marker))) return true;
  return (
    parts.includes("pin") ||
    ((parts.includes("verification") || parts.includes("mfa")) && parts.includes("code"))
  );
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
  ];

  if (report.coordination.hypotheses.length > 0) {
    lines.push(
      "## Coordinator decision record",
      "",
      ...report.coordination.hypotheses.flatMap((hypothesis) => [
        `- **${hypothesis.status}** \`${hypothesis.method} ${hypothesis.route}\` — ${hypothesis.title} (${hypothesis.specialty}, ${(hypothesis.confidence * 100).toFixed(0)}%)`,
        `  ${hypothesis.nextStep}`,
      ]),
      "",
    );
  }

  if (
    report.reproductionAuthentication &&
    report.findings.some(
      (finding) =>
        finding.reproduction.some((request) => request.actorId !== actorIds.anonymous) ||
        (finding.validation?.replayedProof?.type === "browser-visible-effect" &&
          finding.validation.replayedProof.pageActorId !== actorIds.anonymous),
    )
  ) {
    lines.push(
      "## Authentication for reproduction",
      "",
      report.reproductionAuthentication.description,
      "",
      "Set the target and obtain `$QUIVER_TOKEN` before running authenticated reproduction commands:",
      "",
      "```sh",
      `export QUIVER_TARGET=${shellQuote(new URL(report.target).origin)}`,
      ...report.reproductionAuthentication.commands,
      "```",
      "",
    );
  }

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
        `- Severity: **${finding.severity}**`,
        `- Impact level: \`${finding.impactLevel}\``,
        `- CWE: \`${finding.cwe}\``,
        `- Operation: \`${finding.method ?? "GET"} ${finding.endpoint}\``,
        `- Fingerprint: \`${finding.fingerprint}\``,
        `- Resource tested: \`${finding.resource}\``,
        `- Trace: ${
          finding.traceEventSequences.length > 0
            ? finding.traceEventSequences
                .map((sequence) => `[#${sequence}](#trace-event-${sequence})`)
                .join(", ")
            : "_No validator tool event recorded._"
        }`,
        "",
        finding.rationale,
        "",
        `**Impact.** ${finding.impact}`,
        "",
        `**Mitigation.** ${finding.mitigation}`,
        "",
      );
      if (finding.validation) {
        lines.push(
          "Deterministic validation:",
          "",
          `- Outcome: **${finding.validation.status}**`,
          `- Predicate: \`${finding.validation.proof.predicate}\``,
          `- Result: ${finding.validation.evidence}`,
          ...finding.validation.proof.checks.map(
            (check) =>
              `- ${check.passed ? "PASS" : "FAIL"}: ${check.description}${
                check.actual === undefined ? "" : ` (observed: \`${inlineValue(check.actual)}\`)`
              }`,
          ),
          "",
          `Informational LLM review: **${finding.validation.reviewer.assessment}** — ${finding.validation.reviewer.evidence}`,
          "",
          "Raw replay evidence:",
          "",
        );
        finding.validation.observations.forEach((observation, index) => {
          lines.push(
            `${index + 1}. \`${observation.actorId} ${observation.method ?? "GET"} ${observation.path}\` → **${observation.status}**${observation.truncated ? " (truncated)" : ""}`,
            "",
            "```json",
            JSON.stringify(observation.body, null, 2),
            "```",
            "",
          );
        });
      }
      lines.push("Reproduction:", "", "```sh");
      for (const request of finding.validation?.reproduction ?? finding.reproduction) {
        const url = new URL(request.path, report.target).href;
        const auth =
          request.actorId !== actorIds.anonymous
            ? " --header 'Authorization: Bearer $QUIVER_TOKEN'"
            : "";
        const method = request.method ?? "GET";
        const headers = Object.entries(request.headers ?? {})
          .flatMap(([name, value]) => {
            if (!isCredentialCapableHeader(name)) {
              return [` --header ${shellQuote(`${name}: ${value}`)}`];
            }
            if (request.actorId !== actorIds.anonymous && name.toLowerCase() === "authorization")
              return [];
            const variable = `QUIVER_HEADER_${name
              .toUpperCase()
              .replaceAll(/[^A-Z0-9]+/g, "_")
              .replaceAll(/^_+|_+$/g, "")}`;
            return [` --header ${shellQuote(`${name}: `)}"$${variable}"`];
          })
          .join("");
        const body =
          request.body === undefined
            ? ""
            : request.body.includes("[REDACTED]") || request.body.includes("%5BREDACTED%5D")
              ? ' --data-raw "$QUIVER_REQUEST_BODY"'
              : ` --data-raw ${shellQuote(request.body)}`;
        lines.push(
          `curl --silent --show-error --request ${method}${auth}${headers}${body} ${shellQuote(url)}`,
        );
      }
      lines.push("```", "");
      const replayedProof = finding.validation?.replayedProof;
      if (replayedProof?.type === "browser-visible-effect") {
        lines.push(
          "Artifact collection:",
          "",
          `1. Open \`${new URL(replayedProof.pagePath, report.target).href}\` in a constrained Chromium session${replayedProof.pageActorId === actorIds.anonymous ? " without authentication" : ` as ${replayedProof.pageActorId}`}.`,
          `2. Block cross-origin requests, WebSockets, and popups; observe a dialog whose complete message is \`${replayedProof.marker}\`.`,
          "",
        );
      } else if (replayedProof?.type === "oast-callback") {
        lines.push(
          "Artifact collection:",
          "",
          "1. Start a fresh HTTP OAST listener reachable from the target (for Docker, configure a host-gateway advertised address).",
          `2. Replace the expired campaign callback \`${replayedProof.callbackUrl}\` in the request with the fresh listener URL, then replay the request.`,
          "3. Confirm the listener receives the fresh unguessable token; historical callback metadata is retained below as validation evidence.",
          "",
        );
      }
      if (finding.validation?.artifacts) {
        lines.push(
          "Collected artifacts:",
          "",
          "```json",
          JSON.stringify(finding.validation.artifacts, null, 2),
          "```",
          "",
        );
      }
    }
  }

  lines.push("## Exploit-chain proofs", "");
  if (report.exploitChains.length === 0) {
    lines.push("_None._", "");
  } else {
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
      for (const item of chain.validation?.checks ?? []) {
        lines.push(
          `- ${item.passed ? "PASS" : "FAIL"}: ${item.description}${
            item.actual === undefined ? "" : ` (observed: \`${inlineValue(item.actual)}\`)`
          }`,
        );
      }
      lines.push("");
    }
  }

  lines.push(
    "## Campaign trace",
    "",
    "Chronological request and agent-tool activity. The JSON report contains the complete state trace.",
    "",
    "| Event | Time | Type | Agent/phase | Detail |",
    "| ---: | ---: | --- | --- | --- |",
  );
  for (const event of report.events.filter((item) => item.type !== "state")) {
    lines.push(
      `<a id="trace-event-${event.sequence}"></a>| ${event.sequence} | ${event.elapsedMs}ms | ${event.type} | ${traceActor(event.data)} | ${traceDetail(event.data)} |`,
    );
  }
  lines.push("");

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

function inlineValue(value: unknown): string {
  return JSON.stringify(value).replaceAll("`", "\\`").slice(0, 160);
}

function traceActor(data: Record<string, unknown>): string {
  return escapeTable(String(data.agentId ?? data.phase ?? "campaign"));
}

function traceDetail(data: Record<string, unknown>): string {
  const detail = data.toolName ?? data.path ?? data.error ?? data.toolCallId ?? "";
  return escapeTable(String(detail));
}

function escapeTable(value: string): string {
  return value.replaceAll("|", "\\|").replaceAll("\n", " ");
}
