import type { CampaignRun } from "./runner.ts";
import { redactStructuredCredentials } from "./security/redaction.ts";
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
  schemaVersion: 9;
  generatedAt: string;
  profileId: string;
  reproductionAuthentication?: CampaignRun["reproductionAuthentication"];
  model: string;
  usage: CampaignRun["usage"];
  missionUsage: CampaignRun["missionUsage"];
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
  const findings = run.state.findings.map((finding): ReportedFinding =>
    redactStructuredCredentials({
      ...finding,
      validation: run.state.validations.find(
        ({ fingerprint }) => fingerprint === finding.fingerprint,
      ),
      traceEventSequences: run.events
        .filter(
          (event) =>
            event.data.agentId?.startsWith("validator") &&
            eventFingerprint(event.data.input) === finding.fingerprint,
        )
        .map(({ sequence }) => sequence),
    }),
  );
  const confirmedCount = run.state.validations.filter(
    ({ status }) => status === "confirmed",
  ).length;
  const rejectedCount = run.state.validations.filter(({ status }) => status === "rejected").length;
  return {
    schemaVersion: 9,
    generatedAt: generatedAt.toISOString(),
    profileId: run.profileId,
    reproductionAuthentication: run.reproductionAuthentication,
    model: run.model,
    usage: run.usage,
    missionUsage: run.missionUsage,
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
      agentFailures: run.state.agents.filter(({ status }) => status === "failed").length,
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
    exploitChains: redactStructuredCredentials(
      run.state.exploitChains.map((chain) => ({
        ...chain,
        validation: run.state.exploitChainValidations.find(
          ({ fingerprint }) => fingerprint === chain.fingerprint,
        ),
      })),
    ),
    events: redactStructuredCredentials(run.events),
  };
}

function eventFingerprint<Input>(input: Input): string | undefined {
  return input instanceof Object
    ? String(Reflect.get(input, "fingerprint") ?? "") || undefined
    : undefined;
}
