import { defineTool } from "@flue/runtime";
import * as v from "valibot";
import type { AdaptiveCoordinator } from "./adaptive-coordinator.ts";
import {
  categorySchema,
  impactLevelSchema,
  indexSchema,
  jsonPointerSchema,
  methodSchema,
  specialtySchema,
} from "./agent-schemas.ts";
import { chainProofOutput, proofOutput } from "./agent-output.ts";
import type { CampaignLedger } from "./campaign-ledger.ts";
import { chainInputFingerprint, evaluateExploitChain } from "./exploit-chain.ts";
import { actorIds } from "./sessions.ts";
import { fingerprintFinding, type ExploitChainInput, type FindingInput } from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";
import type { VerificationEngine } from "./verification.ts";
import { proofPredicateSchema } from "./verification.ts";

export function createExplorerSubmissionTools(
  agentId: string,
  profile: TargetProfile,
  ledger: CampaignLedger,
  coordinator: AdaptiveCoordinator,
  verification: VerificationEngine,
) {
  const submit = defineTool({
    name: "submit_finding",
    description:
      "Record one evidence-backed, reproducible vulnerability. Continue exploring after submission.",
    input: v.object({
      title: v.string(),
      category: categorySchema,
      severity: v.picklist(["low", "medium", "high", "critical"]),
      cwe: v.string(),
      endpoint: v.string(),
      method: methodSchema,
      resource: v.string(),
      rationale: v.string(),
      impact: v.string(),
      mitigation: v.string(),
      impactLevel: impactLevelSchema,
      reproduction: v.array(
        v.object({
          path: v.string(),
          method: methodSchema,
          headers: v.optional(v.record(v.string(), v.string())),
          body: v.optional(v.string()),
          actorId: v.picklist([actorIds.anonymous, ...(profile.actorIds ?? [])]),
          sampleId: v.optional(v.pipe(v.string(), v.minLength(1), v.maxLength(80))),
        }),
      ),
      proof: proofPredicateSchema,
    }),
    run({ data }) {
      const finding: FindingInput = { agentId, ...data };
      const fingerprint = fingerprintFinding(finding);
      const observations = ledger.observationsFor(finding.reproduction);
      if (!observations) {
        return {
          output: {
            accepted: false,
            fingerprint,
            error:
              "Every reproduction request must have a completed matching http_request observation",
            deterministicProof: null,
          },
        };
      }
      const preflight = verification.preflight(finding, { observations });
      if (!preflight.accepted) {
        return {
          output: {
            accepted: false,
            fingerprint,
            error: "The deterministic proof does not pass against exploration observations",
            deterministicProof: proofOutput(preflight.proof),
          },
        };
      }
      const recorded = ledger.recordFinding(finding);
      return {
        output: {
          ...recorded,
          error: null,
          deterministicProof: proofOutput(preflight.proof),
        },
      };
    },
  });
  const submitExploitChain = defineTool({
    name: "submit_exploit_chain",
    description:
      "Record a chain of two or more submitted findings when an exact replay value from each step is consumed by the next step.",
    input: v.object({
      title: v.string(),
      impactLevel: impactLevelSchema,
      steps: v.pipe(v.array(v.string()), v.minLength(2), v.maxLength(6)),
      links: v.array(
        v.object({
          from: v.object({
            fingerprint: v.string(),
            requestIndex: indexSchema,
            jsonPointer: jsonPointerSchema,
          }),
          to: v.object({
            fingerprint: v.string(),
            requestIndex: indexSchema,
            location: v.picklist(["query", "json-body", "header"]),
            parameter: v.pipe(v.string(), v.minLength(1)),
          }),
        }),
      ),
    }),
    run({ data }) {
      const input: ExploitChainInput = { agentId, ...data };
      const fingerprint = chainInputFingerprint(input);
      const result = evaluateExploitChain(
        { ...input, fingerprint },
        ledger.findingEvidence(),
        profile.maximumImpactLevel ?? "observation",
        profile.proofPolicies,
        { requireConfirmed: false, requireInjectedDataflow: false },
      );
      if (result.status !== "confirmed") {
        return { output: { accepted: false, fingerprint, validation: chainProofOutput(result) } };
      }
      return {
        output: {
          ...ledger.recordExploitChain(input),
          validation: chainProofOutput(result),
        },
      };
    },
  });
  const finish = defineTool({
    name: "finish_exploration",
    description:
      "Debrief the persistent coordinator, then retire this worker. Include strong untested leads so the coordinator can spawn a specialist.",
    input: v.object({
      summary: v.string(),
      exhausted: v.boolean(),
      hypotheses: v.optional(
        v.array(
          v.object({
            title: v.string(),
            method: v.optional(methodSchema),
            route: v.string(),
            specialty: specialtySchema,
            confidence: v.pipe(v.number(), v.minValue(0), v.maxValue(1)),
            rationale: v.string(),
            nextStep: v.string(),
          }),
        ),
      ),
    }),
    run({ data }) {
      const debrief = coordinator.debrief(agentId, data);
      return {
        output: {
          finished: true,
          debriefed: true,
          retainedHypotheses: debrief.hypotheses.length,
        },
        terminate: true,
      };
    },
  });
  return { submit, submitExploitChain, finish };
}
