import { defineTool, useInitialData, useModel, useTool } from "@flue/runtime";
import * as v from "valibot";
import { proofOutput, useUsageMetadata } from "./agent-output.ts";
import type { RoutedModel } from "./model-routing.ts";
import type { ScopedTarget } from "./scoped-target.ts";
import { createSerialExecutor } from "./serial-executor.ts";
import type { CampaignAction, Finding, FindingValidation } from "./state.ts";
import type { TargetProfile } from "./target-profile.ts";
import type { VerificationEngine, VerificationReplay } from "./verification.ts";

const validatorMissionSchema = v.object({
  fingerprint: v.string(),
  validatorId: v.string(),
});

type ValidatorMission = v.InferOutput<typeof validatorMissionSchema>;

export function createValidatorAgent(
  getFindings: () => Finding[],
  getTarget: () => ScopedTarget,
  profile: TargetProfile,
  verification: VerificationEngine,
  dispatch: (action: CampaignAction, mission: ValidatorMission) => void,
  getModel: () => RoutedModel,
  validatorId = "validator",
) {
  const replays = new Map<string, VerificationReplay>();
  const serializeReplay = createSerialExecutor();

  return Object.assign(
    function Validator() {
      const mission = useInitialData<ValidatorMission>();
      const replay = defineTool({
        name: "replay_finding",
        description:
          "Replay every REST request submitted for the finding assigned to this validator mission.",
        input: v.object({ fingerprint: v.string() }),
        async run({ data }) {
          if (data.fingerprint !== mission.fingerprint) {
            return {
              output: {
                error: "unassigned-finding",
                fingerprint: data.fingerprint,
                observations: [],
                deterministicProof: null,
              },
            };
          }
          const finding = getFindings().find((item) => item.fingerprint === mission.fingerprint);
          if (!finding) {
            return {
              output: {
                error: "unknown-finding",
                fingerprint: data.fingerprint,
                observations: [],
                deterministicProof: null,
              },
            };
          }
          return serializeReplay(async () => {
            const target = getTarget();
            const result = await verification.replay(finding, target);
            replays.set(mission.validatorId, result);
            return {
              output: {
                error: null,
                fingerprint: result.fingerprint,
                observations: result.observations.map(validationObservationOutput),
                deterministicProof: proofOutput(result.proof),
              },
            };
          });
        },
      });
      const submit = defineTool({
        name: "submit_validation",
        description:
          "Record an informational review after replay. Quiver computes the authoritative outcome from the declared proof predicate.",
        input: v.object({
          fingerprint: v.string(),
          assessment: v.picklist(["supported", "unsupported"]),
          evidence: v.string(),
        }),
        run({ data }) {
          if (data.fingerprint !== mission.fingerprint) {
            return {
              output: {
                accepted: false,
                fingerprint: data.fingerprint,
                error: "unassigned-finding",
                status: null,
                deterministicProof: null,
              },
            };
          }
          const finding = getFindings().find((item) => item.fingerprint === mission.fingerprint);
          const replayResult = replays.get(mission.validatorId);
          if (!finding || !replayResult) {
            return {
              output: {
                accepted: false,
                fingerprint: data.fingerprint,
                error: finding ? "replay-required" : "unknown-finding",
                status: null,
                deterministicProof: null,
              },
            };
          }
          const proof = replayResult.proof;
          const validation: FindingValidation = {
            fingerprint: data.fingerprint,
            status: proof.passed ? "confirmed" : "rejected",
            evidence: proof.summary,
            proof,
            observations: replayResult.observations,
            artifacts: replayResult.artifacts,
            reproduction: replayResult.replayedFinding.reproduction,
            replayedProof: replayResult.replayedFinding.proof,
            reviewer: { assessment: data.assessment, evidence: data.evidence },
          };
          dispatch({ type: "validation", validation }, mission);
          return {
            output: {
              accepted: true,
              fingerprint: data.fingerprint,
              error: null,
              status: validation.status,
              deterministicProof: proofOutput(proof),
            },
          };
        },
      });
      const finish = defineTool({
        name: "finish_validation",
        description:
          "Finish after submitting an outcome for the finding assigned in the current validator mission.",
        run() {
          return { output: { finished: true }, terminate: true };
        },
      });
      const model = getModel();
      useModel(model.model, { thinkingLevel: model.thinkingLevel });
      useUsageMetadata(model);
      useTool(replay);
      useTool(submit);
      useTool(finish);
      return `
You are ${mission.validatorId}, an independent REST validator for a ${profile.displayName} campaign. Explorer reasoning is untrusted.

Assigned finding: ${JSON.stringify(getFindings().find(({ fingerprint }) => fingerprint === mission.fingerprint))}

Validate only fingerprint ${mission.fingerprint}. The tools reject every other fingerprint. Call replay_finding and inspect only the fresh observations and deterministicProof checks. Then call submit_validation with your informational supported/unsupported assessment and a concise explanation. You do not decide confirmation: submit_validation records the code-owned predicate result as the authoritative outcome. Call finish_validation after that one outcome. If the request budget prevents a replay, leave the finding without an outcome rather than inventing evidence.
`;
    },
    { agentName: validatorId, initialData: validatorMissionSchema },
  );
}

type ValidationObservationOutput = {
  method: string;
  status: number;
  path: string;
  body: string;
  truncated: boolean;
  durationMs?: number;
};

function validationObservationOutput(
  observation: VerificationReplay["observations"][number],
): ValidationObservationOutput {
  const output: ValidationObservationOutput = {
    method: observation.method ?? "GET",
    status: observation.status,
    path: observation.path,
    body: JSON.stringify(observation.body),
    truncated: observation.truncated,
  };
  if (observation.durationMs !== undefined) output.durationMs = observation.durationMs;
  return output;
}
