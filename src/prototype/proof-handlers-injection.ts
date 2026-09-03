import { endpointMatchesRequest } from "./endpoint.ts";
import type { ProofCheckHandler } from "./proof-types.ts";
import * as support from "./proof-support.ts";

export const sqlSemanticDifferentialHandler: ProofCheckHandler<"sql-semantic-differential"> = (
  finding,
  observations,
  checks,
  context,
) => {
  const proof = finding.proof;
  const policy = support.policyFor(context.policies, proof.policyId, "sql-semantic-differential");
  const controlRequest = finding.reproduction[proof.controlRequestIndex];
  const probeRequest = finding.reproduction[proof.probeRequestIndex];
  const controlObservation = observations[proof.controlRequestIndex];
  const probeObservation = observations[proof.probeRequestIndex];
  const controlResult = policy
    ? support.selectedAt(observations, proof.controlRequestIndex, policy.response.jsonPointer)
    : { found: false };
  const probeResult = policy
    ? support.selectedAt(observations, proof.probeRequestIndex, policy.response.jsonPointer)
    : { found: false };
  checks.push(
    support.check(
      policy?.category === finding.category,
      "target policy authorizes this SQL semantic differential",
    ),
    support.check(
      policy !== undefined &&
        finding.reproduction.length === 2 &&
        proof.controlRequestIndex === 0 &&
        proof.probeRequestIndex === 1,
      "SQL proof is one closed adjacent control-probe pair",
    ),
    support.check(
      policy !== undefined &&
        [controlRequest, probeRequest].every(
          (request) =>
            request !== undefined &&
            (request.method ?? "GET") === policy.method &&
            endpointMatchesRequest(policy.endpoint, request.path) &&
            support.affectedOperationMatches(finding, request),
        ),
      "SQL control and probe match the policy-bound affected operation",
    ),
    support.check(
      policy !== undefined &&
        support.requestMutationValue(controlRequest, policy.mutation) ===
          policy.mutation.controlValue &&
        support.requestMutationValue(probeRequest, policy.mutation) === policy.mutation.probeValue,
      "SQL requests use the target-owned control and probe predicates",
    ),
    support.check(
      policy !== undefined &&
        support.requestsShareMutationContract(controlRequest, probeRequest, policy.mutation),
      "SQL control and probe differ only by the policy-owned mutation",
    ),
    support.check(
      controlObservation !== undefined &&
        probeObservation !== undefined &&
        support.isSuccess(controlObservation.status) &&
        support.isSuccess(probeObservation.status),
      "SQL control and probe both returned successful responses",
    ),
    support.check(
      policy !== undefined &&
        controlResult.found &&
        support.sameValue(controlResult.value, policy.response.controlValue),
      "SQL control produced the target-owned semantic result",
      support.selectedEvidence(
        policy?.response.jsonPointer ?? "",
        controlResult.value,
        observations,
      ),
    ),
    support.check(
      policy !== undefined &&
        probeResult.found &&
        support.sameValue(probeResult.value, policy.response.probeValue),
      "SQL probe produced the target-owned semantic result",
      support.selectedEvidence(policy?.response.jsonPointer ?? "", probeResult.value, observations),
    ),
  );
};
export const commandExecutionChallengeHandler: ProofCheckHandler<"command-execution-challenge"> = (
  finding,
  observations,
  checks,
  context,
) => {
  const proof = finding.proof;
  const policy = support.policyFor(context.policies, proof.policyId, "command-execution-challenge");
  const request = finding.reproduction[proof.requestIndex];
  const observation = observations[proof.requestIndex];
  const selected = policy
    ? support.selectedAt(observations, proof.requestIndex, policy.outputJsonPointer)
    : { found: false };
  const expectedOutput = policy
    ? support.commandChallengeOutput(policy, proof.challenge)
    : undefined;
  checks.push(
    support.check(
      policy?.category === finding.category,
      "target policy authorizes this command-execution challenge",
    ),
    support.check(
      policy !== undefined &&
        Number.isSafeInteger(proof.challenge) &&
        proof.challenge >= policy.challengeMinimum &&
        proof.challenge <= policy.challengeMaximum &&
        expectedOutput !== undefined,
      "command challenge is a bounded policy-owned arithmetic input",
      proof.challenge,
    ),
    support.check(
      policy !== undefined &&
        finding.reproduction.length === 1 &&
        proof.requestIndex === 0 &&
        request !== undefined &&
        (request.method ?? "GET") === policy.method &&
        endpointMatchesRequest(policy.endpoint, request.path) &&
        support.affectedOperationMatches(finding, request),
      "command challenge is one policy-bound affected operation",
    ),
    support.check(
      policy !== undefined &&
        support.challengeRequestMatches(request, policy.challenge, String(proof.challenge)),
      "request uses the target-owned command template",
    ),
    support.check(
      observation !== undefined && support.isSuccess(observation.status),
      "command challenge returned a successful response",
      observation?.status,
    ),
    support.check(
      selected.found &&
        support.stringValue(selected.value) !== undefined &&
        expectedOutput !== undefined &&
        support.stringValue(selected.value)?.includes(expectedOutput) === true,
      "response contains the computed command-execution result",
      support.selectedEvidence(policy?.outputJsonPointer ?? "", selected.value, observations),
    ),
    support.check(
      request !== undefined &&
        expectedOutput !== undefined &&
        !support.requestContains(request, expectedOutput),
      "computed command result was not present in the request",
      expectedOutput,
    ),
  );
};
