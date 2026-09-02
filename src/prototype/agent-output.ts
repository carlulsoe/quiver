import { useResponseFinish } from "@flue/runtime";
import type { RoutedModel } from "./model-routing.ts";
import type { ProofResult } from "./state.ts";
import { evaluateExploitChain } from "./exploit-chain.ts";

export function useUsageMetadata(model: RoutedModel) {
  useResponseFinish(({ response }) => ({
    quiverUsage: response.usage,
    quiverModel: model.model,
  }));
}

export function proofOutput(proof: ProofResult) {
  return {
    predicate: proof.predicate,
    classification: proof.classification ?? null,
    passed: proof.passed,
    summary: proof.summary,
    checks: proof.checks.map((item) => ({
      description: item.description,
      passed: item.passed,
      actual: item.actual === undefined ? null : JSON.stringify(item.actual),
    })),
  };
}

export function chainProofOutput(result: ReturnType<typeof evaluateExploitChain>) {
  return {
    fingerprint: result.fingerprint,
    status: result.status,
    summary: result.summary,
    checks: result.checks.map((item) => ({
      description: item.description,
      passed: item.passed,
      actual: item.actual === undefined ? null : JSON.stringify(item.actual),
    })),
  };
}
