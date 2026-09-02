import type { ThinkingLevel } from "@flue/runtime";
import { number, safeParse } from "valibot";
import type { SpecialistKind } from "./adaptive-coordinator.ts";
import { blendedCost, cloneModel, preferredModels, routedModelCatalog } from "./model-catalog.ts";

export type ModelCapability = "browser-reasoning" | "payload-generation" | "large-context";
export type MissionCostPreference = "cheap" | "balanced" | "quality";
export type MissionKind = "route-triage" | "specialist" | "validation";

export interface MissionRequirements {
  kind: MissionKind;
  capabilities: readonly ModelCapability[];
  costPreference: MissionCostPreference;
  /** Estimated prompt size. Selection fails closed when no model can hold it. */
  estimatedInputTokens: number;
}

export interface RoutedModel {
  model: string;
  thinkingLevel: ThinkingLevel;
  contextWindow: number;
  capabilities: readonly ModelCapability[];
  inputCostPerMillion: number;
  outputCostPerMillion: number;
}

export interface ModelRoute {
  requirements: MissionRequirements;
  candidates: readonly RoutedModel[];
}

export interface ModelRouter {
  route(requirements: MissionRequirements): ModelRoute;
}

export interface SpecialistRequirementInput {
  specialty: SpecialistKind;
  contextTokens: number;
  browserBacked: boolean;
}

export function createModelRouter(available: (model: string) => boolean = () => true): ModelRouter {
  return {
    route(requirements) {
      assertRequirements(requirements);
      const compatible = routedModelCatalog.filter(
        (candidate) =>
          available(candidate.model) &&
          candidate.contextWindow >= requirements.estimatedInputTokens &&
          requirements.capabilities.every((capability) =>
            candidate.capabilities.includes(capability),
          ),
      );
      const order = preferredModels[requirements.kind];
      compatible.sort((left, right) => {
        if (requirements.costPreference === "cheap") {
          return (
            blendedCost(left) - blendedCost(right) ||
            order.indexOf(left.model) - order.indexOf(right.model)
          );
        }
        if (requirements.costPreference === "quality") {
          return order.indexOf(left.model) - order.indexOf(right.model);
        }
        const leftIndex = order.indexOf(left.model);
        const rightIndex = order.indexOf(right.model);
        return leftIndex - rightIndex || blendedCost(left) - blendedCost(right);
      });
      if (compatible.length === 0) {
        const capabilities = requirements.capabilities.join(", ") || "standard tool use";
        throw new Error(
          `No available model satisfies ${requirements.kind}: ${capabilities}, ${requirements.estimatedInputTokens} input tokens`,
        );
      }
      return {
        requirements: cloneRequirements(requirements),
        candidates: compatible.map(cloneModel),
      };
    },
  };
}

export function routeTriageRequirements(contextTokens: number): MissionRequirements {
  return {
    kind: "route-triage",
    capabilities: contextTokens > 300_000 ? ["large-context"] : [],
    costPreference: "cheap",
    estimatedInputTokens: normalizedTokenEstimate(contextTokens),
  };
}

export function specialistRequirements({
  specialty,
  contextTokens,
  browserBacked,
}: SpecialistRequirementInput): MissionRequirements {
  const capabilities = new Set<ModelCapability>();
  if (specialty === "request-semantics") capabilities.add("payload-generation");
  if (specialty === "authentication" && browserBacked) capabilities.add("browser-reasoning");
  if (contextTokens > 300_000) capabilities.add("large-context");
  return {
    kind: "specialist",
    capabilities: [...capabilities],
    costPreference: "balanced",
    estimatedInputTokens: normalizedTokenEstimate(contextTokens),
  };
}

export function validationRequirements(findingTokens: number): MissionRequirements {
  return {
    kind: "validation",
    capabilities: findingTokens > 300_000 ? ["large-context"] : [],
    costPreference: "balanced",
    estimatedInputTokens: normalizedTokenEstimate(findingTokens),
  };
}

/**
 * A model fallback is safe only before the mission has invoked a tool. This avoids replaying
 * state-changing requests merely because a provider failed after receiving tool output.
 */
export function shouldFallbackModel<Failure>(error: Failure, toolInvoked: boolean): boolean {
  if (toolInvoked) return false;
  const status = errorStatus(error);
  if (status !== undefined) return status === 408 || status === 429 || status >= 500;
  const message = String(error).toLowerCase();
  return [
    "model unavailable",
    "model is unavailable",
    "rate limit",
    "rate_limit",
    "overloaded",
    "capacity",
    "timed out",
    "timeout",
    "service unavailable",
  ].some((marker) => message.includes(marker));
}

export function estimateTokens<Value>(value: Value): number {
  const text =
    Object.prototype.toString.call(value) === "[object String]"
      ? String(value)
      : (JSON.stringify(value) ?? "");
  return Math.ceil(text.length / 4);
}

function assertRequirements(requirements: MissionRequirements): void {
  if (
    !Number.isInteger(requirements.estimatedInputTokens) ||
    requirements.estimatedInputTokens < 0
  ) {
    throw new Error("Estimated mission input tokens must be a non-negative integer");
  }
  if (new Set(requirements.capabilities).size !== requirements.capabilities.length) {
    throw new Error("Mission capabilities must be unique");
  }
}

function normalizedTokenEstimate(value: number): number {
  if (!Number.isFinite(value) || value < 0)
    throw new Error("Context token estimate must be non-negative");
  return Math.ceil(value);
}

function cloneRequirements(requirements: MissionRequirements): MissionRequirements {
  return { ...requirements, capabilities: [...requirements.capabilities] };
}

function errorStatus<Failure>(error: Failure): number | undefined {
  let current: object | undefined = error instanceof Object ? error : undefined;
  for (let depth = 0; depth < 4 && current; depth += 1) {
    const status = Reflect.get(current, "status") ?? Reflect.get(current, "statusCode");
    const parsed = safeParse(number(), status);
    if (parsed.success) return parsed.output;
    const cause = Reflect.get(current, "cause");
    current = cause instanceof Object ? cause : undefined;
  }
  return undefined;
}
