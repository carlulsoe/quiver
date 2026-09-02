import type { ThinkingLevel } from "@flue/runtime";
import type { SpecialistKind } from "./adaptive-coordinator.ts";
import { GLM_FLASH_MODEL } from "./models.ts";

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

const modelCatalog: readonly RoutedModel[] = [
  {
    model: GLM_FLASH_MODEL,
    thinkingLevel: "medium",
    contextWindow: 1_048_576,
    capabilities: ["payload-generation", "large-context"],
    inputCostPerMillion: 0.075,
    outputCostPerMillion: 0.25,
  },
  {
    model: "openrouter/google/gemini-2.5-flash-lite",
    thinkingLevel: "medium",
    contextWindow: 1_048_576,
    capabilities: ["browser-reasoning", "large-context"],
    inputCostPerMillion: 0.1,
    outputCostPerMillion: 0.4,
  },
  {
    model: "openrouter/openai/gpt-5-mini",
    thinkingLevel: "medium",
    contextWindow: 400_000,
    capabilities: ["browser-reasoning", "payload-generation"],
    inputCostPerMillion: 0.25,
    outputCostPerMillion: 2,
  },
  {
    model: "openrouter/google/gemini-2.5-pro",
    thinkingLevel: "high",
    contextWindow: 1_048_576,
    capabilities: ["browser-reasoning", "payload-generation", "large-context"],
    inputCostPerMillion: 1.25,
    outputCostPerMillion: 10,
  },
] as const;

const preferredModels: Record<MissionKind, readonly string[]> = {
  "route-triage": [
    GLM_FLASH_MODEL,
    "openrouter/google/gemini-2.5-flash-lite",
    "openrouter/openai/gpt-5-mini",
    "openrouter/google/gemini-2.5-pro",
  ],
  specialist: [
    "openrouter/openai/gpt-5-mini",
    "openrouter/google/gemini-2.5-flash-lite",
    GLM_FLASH_MODEL,
    "openrouter/google/gemini-2.5-pro",
  ],
  validation: [
    GLM_FLASH_MODEL,
    "openrouter/openai/gpt-5-mini",
    "openrouter/google/gemini-2.5-flash-lite",
    "openrouter/google/gemini-2.5-pro",
  ],
};

export function createModelRouter(available: (model: string) => boolean = () => true): ModelRouter {
  return {
    route(requirements) {
      assertRequirements(requirements);
      const compatible = modelCatalog.filter(
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
export function shouldFallbackModel(error: unknown, toolInvoked: boolean): boolean {
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

export function estimateTokens(value: unknown): number {
  const text = typeof value === "string" ? value : (JSON.stringify(value) ?? "");
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

function blendedCost(model: RoutedModel): number {
  return model.inputCostPerMillion + model.outputCostPerMillion;
}

function cloneModel(model: RoutedModel): RoutedModel {
  return { ...model, capabilities: [...model.capabilities] };
}

function cloneRequirements(requirements: MissionRequirements): MissionRequirements {
  return { ...requirements, capabilities: [...requirements.capabilities] };
}

function errorStatus(error: unknown): number | undefined {
  let current: unknown = error;
  for (let depth = 0; depth < 4 && current && typeof current === "object"; depth += 1) {
    const record = current as { status?: unknown; statusCode?: unknown; cause?: unknown };
    const status = record.status ?? record.statusCode;
    if (typeof status === "number") return status;
    current = record.cause;
  }
  return undefined;
}
