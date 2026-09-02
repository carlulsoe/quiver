import { GLM_FLASH_MODEL } from "./models.ts";
import type { MissionKind, RoutedModel } from "./model-routing.ts";

export const routedModelCatalog: readonly RoutedModel[] = [
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
];

export const preferredModels = {
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
} satisfies Record<MissionKind, readonly string[]>;

export function blendedCost(model: RoutedModel): number {
  return model.inputCostPerMillion + model.outputCostPerMillion;
}
export function cloneModel(model: RoutedModel): RoutedModel {
  return { ...model, capabilities: [...model.capabilities] };
}
