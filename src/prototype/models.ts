import { openrouterProvider } from "@earendil-works/pi-ai/providers/openrouter";
import type { Model } from "@earendil-works/pi-ai";
import { setProvider } from "@flue/runtime";

export const GLM_FLASH_MODEL = "openrouter/z-ai/glm-5.3-flash";

const openrouter = openrouterProvider();
const reference = openrouter.getModels().find((model) => model.id === "z-ai/glm-5.2");
if (!reference) throw new Error("Flue's OpenRouter provider has no GLM reference model");

const glm53Flash: Model<"openai-completions"> = {
  ...reference,
  id: "z-ai/glm-5.3-flash",
  name: "Z.ai: GLM 5.3 Flash",
  input: ["text", "image"],
  cost: { input: 0.075, output: 0.25, cacheRead: 0.015, cacheWrite: 0 },
  contextWindow: 1_048_576,
  maxTokens: 131_072,
  reasoning: true,
  thinkingLevelMap: {
    off: null,
    minimal: "low",
    low: "low",
    medium: "high",
    high: "high",
    xhigh: "max",
    max: "max",
  },
};

setProvider({
  ...openrouter,
  getModels: () => [...openrouter.getModels(), glm53Flash],
});
