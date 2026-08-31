import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/evals/**/*.eval.ts"],
    // A complete eval includes three model-driven explorers and an independent
    // validator. Local GLM Flash latency can legitimately exceed six minutes.
    testTimeout: 600_000,
    hookTimeout: 600_000,
    fileParallelism: false,
    sequence: { concurrent: false },
    reporters: ["vitest-evals/reporter"],
  },
});
