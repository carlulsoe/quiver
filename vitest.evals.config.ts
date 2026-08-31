import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/evals/**/*.eval.ts"],
    // A complete campaign includes two model-driven explorers and an independent
    // validator. Local GLM Flash latency can legitimately exceed three minutes.
    testTimeout: 360_000,
    hookTimeout: 360_000,
    fileParallelism: false,
    sequence: { concurrent: false },
    reporters: ["vitest-evals/reporter"],
  },
});
