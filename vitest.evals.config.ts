import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/evals/**/*.eval.ts"],
    testTimeout: 180_000,
    hookTimeout: 180_000,
    fileParallelism: false,
    reporters: ["vitest-evals/reporter"],
  },
});
