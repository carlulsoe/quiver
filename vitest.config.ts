import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    exclude: ["src/**/*.integration.test.ts"],
    // Keep real-browser suites responsive on hosts that report large CPU counts.
    maxWorkers: 4,
  },
});
