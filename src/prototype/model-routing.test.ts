import { describe, expect, it } from "vitest";
import {
  createModelRouter,
  routeTriageRequirements,
  shouldFallbackModel,
  specialistRequirements,
} from "./model-routing.ts";
import { GLM_FLASH_MODEL } from "./models.ts";

describe("mission model routing", () => {
  it("uses the cheap route for ordinary triage and retains compatible fallbacks", () => {
    const route = createModelRouter().route(routeTriageRequirements(10_000));

    expect(route.candidates[0]?.model).toBe(GLM_FLASH_MODEL);
    expect(route.candidates.length).toBeGreaterThan(1);
  });

  it("routes browser-backed authentication to a browser reasoning model", () => {
    const route = createModelRouter().route(
      specialistRequirements({
        specialty: "authentication",
        contextTokens: 10_000,
        browserBacked: true,
      }),
    );

    expect(route.requirements.capabilities).toContain("browser-reasoning");
    expect(
      route.candidates.every(({ capabilities }) => capabilities.includes("browser-reasoning")),
    ).toBe(true);
  });

  it("requires payload generation for request-semantics specialists", () => {
    const route = createModelRouter().route(
      specialistRequirements({
        specialty: "request-semantics",
        contextTokens: 10_000,
        browserBacked: false,
      }),
    );

    expect(route.requirements.capabilities).toContain("payload-generation");
    expect(
      route.candidates.every(({ capabilities }) => capabilities.includes("payload-generation")),
    ).toBe(true);
  });

  it("filters unavailable models and rejects an unsatisfied route", () => {
    const onlyGlm = createModelRouter((model) => model === GLM_FLASH_MODEL);
    expect(onlyGlm.route(routeTriageRequirements(1)).candidates).toHaveLength(1);
    expect(() =>
      onlyGlm.route(
        specialistRequirements({
          specialty: "authentication",
          contextTokens: 1,
          browserBacked: true,
        }),
      ),
    ).toThrow("No available model satisfies specialist");
  });

  it("falls back only for availability failures before any tool invocation", () => {
    expect(shouldFallbackModel({ status: 503 }, false)).toBe(true);
    expect(shouldFallbackModel(new Error("model overloaded"), false)).toBe(true);
    expect(shouldFallbackModel({ status: 401 }, false)).toBe(false);
    expect(shouldFallbackModel({ status: 503 }, true)).toBe(false);
  });
});
