import { describe, expect, it } from "vitest";
import { buildEvalMatrix, deriveHeldOutSeed } from "./matrix.ts";

describe("generic evaluation matrix", () => {
  it("repeats crAPI while preserving VAmPI pairs and VulnerableApp native runs", () => {
    const matrix = buildEvalMatrix({
      profileIds: ["crapi", "vampi-vulnerable", "vampi-secure", "vulnerableapp"],
      trialCount: 3,
      runSeed: "matrix-seed",
    });

    expect(matrix.filter(({ profileId }) => profileId === "crapi")).toHaveLength(3);
    for (const index of [1, 2, 3]) {
      expect(
        matrix.filter((item) => item.index === index).map(({ profileId }) => profileId),
      ).toEqual(["crapi", "vampi-vulnerable", "vampi-secure", "vulnerableapp"]);
    }
  });

  it("derives distinct reproducible held-out seeds without assigning seeds to known targets", () => {
    const matrix = buildEvalMatrix({
      profileIds: ["crapi", "held-out"],
      trialCount: 3,
      runSeed: "matrix-seed",
    });
    const seeds = matrix.flatMap(({ heldOutSeed }) => (heldOutSeed ? [heldOutSeed] : []));

    expect(new Set(seeds).size).toBe(3);
    expect(seeds[0]).toBe(deriveHeldOutSeed("matrix-seed", 1));
    expect(
      buildEvalMatrix({
        profileIds: ["held-out"],
        trialCount: 3,
        runSeed: "matrix-seed",
      }).map(({ heldOutSeed }) => heldOutSeed),
    ).toEqual(seeds);
    expect(matrix.find(({ profileId }) => profileId === "crapi")).not.toHaveProperty("heldOutSeed");
  });
});
