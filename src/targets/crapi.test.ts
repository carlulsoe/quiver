import { describe, expect, it } from "vitest";
import type { ScopedTarget } from "../prototype/scoped-target.ts";
import { crapiProfile } from "./crapi.ts";

describe("crAPI target profile", () => {
  it("rejects a proof path outside the vehicle-location route shape", async () => {
    const unusedTarget = {} as ScopedTarget;

    await expect(
      crapiProfile.validate(unusedTarget, {
        agentId: "explorer-1",
        title: "candidate",
        category: "BOLA",
        resource: "vehicle-1",
        sourcePath: "/posts",
        proofPath: "/identity/api/v2/vehicle/vehicle-1",
        rationale: "candidate rationale",
      }),
    ).resolves.toMatchObject({ confirmed: false, reason: "invalid-proof-path" });
  });
});
