import type { TargetProfile } from "../prototype/target-profile.ts";
import { heldOutCanary } from "./held-out-fixture.ts";
import { readFileSync } from "node:fs";

const configuredSeed = process.env.QUIVER_HELD_OUT_SEED ?? readPublishedSeed();
const configuredCanary = configuredSeed ? heldOutCanary(configuredSeed) : undefined;

export const heldOutProfile: TargetProfile = {
  id: "held-out",
  displayName: "Quiver randomized held-out target",
  objective:
    "Find the seeded read-only vulnerability while distinguishing it from authorization controls. Routes and identifiers change with each target seed. Treat returned QUIVER-CANARY values as concrete impact evidence and include them in deterministic proof pointers.",
  authenticate: async (target) => {
    target.setAuthentication({ authorization: "Bearer quiver-showcase-user" });
    return { authContext: "held-out-ordinary-user" };
  },
  reproductionAuthentication: {
    description:
      "The local held-out fixture uses a fixed synthetic bearer token; it is not a real credential.",
    commands: [`export QUIVER_TOKEN='quiver-showcase-user'`],
  },
  proofPolicies: configuredCanary
    ? [
        {
          id: "held-out-record-canary",
          kind: "canary",
          category: "sensitive-data-exposure",
          description: "The seeded foreign record contains a verifier-only synthetic canary.",
          endpoint: "/api/{namespace}/vaults/{id}",
          method: "GET",
          verify: (value: string) => value === configuredCanary,
          source: "immutable-fixture",
          jsonPointer: "/record/canary",
        },
      ]
    : [],
};

function readPublishedSeed(): string | undefined {
  try {
    const seed = readFileSync(".prototype/held-out-seed", "utf8").trim();
    return seed || undefined;
  } catch {
    return undefined;
  }
}
