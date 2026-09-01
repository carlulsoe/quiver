import type { TargetProfile } from "../prototype/target-profile.ts";
import { heldOutCanary } from "./held-out-fixture.ts";
import { readFileSync } from "node:fs";
import { actorIds } from "../prototype/sessions.ts";

const configuredSeed = process.env.QUIVER_HELD_OUT_SEED ?? readPublishedSeed();

export const heldOutProfile: TargetProfile = createHeldOutProfile(configuredSeed);

export function createHeldOutProfile(seed: string | undefined): TargetProfile {
  const canary = seed ? heldOutCanary(seed) : undefined;
  return {
    id: "held-out",
    displayName: "Quiver randomized held-out target",
    objective:
      "Find the seeded read-only vulnerability while distinguishing it from authorization controls. Routes and identifiers change with each target seed. Treat returned QUIVER-CANARY values as concrete impact evidence and include them in deterministic proof pointers.",
    maximumImpactLevel: "observation",
    authenticate: async (target) => {
      target.setSession(actorIds.ordinary, {
        headers: { authorization: "Bearer quiver-showcase-user" },
      });
      return { authContext: "held-out-ordinary-user" };
    },
    actorIds: [actorIds.ordinary],
    reproductionAuthentication: {
      description:
        "The local held-out fixture uses a fixed synthetic bearer token; it is not a real credential.",
      commands: [`export QUIVER_TOKEN='quiver-showcase-user'`],
    },
    proofPolicies: canary
      ? [
          {
            id: "held-out-record-canary",
            kind: "canary",
            category: "sensitive-data-exposure",
            description: "The seeded foreign record contains a verifier-only synthetic canary.",
            endpoint: "/api/{namespace}/vaults/{id}",
            method: "GET",
            verify: (value: string) => value === canary,
            source: "immutable-fixture",
            jsonPointer: "/record/canary",
          },
        ]
      : [],
  };
}

function readPublishedSeed(): string | undefined {
  try {
    const seed = readFileSync(".prototype/held-out-seed", "utf8").trim();
    return seed || undefined;
  } catch {
    return undefined;
  }
}
