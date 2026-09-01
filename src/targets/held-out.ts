import { readFileSync } from "node:fs";
import { actorIds } from "../prototype/sessions.ts";
import { createTargetProfile } from "../prototype/target-profile.ts";
import type { TargetManifest } from "../prototype/target-manifest.ts";
import { heldOutCanary } from "./held-out-fixture.ts";

const configuredSeed = process.env.QUIVER_HELD_OUT_SEED ?? readPublishedSeed();

export const heldOutManifest = {
  schemaVersion: 1,
  id: "held-out",
  displayName: "Quiver randomized held-out target",
  authenticationContext: "held-out-multi-principal",
  objective:
    "Find the seeded read-only vulnerability while distinguishing it from authorization controls. Routes and identifiers change with each target seed. Treat returned QUIVER-CANARY values as concrete impact evidence and include them in deterministic proof pointers.",
  scope: {
    maximumImpactLevel: "observation",
    protectedOperations: [
      {
        method: "GET",
        path: "/api/{namespace}/vaults/{id}",
        authorizedActors: [actorIds.userA, actorIds.userB, actorIds.administrator],
        description: "Vault reads must enforce ownership unless the caller is an administrator.",
      },
      {
        method: "POST",
        path: "/api/{namespace}/audit",
        authorizedActors: [actorIds.administrator],
        description: "Audit execution is an administrator-only operation.",
      },
    ],
  },
  identities: [
    { id: actorIds.anonymous, label: "Anonymous", role: "anonymous" },
    ...(
      [
        [actorIds.userA, "Held-out user A", "user", "quiver-showcase-user"],
        [actorIds.userB, "Held-out user B", "user", "quiver-showcase-user-b"],
        [
          actorIds.administrator,
          "Held-out administrator",
          "administrator",
          "quiver-showcase-admin",
        ],
      ] as const
    ).map(([id, label, role, credential]) => ({
      id,
      label,
      role,
      authentication: {
        kind: "header-token" as const,
        credential: { location: "literal" as const, value: credential },
      },
    })),
  ],
  reproductionAuthentication: {
    description:
      "The held-out fixture uses fixed synthetic bearer tokens; they are not credentials.",
    commands: [`export QUIVER_TOKEN='quiver-showcase-user'`],
    actors: {
      [actorIds.userA]: {
        description: "Synthetic user A.",
        commands: [`export QUIVER_TOKEN='quiver-showcase-user'`],
      },
      [actorIds.userB]: {
        description: "Synthetic user B.",
        commands: [`export QUIVER_TOKEN='quiver-showcase-user-b'`],
      },
      [actorIds.administrator]: {
        description: "Synthetic administrator.",
        commands: [`export QUIVER_TOKEN='quiver-showcase-admin'`],
      },
    },
  },
} satisfies TargetManifest;

export const heldOutProfile = createHeldOutProfile(configuredSeed);

export function createHeldOutProfile(seed: string | undefined) {
  const canary = seed ? heldOutCanary(seed) : undefined;
  return createTargetProfile(heldOutManifest, {
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
  });
}

function readPublishedSeed(): string | undefined {
  try {
    const seed = readFileSync(".prototype/held-out-seed", "utf8").trim();
    return seed || undefined;
  } catch {
    return undefined;
  }
}
