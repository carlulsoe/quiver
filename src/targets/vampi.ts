import { actorIds } from "../prototype/sessions.ts";
import { createTargetProfile } from "../prototype/target-profile.ts";
import type { TargetManifest } from "../prototype/target-manifest.ts";

const shared = {
  schemaVersion: 1,
  displayName: "VAmPI",
  authenticationContext: "name1",
  scope: {
    setupOperations: [{ method: "POST", path: "/users/v1/login" }],
    deniedOperations: [{ method: "GET", path: "/createdb" }],
    protectedOperations: [
      {
        method: "GET",
        path: "/users/v1/{id}",
        authorizedActors: [actorIds.userA],
        description: "User records must enforce object ownership.",
      },
    ],
  },
  identities: [
    { id: actorIds.anonymous, label: "Anonymous", role: "anonymous" },
    {
      id: actorIds.userA,
      label: "VAmPI user A",
      role: "user",
      authentication: {
        kind: "header-token",
        login: {
          request: {
            method: "POST",
            path: "/users/v1/login",
            headers: { "content-type": "application/json" },
            body: { username: "name1", password: "pass1" },
          },
          credential: { location: "body", pointer: "/auth_token" },
          expectedStatuses: [200],
        },
      },
    },
  ],
  reproductionAuthentication: {
    description: "Log in as VAmPI's user A fixture. The target launcher initializes the database.",
    commands: [
      `export QUIVER_TOKEN="$(curl --silent --show-error --fail-with-body --request POST --header 'content-type: application/json' --data '{"username":"name1","password":"pass1"}' "$QUIVER_TARGET/users/v1/login" | jq --raw-output '.auth_token')"`,
      `test -n "$QUIVER_TOKEN" && test "$QUIVER_TOKEN" != "null"`,
    ],
  },
} satisfies Omit<TargetManifest, "id" | "objective">;

export const vampiVulnerableManifest = {
  ...shared,
  id: "vampi-vulnerable",
  displayName: "VAmPI (vulnerable)",
  objective:
    "Find machine-provable authorization and data-exposure flaws. This vulnerable instance is the positive half of a differential regression oracle.",
} satisfies TargetManifest;

export const vampiSecureManifest = {
  ...shared,
  id: "vampi-secure",
  displayName: "VAmPI (secure)",
  objective:
    "Test the same hypotheses as the vulnerable VAmPI instance. Confirmed findings here are differential false positives or vulnerabilities that persist despite secure mode.",
} satisfies TargetManifest;

export const vampiVulnerableProfile = createTargetProfile(vampiVulnerableManifest);
export const vampiSecureProfile = createTargetProfile(vampiSecureManifest);
