import { actorIds } from "../prototype/sessions.ts";
import { createTargetProfile } from "../prototype/target-profile.ts";
import type { TargetManifest } from "../prototype/target-manifest.ts";

export const brokenCrystalsManifest = {
  schemaVersion: 1,
  id: "broken-crystals",
  displayName: "Broken Crystals",
  authenticationContext: "ordinary-test-user",
  objective:
    "Exercise the full browser-backed REST workflow against a large modern application. Prioritize machine-provable broken authorization and sensitive or excessive data exposure; do not execute command, file-write, email, denial-of-service, or other destructive payloads.",
  scope: { setupOperations: [{ method: "POST", path: "/api/auth/login" }] },
  identities: [
    { id: actorIds.anonymous, label: "Anonymous", role: "anonymous" },
    {
      id: actorIds.userA,
      label: "Broken Crystals user A",
      role: "user",
      authentication: {
        kind: "browser-login",
        login: {
          request: {
            method: "POST",
            path: "/api/auth/login",
            headers: { "content-type": "application/json" },
            body: {
              user: { env: "BROKEN_CRYSTALS_TEST_USER", default: "user" },
              password: { env: "BROKEN_CRYSTALS_TEST_PASSWORD", default: "user" },
              op: "basic",
            },
          },
          credential: { location: "header", name: "authorization" },
          expectedStatuses: [201],
        },
        session: {
          headers: { authorization: "{{credential}}" },
          localStorage: { authorization: "{{credential}}" },
          cookies: [{ name: "authorization", value: "{{credential}}", path: "/" }],
        },
      },
    },
  ],
  reproductionAuthentication: {
    description: "Log in as the Broken Crystals user A fixture.",
    commands: [
      `export QUIVER_TOKEN="$(curl --silent --show-error --dump-header - --output /dev/null --request POST --header 'content-type: application/json' --data '{"user":"'"\${BROKEN_CRYSTALS_TEST_USER:-user}"'","password":"'"\${BROKEN_CRYSTALS_TEST_PASSWORD:-user}"'","op":"basic"}' "$QUIVER_TARGET/api/auth/login" | awk 'BEGIN { IGNORECASE=1 } /^authorization:/ { sub(/^[^:]*:[[:space:]]*/, ""); sub(/\\r$/, ""); print; exit }')"`,
      `test -n "$QUIVER_TOKEN"`,
    ],
  },
} satisfies TargetManifest;

export const brokenCrystalsProfile = createTargetProfile(brokenCrystalsManifest);
