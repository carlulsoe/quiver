import { actorIds } from "../prototype/sessions.ts";
import { createTargetProfile } from "../prototype/target-profile.ts";
import type { TargetManifest } from "../prototype/target-manifest.ts";

export const crapiManifest = {
  schemaVersion: 1,
  id: "crapi",
  displayName: "OWASP crAPI",
  authenticationContext: "ordinary-test-user",
  objective:
    "Find as many distinct read-only vulnerabilities as the request budget supports. Prioritize broken authorization, excessive data exposure, sensitive data exposure, and security misconfiguration. Treat multiple affected resources at the same endpoint as one vulnerability.",
  scope: {
    maximumImpactLevel: "observation",
    setupOperations: [
      { method: "POST", path: "/identity/api/auth/login" },
      { method: "POST", path: "/identity/api/auth/verify" },
    ],
    deniedOperations: [
      { method: "GET", path: "/workshop/api/mechanic/receive_report" },
      { method: "GET", path: "/workshop/api/mechanic/mechanic_report" },
    ],
    protectedOperations: [
      {
        method: "GET",
        path: "/identity/api/v2/user/dashboard",
        authorizedActors: [actorIds.userA],
        description: "A user dashboard must be limited to its authenticated principal.",
      },
    ],
  },
  identities: [
    { id: actorIds.anonymous, label: "Anonymous", role: "anonymous" },
    {
      id: actorIds.userA,
      label: "crAPI user A",
      role: "user",
      authentication: {
        kind: "browser-login",
        login: {
          request: {
            method: "POST",
            path: "/identity/api/auth/login",
            headers: { "content-type": "application/json" },
            body: {
              email: { env: "CRAPI_TEST_EMAIL", default: "test@example.com" },
              password: { env: "CRAPI_TEST_PASSWORD", default: "Test!123" },
            },
          },
          credential: { location: "body", pointer: "/token" },
          expectedStatuses: [200],
        },
        session: {
          headers: { authorization: "Bearer {{credential}}" },
          localStorage: {
            "persist:reducers": JSON.stringify({
              userReducer: JSON.stringify({
                fetchingData: false,
                isLoggedIn: true,
                accessToken: "{{credential}}",
                id: "",
                name: "",
                email: "{{env:CRAPI_TEST_EMAIL|test@example.com}}",
                number: "",
                role: "ROLE_USER",
                available_credit: 0,
                picture_url: "",
                video_url: "",
                video_id: "",
                video_name: "",
              }),
              profileReducer: JSON.stringify({ videoId: "", videoName: "", profilePicData: "" }),
              _persist: JSON.stringify({ version: -1, rehydrated: true }),
            }),
          },
        },
      },
    },
  ],
  reproductionAuthentication: {
    description:
      "Log in as the same user A configured for the campaign. The command uses CRAPI_TEST_EMAIL and CRAPI_TEST_PASSWORD when set, otherwise the manifest defaults.",
    commands: [
      `export QUIVER_TOKEN="$(curl --silent --show-error --fail-with-body --request POST --header 'content-type: application/json' --data '{"email":"'"\${CRAPI_TEST_EMAIL:-test@example.com}"'","password":"'"\${CRAPI_TEST_PASSWORD:-Test!123}"'"}' "$QUIVER_TARGET/identity/api/auth/login" | jq --raw-output '.token')"`,
      `test -n "$QUIVER_TOKEN" && test "$QUIVER_TOKEN" != "null"`,
    ],
  },
} satisfies TargetManifest;

export const crapiProfile = createTargetProfile(crapiManifest);
