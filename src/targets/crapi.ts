import type { ScopedTarget } from "../prototype/scoped-target.ts";
import type { TargetProfile } from "../prototype/target-profile.ts";

interface LoginResponse {
  token?: unknown;
}

async function authenticate(target: ScopedTarget): Promise<{ authContext: string }> {
  if (target.isAuthenticated) return { authContext: "ordinary-test-user" };

  const result = await target.request({
    path: "/identity/api/auth/login",
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email: process.env.CRAPI_TEST_EMAIL ?? "test@example.com",
      password: process.env.CRAPI_TEST_PASSWORD ?? "Test!123",
    }),
  });
  const body = result.body as LoginResponse;
  if (result.status !== 200 || typeof body.token !== "string") {
    throw new Error(`crAPI test-user login failed with status ${result.status}`);
  }
  target.setAuthentication({ authorization: `Bearer ${body.token}` });
  target.setBrowserLocalStorage({
    "persist:reducers": JSON.stringify({
      userReducer: JSON.stringify({
        fetchingData: false,
        isLoggedIn: true,
        accessToken: body.token,
        id: "",
        name: "",
        email: process.env.CRAPI_TEST_EMAIL ?? "test@example.com",
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
  });
  return { authContext: "ordinary-test-user" };
}

export const crapiProfile: TargetProfile = {
  id: "crapi",
  displayName: "OWASP crAPI",
  objective:
    "Find as many distinct read-only vulnerabilities as the request budget supports. Prioritize broken authorization, excessive data exposure, sensitive data exposure, and security misconfiguration. Treat multiple affected resources at the same endpoint as one vulnerability.",
  allowedRequests: [
    { method: "POST", path: "/identity/api/auth/login" },
    { method: "POST", path: "/identity/api/auth/verify" },
  ],
  deniedRequests: [
    { method: "GET", path: "/workshop/api/mechanic/receive_report" },
    { method: "GET", path: "/workshop/api/mechanic/mechanic_report" },
  ],
  authenticate,
  reproductionAuthentication: {
    description:
      "Log in as the same ordinary test user configured for the campaign. The command uses CRAPI_TEST_EMAIL and CRAPI_TEST_PASSWORD when set, otherwise the profile defaults.",
    commands: [
      `export QUIVER_TOKEN="$(curl --silent --show-error --fail-with-body --request POST --header 'content-type: application/json' --data '{"email":"'"\${CRAPI_TEST_EMAIL:-test@example.com}"'","password":"'"\${CRAPI_TEST_PASSWORD:-Test!123}"'"}' "$QUIVER_TARGET/identity/api/auth/login" | jq --raw-output '.token')"`,
      `test -n "$QUIVER_TOKEN" && test "$QUIVER_TOKEN" != "null"`,
    ],
  },
};
