import type { ScopedTarget } from "../prototype/scoped-target.ts";
import type { TargetProfile } from "../prototype/target-profile.ts";

interface LoginResponse {
  auth_token?: unknown;
}

async function authenticate(target: ScopedTarget): Promise<{ authContext: string }> {
  if (target.isAuthenticated) return { authContext: "name1" };
  const result = await target.setupRequest({
    path: "/users/v1/login",
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "name1", password: "pass1" }),
  });
  const body = result.body as LoginResponse;
  if (result.status !== 200 || typeof body.auth_token !== "string") {
    throw new Error(`VAmPI fixture-user login failed with status ${result.status}`);
  }
  target.setAuthentication({ authorization: `Bearer ${body.auth_token}` });
  return { authContext: "name1" };
}

const shared = {
  displayName: "VAmPI",
  allowedRequests: [{ method: "POST" as const, path: "/users/v1/login" }],
  deniedRequests: [{ method: "GET" as const, path: "/createdb" }],
  authenticate,
  reproductionAuthentication: {
    description:
      "Log in as VAmPI's name1 fixture user. The target launcher initializes the database.",
    commands: [
      `export QUIVER_TOKEN="$(curl --silent --show-error --fail-with-body --request POST --header 'content-type: application/json' --data '{"username":"name1","password":"pass1"}' "$QUIVER_TARGET/users/v1/login" | jq --raw-output '.auth_token')"`,
      `test -n "$QUIVER_TOKEN" && test "$QUIVER_TOKEN" != "null"`,
    ],
  },
};

export const vampiVulnerableProfile: TargetProfile = {
  ...shared,
  id: "vampi-vulnerable",
  displayName: "VAmPI (vulnerable)",
  objective:
    "Find machine-provable authorization and data-exposure flaws. This vulnerable instance is the positive half of a differential regression oracle.",
};

export const vampiSecureProfile: TargetProfile = {
  ...shared,
  id: "vampi-secure",
  displayName: "VAmPI (secure)",
  objective:
    "Test the same hypotheses as the vulnerable VAmPI instance. Confirmed findings here are differential false positives or vulnerabilities that persist despite secure mode.",
};
