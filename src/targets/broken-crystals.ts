import type { ScopedTarget } from "../prototype/scoped-target.ts";
import type { TargetProfile } from "../prototype/target-profile.ts";
import { actorIds } from "../prototype/sessions.ts";

async function authenticate(target: ScopedTarget): Promise<{ authContext: string }> {
  const user = process.env.BROKEN_CRYSTALS_TEST_USER ?? "user";
  const password = process.env.BROKEN_CRYSTALS_TEST_PASSWORD ?? "user";
  const result = await target.setupRequest({
    path: "/api/auth/login",
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ user, password, op: "basic" }),
  });
  const token = result.headers.authorization;
  if (result.status !== 201 || !token) {
    throw new Error(`Broken Crystals test-user login failed with status ${result.status}`);
  }
  target.setSession(actorIds.ordinary, {
    headers: { authorization: token },
    browserState: {
      localStorage: { authorization: token },
      cookies: [{ name: "authorization", value: token, path: "/" }],
    },
  });
  return { authContext: "ordinary-test-user" };
}

export const brokenCrystalsProfile: TargetProfile = {
  id: "broken-crystals",
  displayName: "Broken Crystals",
  objective:
    "Exercise the full browser-backed REST workflow against a large modern application. Prioritize machine-provable broken authorization and sensitive or excessive data exposure; do not execute command, file-write, email, denial-of-service, or other destructive payloads.",
  allowedRequests: [{ method: "POST", path: "/api/auth/login" }],
  authenticate,
  actorIds: [actorIds.ordinary],
  reproductionAuthentication: {
    description: "Log in as the ordinary Broken Crystals fixture user.",
    commands: [
      `export QUIVER_TOKEN="$(curl --silent --show-error --dump-header - --output /dev/null --request POST --header 'content-type: application/json' --data '{"user":"'"\${BROKEN_CRYSTALS_TEST_USER:-user}"'","password":"'"\${BROKEN_CRYSTALS_TEST_PASSWORD:-user}"'","op":"basic"}' "$QUIVER_TARGET/api/auth/login" | awk 'BEGIN { IGNORECASE=1 } /^authorization:/ { sub(/^[^:]*:[[:space:]]*/, ""); sub(/\\r$/, ""); print; exit }')"`,
      `test -n "$QUIVER_TOKEN"`,
    ],
  },
};
