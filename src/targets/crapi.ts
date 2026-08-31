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
  return { authContext: "ordinary-test-user" };
}

export const crapiProfile: TargetProfile = {
  id: "crapi",
  displayName: "OWASP crAPI",
  objective:
    "Find as many distinct read-only vulnerabilities as the request budget supports. Prioritize broken authorization, excessive data exposure, sensitive data exposure, and security misconfiguration. Treat multiple affected resources at the same endpoint as one vulnerability.",
  allowedRequests: [{ method: "POST", path: "/identity/api/auth/login" }],
  deniedRequests: [
    { method: "GET", path: "/workshop/api/mechanic/receive_report" },
    { method: "GET", path: "/workshop/api/mechanic/mechanic_report" },
  ],
  authenticate,
};
