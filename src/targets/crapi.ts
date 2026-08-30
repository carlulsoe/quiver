import type { ScopedTarget } from "../prototype/scoped-target.ts";
import type { Candidate } from "../prototype/state.ts";
import type { TargetProfile } from "../prototype/target-profile.ts";
import { assessVehicleLocationBola } from "./crapi-validator.ts";

interface LoginResponse {
  token?: unknown;
}

interface VehicleResponse {
  uuid?: unknown;
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

async function validate(target: ScopedTarget, candidate: Candidate) {
  const proofMatch = candidate.proofPath.match(
    /^\/identity\/api\/v2\/vehicle\/([^/?#]+)\/location$/,
  );
  if (!proofMatch) {
    return {
      confirmed: false,
      reason: "invalid-proof-path",
      evidence: "The submitted proof path is not a crAPI vehicle-location route.",
    };
  }
  await authenticate(target);
  const dashboard = await target.request({
    path: "/identity/api/v2/user/dashboard",
    authenticated: true,
  });
  const location = await target.request({ path: candidate.proofPath, authenticated: true });
  return assessVehicleLocationBola(dashboard, location);
}

async function createNegativeControl(target: ScopedTarget): Promise<Candidate> {
  await authenticate(target);
  const result = await target.request({
    path: "/identity/api/v2/vehicle/vehicles",
    authenticated: true,
  });
  const vehicleId = (result.body as VehicleResponse[])[0]?.uuid;
  if (result.status !== 200 || typeof vehicleId !== "string") {
    throw new Error(`could not resolve the test user's vehicle: status=${result.status}`);
  }
  return {
    agentId: "negative-control",
    title: "Authenticated user's own vehicle location",
    category: "BOLA",
    resource: vehicleId,
    sourcePath: "/identity/api/v2/vehicle/vehicles",
    proofPath: `/identity/api/v2/vehicle/${encodeURIComponent(vehicleId)}/location`,
    rationale: "Negative control: this vehicle belongs to the authenticated user.",
  };
}

export const crapiProfile: TargetProfile = {
  id: "crapi",
  displayName: "OWASP crAPI",
  objective:
    "Find one BOLA where an ordinary authenticated user can read another user's vehicle location. Set proofPath to the exact location endpoint tested.",
  allowedRequests: [{ method: "POST", path: "/identity/api/auth/login" }],
  authenticate,
  validate,
  createNegativeControl,
};
