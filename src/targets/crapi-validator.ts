import type { HttpObservation } from "../prototype/scoped-target.ts";

interface DashboardResponse {
  name?: unknown;
  email?: unknown;
}

interface LocationResponse {
  fullName?: unknown;
  vehicleLocation?: { latitude?: unknown; longitude?: unknown };
}

export interface BolaAssessment {
  confirmed: boolean;
  reason:
    | "cross-owner-coordinates"
    | "same-owner"
    | "missing-coordinates"
    | "unproven-owner"
    | "request-failed";
  evidence: string;
  facts: {
    dashboardStatus: number;
    locationStatus: number;
    differentOwner: boolean;
    hasCoordinates: boolean;
  };
}

export function assessVehicleLocationBola(
  dashboard: HttpObservation,
  location: HttpObservation,
): BolaAssessment {
  const dashboardBody = dashboard.body as DashboardResponse;
  const locationBody = location.body as LocationResponse;
  const hasCoordinates =
    typeof locationBody.vehicleLocation?.latitude === "string" &&
    typeof locationBody.vehicleLocation?.longitude === "string";
  const differentOwner =
    typeof dashboardBody.name === "string" &&
    typeof locationBody.fullName === "string" &&
    dashboardBody.name !== locationBody.fullName;
  const confirmed =
    dashboard.status === 200 && location.status === 200 && hasCoordinates && differentOwner;
  const reason: BolaAssessment["reason"] =
    dashboard.status !== 200 || location.status !== 200
      ? "request-failed"
      : !hasCoordinates
        ? "missing-coordinates"
        : typeof dashboardBody.name !== "string" || typeof locationBody.fullName !== "string"
          ? "unproven-owner"
          : differentOwner
            ? "cross-owner-coordinates"
            : "same-owner";
  const evidence = confirmed
    ? `Authenticated as ${String(dashboardBody.email)} (${String(dashboardBody.name)}) but ${location.path} returned coordinates for ${String(locationBody.fullName)}.`
    : `Could not prove cross-owner access: dashboard=${dashboard.status}, location=${location.status}, differentOwner=${differentOwner}, coordinates=${hasCoordinates}.`;

  return {
    confirmed,
    reason,
    evidence,
    facts: {
      dashboardStatus: dashboard.status,
      locationStatus: location.status,
      differentOwner,
      hasCoordinates,
    },
  };
}
