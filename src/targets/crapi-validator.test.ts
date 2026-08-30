import { describe, expect, it } from "vitest";
import { assessVehicleLocationBola } from "./crapi-validator.ts";

describe("vehicle-location BOLA assessment", () => {
  it("confirms coordinates returned for a different owner", () => {
    expect(
      assessVehicleLocationBola(
        {
          status: 200,
          path: "/identity/api/v2/user/dashboard",
          body: { email: "test@example.com", name: "Test" },
        },
        {
          status: 200,
          path: "/identity/api/v2/vehicle/other/location",
          body: {
            fullName: "Robot",
            vehicleLocation: { latitude: "40.1", longitude: "-74.2" },
          },
        },
      ),
    ).toEqual({
      confirmed: true,
      reason: "cross-owner-coordinates",
      evidence:
        "Authenticated as test@example.com (Test) but /identity/api/v2/vehicle/other/location returned coordinates for Robot.",
      facts: {
        dashboardStatus: 200,
        locationStatus: 200,
        differentOwner: true,
        hasCoordinates: true,
      },
    });
  });

  it("classifies the authenticated user's own vehicle as a safe control", () => {
    const result = assessVehicleLocationBola(
      {
        status: 200,
        path: "/identity/api/v2/user/dashboard",
        body: { email: "test@example.com", name: "Test" },
      },
      {
        status: 200,
        path: "/identity/api/v2/vehicle/own/location",
        body: {
          fullName: "Test",
          vehicleLocation: { latitude: "40.1", longitude: "-74.2" },
        },
      },
    );

    expect(result.confirmed).toBe(false);
    expect(result.reason).toBe("same-owner");
  });
});
