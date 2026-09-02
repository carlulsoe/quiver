import { describe, expect, it } from "vitest";
import {
  discoverGraphqlOperations,
  extractOpenApiRequestBodies,
  normalizeAttackSurfaceOrigins,
} from "./attack-surface.ts";

describe("stateful discovery evidence", () => {
  it("separates attackable, visit-only, auth-only, and blocked exact origins", () => {
    const scopes = normalizeAttackSurfaceOrigins("http://127.0.0.1:8888", [
      { origin: "http://127.0.0.1:9000", scope: "visit-only" },
      { origin: "http://127.0.0.1:9001", scope: "attackable" },
      { origin: "http://127.0.0.1:9002", scope: "auth-only" },
      { origin: "http://127.0.0.1:9003", scope: "blocked" },
      { origin: "http://127.0.0.1:8888", scope: "visit-only" },
    ]);

    expect(Object.fromEntries(scopes)).toEqual({
      "http://127.0.0.1:8888": "attackable",
      "http://127.0.0.1:9000": "visit-only",
      "http://127.0.0.1:9001": "attackable",
      "http://127.0.0.1:9002": "auth-only",
      "http://127.0.0.1:9003": "blocked",
    });
    expect(() =>
      normalizeAttackSurfaceOrigins("http://127.0.0.1:8888", [
        { origin: "http://127.0.0.1:9000/app", scope: "visit-only" },
      ]),
    ).toThrow("must not include a path");
  });

  it("derives bounded request examples and multipart fields from OpenAPI schemas", () => {
    const document = {
      components: {
        schemas: {
          Upload: {
            type: "object",
            properties: {
              email: { type: "string", format: "email" },
              count: { type: "integer", minimum: 2 },
              accessToken: { type: "string", example: "must-not-leak" },
              attachment: { type: "string", format: "binary" },
            },
          },
        },
      },
    };

    expect(
      extractOpenApiRequestBodies(
        document,
        {},
        {
          requestBody: {
            content: {
              "multipart/form-data": {
                schema: { $ref: "#/components/schemas/Upload" },
              },
            },
          },
        },
      ),
    ).toEqual([
      {
        contentType: "multipart/form-data",
        source: "openapi",
        example: { email: "quiver@example.invalid", count: 2, accessToken: "[redacted]" },
        fields: ["email", "count", "accessToken"],
        files: [{ field: "attachment" }],
      },
    ]);

    expect(
      extractOpenApiRequestBodies(
        {},
        {},
        {
          requestBody: {
            content: {
              "text/plain": {
                schema: { type: "string", format: "password", example: "must-not-leak" },
              },
            },
          },
        },
      ),
    ).toEqual([{ contentType: "text/plain", source: "openapi", example: "[redacted]" }]);

    expect(
      extractOpenApiRequestBodies(
        {},
        {},
        {
          requestBody: {
            content: {
              "application/json": {
                example: { user: { pin: "must-not-leak", label: "visible" } },
                schema: {
                  type: "object",
                  properties: {
                    user: {
                      type: "object",
                      properties: {
                        pin: { type: "string", "x-sensitive": true },
                        label: { type: "string" },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      ),
    ).toContainEqual({
      contentType: "application/json",
      source: "openapi",
      example: { user: { pin: "[redacted]", label: "visible" } },
    });

    expect(
      extractOpenApiRequestBodies(
        {},
        {},
        {
          requestBody: {
            content: {
              "multipart/form-data": {
                example: { note: "visible", payload: "private file bytes" },
                schema: {
                  allOf: [
                    { type: "object", properties: { note: { type: "string" } } },
                    {
                      type: "object",
                      properties: { payload: { type: "string", format: "binary" } },
                    },
                  ],
                },
              },
            },
          },
        },
      ),
    ).toContainEqual({
      contentType: "multipart/form-data",
      source: "openapi",
      example: { note: "visible", payload: "[file content omitted]" },
      fields: ["note"],
      files: [{ field: "payload" }],
    });
  });

  it("discovers named, anonymous, aliased, and mutation GraphQL operations", () => {
    expect(
      discoverGraphqlOperations(`
        query ReadViewer($id: ID!) {
          viewer { id }
          account: user(id: $id) { email }
        }
        mutation SaveUser { updateUser(input: { name: "ignored" }) { id } }
        { health version status @skip(if: false) }
        query WithFragment { viewer { ...ViewerFields } }
        fragment ViewerFields on User { id email }
        query WithDefault($filter: Filter = { active: true }) { viewer { id } }
      `),
    ).toEqual([
      { type: "query", name: "ReadViewer", rootFields: ["viewer", "user"] },
      { type: "mutation", name: "SaveUser", rootFields: ["updateUser"] },
      { type: "query", rootFields: ["health", "version", "status"] },
      { type: "query", name: "WithFragment", rootFields: ["viewer"] },
      { type: "query", name: "WithDefault", rootFields: ["viewer"] },
    ]);
  });
});
