import { describe, expect, it } from "vitest";
import {
  discoverGraphqlOperations,
  extractOpenApiRequestBodies,
  normalizeAttackSurfaceOrigins,
  resolveEffectiveOpenApiPrefixes,
  resolveOpenApiPrefixes,
} from "./attack-surface.ts";

describe("OpenAPI server scope", () => {
  const origin = "http://127.0.0.1:8888";

  it("uses relative paths only when no servers are declared", () => {
    expect(resolveOpenApiPrefixes({}, origin)).toEqual([""]);
    expect(resolveOpenApiPrefixes({ servers: [] }, origin)).toEqual([]);
  });

  it("accepts same-origin prefixes and rejects foreign or variable servers", () => {
    expect(
      resolveOpenApiPrefixes({ servers: [{ url: "http://127.0.0.1:8888/api/v1" }] }, origin),
    ).toEqual(["/api/v1"]);
    expect(
      resolveOpenApiPrefixes({ servers: [{ url: "https://api.example.com/v1" }] }, origin),
    ).toEqual([]);
    expect(
      resolveOpenApiPrefixes({ servers: [{ url: "https://{tenant}.example.com" }] }, origin),
    ).toEqual([]);
  });

  it("honors the origin declared by Swagger 2 documents", () => {
    expect(
      resolveOpenApiPrefixes(
        { swagger: "2.0", host: "127.0.0.1:8888", schemes: ["http"], basePath: "/api" },
        origin,
      ),
    ).toEqual(["/api"]);
    expect(
      resolveOpenApiPrefixes(
        { swagger: "2.0", host: "api.example.com", schemes: ["https"], basePath: "/api" },
        origin,
      ),
    ).toEqual([]);
    expect(
      resolveOpenApiPrefixes(
        { swagger: "2.0", host: "api.example.com", schemes: ["https"] },
        origin,
      ),
    ).toEqual([]);
  });

  it("applies path and operation server overrides", () => {
    const document = { servers: [{ url: "http://127.0.0.1:8888/root" }] };
    expect(
      resolveEffectiveOpenApiPrefixes(
        document,
        { servers: [{ url: "https://api.example.com/path" }] },
        {},
        origin,
      ),
    ).toEqual([]);
    expect(
      resolveEffectiveOpenApiPrefixes(
        document,
        { servers: [{ url: "https://api.example.com/path" }] },
        { servers: [{ url: "/operation" }] },
        origin,
      ),
    ).toEqual(["/operation"]);
  });
});

describe("stateful discovery evidence", () => {
  it("separates attackable and visit-only exact origins", () => {
    const scopes = normalizeAttackSurfaceOrigins("http://127.0.0.1:8888", [
      { origin: "http://127.0.0.1:9000", scope: "visit-only" },
      { origin: "http://127.0.0.1:9001", scope: "attackable" },
      { origin: "http://127.0.0.1:8888", scope: "visit-only" },
    ]);

    expect(Object.fromEntries(scopes)).toEqual({
      "http://127.0.0.1:8888": "attackable",
      "http://127.0.0.1:9000": "visit-only",
      "http://127.0.0.1:9001": "attackable",
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
