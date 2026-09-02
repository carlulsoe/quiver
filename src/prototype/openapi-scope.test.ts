import { describe, expect, it } from "vitest";
import { resolveEffectiveOpenApiPrefixes, resolveOpenApiPrefixes } from "./attack-surface.ts";

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
