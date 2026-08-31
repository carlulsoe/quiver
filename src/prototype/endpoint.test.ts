import { describe, expect, it } from "vitest";
import { endpointMatchesRequest, normalizeEndpoint } from "./endpoint.ts";

describe("endpoint normalization", () => {
  it.each([
    ["/api/items/42/", "/api/items/{id}"],
    ["/api/items/<itemId>", "/api/items/{id}"],
    ["/api/items/{itemId}?include=owner", "/api/items/{id}"],
    ["/", "/"],
  ])("canonicalizes %s as %s", (endpoint, expected) => {
    expect(normalizeEndpoint(endpoint)).toBe(expected);
  });

  it.each([
    ["/fetch/{name}", "/fetch/report"],
    ["/fetch/<name>", "/fetch/report"],
    ["/fetch/:name", "/fetch/report"],
  ])("matches template %s to concrete slug %s", (endpoint, request) => {
    expect(endpointMatchesRequest(endpoint, request)).toBe(true);
  });
});
