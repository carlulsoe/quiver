import { describe, expect, it } from "vitest";
import { compareVampiPair } from "./vampi-oracle.ts";

describe("VAmPI vulnerable/secure differential oracle", () => {
  it("separates vulnerable-only detections from secure-instance confirmations", () => {
    const bola = {
      category: "broken-object-authorization" as const,
      endpoint: "/books/v1/foreign-title",
      method: "GET" as const,
    };
    const exposure = {
      category: "sensitive-data-exposure" as const,
      endpoint: "/users/v1/_debug",
      method: "GET" as const,
    };
    const score = compareVampiPair([bola, exposure], [exposure]);

    expect(score).toMatchObject({
      vulnerableOnlyCount: 1,
      secureAlsoCount: 1,
      secureOnlyCount: 0,
      vulnerableOnly: ["broken-object-authorization:GET:/books/v1/foreign-title"],
      secureAlso: ["sensitive-data-exposure:GET:/users/v1/_debug"],
      secureOnly: [],
    });
  });

  it("deduplicates confirmations while retaining secure-only findings", () => {
    const vulnerableOnly = {
      category: "broken-object-authorization" as const,
      endpoint: "/books/v1/foreign-title/",
      method: "GET" as const,
    };
    const secureOnly = {
      category: "security-misconfiguration" as const,
      endpoint: "/users/v1",
      method: "POST" as const,
    };

    expect(compareVampiPair([vulnerableOnly, vulnerableOnly], [secureOnly])).toMatchObject({
      vulnerableOnlyCount: 1,
      secureAlsoCount: 0,
      secureOnlyCount: 1,
      vulnerableOnly: ["broken-object-authorization:GET:/books/v1/foreign-title"],
      secureOnly: ["security-misconfiguration:POST:/users/v1"],
    });
  });
});
