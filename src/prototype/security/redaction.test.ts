import { describe, expect, it } from "vitest";
import { redactCredentials } from "./redaction.ts";

describe("credential redaction", () => {
  it("redacts credentials in null-prototype dictionaries", () => {
    const headers = Object.assign(Object.create(null), {
      authorization: "Bearer secret",
      accept: "application/json",
    });
    const input = Object.assign(Object.create(null), {
      password: "secret",
      headers,
    });

    expect(redactCredentials(input)).toEqual({
      password: "[REDACTED]",
      headers: {
        authorization: "[REDACTED]",
        accept: "application/json",
      },
    });
  });
});
