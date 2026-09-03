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

  it("redacts short credentials and credential containers without corrupting benign text", () => {
    const redacted = redactCredentials({
      pin: "123",
      narrative: "Observed PIN 123.",
      benign: "build-1234 returned HTTP 200",
      tokens: ["array-token-sentinel"],
      credentials: { primary: { value: "nested-credential-sentinel" } },
      summary: "Compared array-token-sentinel with nested-credential-sentinel.",
    });

    expect(redacted).toEqual({
      pin: "[REDACTED]",
      narrative: "Observed PIN [REDACTED].",
      benign: "build-1234 returned HTTP 200",
      tokens: "[REDACTED]",
      credentials: "[REDACTED]",
      summary: "Compared [REDACTED] with [REDACTED].",
    });
  });

  it("correlates numeric and boolean credential scalars without redacting adjacent numbers", () => {
    const redacted = redactCredentials({
      pin: 123,
      otp: 456,
      token: true,
      measurement: 123,
      enabled: true,
      passed: true,
      status: 200,
      narrative: "Observed PIN 123, OTP 456, and token true.",
      benign: "build-1234 returned HTTP 200 with structure intact",
    });

    expect(redacted).toEqual({
      pin: "[REDACTED]",
      otp: "[REDACTED]",
      token: "[REDACTED]",
      measurement: "[REDACTED]",
      enabled: "[REDACTED]",
      passed: true,
      status: 200,
      narrative: "Observed PIN [REDACTED], OTP [REDACTED], and token [REDACTED].",
      benign: "build-1234 returned HTTP 200 with structure intact",
    });
  });
});
