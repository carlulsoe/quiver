import { describe, expect, it } from "vitest";
import { redactCredentials, redactStructuredCredentials } from "./redaction.ts";

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
      pin: 200,
      otp: 7,
      token: false,
      counter: 7,
      diagnosticValue: 7,
      enabled: false,
      passed: false,
      status: 200,
      narrative: "Observed PIN 200, OTP 7, and token false.",
      benign: "build-2000 returned HTTP 201 with structure intact",
    });

    expect(redacted).toEqual({
      pin: "[REDACTED]",
      otp: "[REDACTED]",
      token: "[REDACTED]",
      counter: "[REDACTED]",
      diagnosticValue: "[REDACTED]",
      enabled: "[REDACTED]",
      passed: "[REDACTED]",
      status: "[REDACTED]",
      narrative: "Observed PIN [REDACTED], OTP [REDACTED], and token [REDACTED].",
      benign: "build-2000 returned HTTP 201 with structure intact",
    });
  });

  it("preserves typed schema fields while redacting equal values in raw payloads", () => {
    const redacted = redactStructuredCredentials({
      status: 200,
      counter: 7,
      truncated: false,
      redirected: false,
      checks: [{ passed: false, actual: 200 }],
      body: {
        pin: 200,
        otp: 7,
        token: false,
        status: 200,
        diagnosticValue: 200,
        counter: 7,
        enabled: false,
      },
      narrative: "Observed PIN 200, OTP 7, and token false.",
    });

    expect(redacted).toEqual({
      status: 200,
      counter: 7,
      truncated: false,
      redirected: false,
      checks: [{ passed: false, actual: "[REDACTED]" }],
      body: {
        pin: "[REDACTED]",
        otp: "[REDACTED]",
        token: "[REDACTED]",
        status: "[REDACTED]",
        diagnosticValue: "[REDACTED]",
        counter: "[REDACTED]",
        enabled: "[REDACTED]",
      },
      narrative: "Observed PIN [REDACTED], OTP [REDACTED], and token [REDACTED].",
    });
  });
});
