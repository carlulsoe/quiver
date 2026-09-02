import type { BrowserChallengeMutation } from "./state.ts";
import type { BrowserEffectProofPolicy } from "./target-profile-types.ts";

export function sameChallenge(
  left: BrowserChallengeMutation,
  right: BrowserChallengeMutation,
): boolean {
  return (
    left.location === right.location &&
    left.parameter === right.parameter &&
    left.template === right.template
  );
}

export function browserPolicyPath(policy: BrowserEffectProofPolicy, marker: string): string {
  if (!policy.pageChallenge) return policy.pagePath;
  if (
    !["query", "fragment"].includes(policy.pageChallenge.location) ||
    policy.pageChallenge.template.split("{{challenge}}").length !== 2
  ) {
    throw new Error("Browser page challenge must be one URL substitution");
  }
  const url = new URL(policy.pagePath, "http://browser-policy.invalid");
  if (browserChallengeValues(policy.pagePath, policy.pageChallenge).length !== 1) {
    throw new Error("Browser policy pagePath must contain its challenge URL parameter once");
  }
  setBrowserChallenge(
    url,
    policy.pageChallenge,
    policy.pageChallenge.template.replace("{{challenge}}", marker),
  );
  return `${url.pathname}${url.search}${url.hash}`;
}

export function browserChallengeValues(
  path: string,
  challenge: BrowserChallengeMutation,
): string[] {
  const url = new URL(path, "http://browser-policy.invalid");
  if (challenge.location === "query") return url.searchParams.getAll(challenge.parameter);
  if (challenge.location !== "fragment") return [];
  return new URLSearchParams(url.hash.slice(1)).getAll(challenge.parameter);
}

export function setBrowserChallenge(
  url: URL,
  challenge: BrowserChallengeMutation,
  value: string,
): void {
  if (challenge.location === "query") {
    url.searchParams.set(challenge.parameter, value);
    return;
  }
  const fragment = new URLSearchParams(url.hash.slice(1));
  fragment.set(challenge.parameter, value);
  url.hash = fragment.toString();
}

export function safePolicyRegex(pattern: string): RegExp | undefined {
  if (pattern.length > 256) return undefined;
  try {
    return new RegExp(pattern, "i");
  } catch {
    return undefined;
  }
}

export function isAbsoluteHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && url.href === value;
  } catch {
    return false;
  }
}

export function isExactOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) && `${url.origin}` === value;
  } catch {
    return false;
  }
}

export function isOriginRelativePath(value: string): boolean {
  return value.startsWith("/") && !value.startsWith("//");
}
