export const verificationInstructions = `Every finding must declare a machine-checkable proof predicate using zero-based reproduction request indexes and RFC 6901 JSON pointers into parsed response bodies:
- cross-principal-access: identify the named actor and the accessed resource owner in replay responses; they must differ, the access response must succeed, and each evidence pointer must exist in that access response.
- authentication-bypass: replay the same protected operation once as an actor authorized by the target manifest and once anonymously. Both requests must succeed and return matching scalar evidence fields.
- role-privilege-differential: replay the same protected operation as an authorized higher-role actor and an unauthorized lower-role actor. Both requests must succeed and return matching scalar evidence fields. Use this for missing function-level authorization, or for a POST/PUT/PATCH cross-role business action.
- unauthenticated-success: identify an anonymous request whose successful response contains each declared evidence field.
- cross-principal-data-exposure: identify the named actor and a different subject whose fields appear in the successful response, plus every concrete exposed field.
- internal-field-exposure: identify a successful response and implementation-only fields whose presence alone violates the response contract. Use this only for unmistakable internal/debug/configuration properties—not normal fields from the caller's own resource.
- canary-retrieval: select a value from a replay response that matches a target-owned canary policy.
- file-content-retrieval: match a raw, non-JSON response body and media type against a verifier-only immutable-file policy; the request must contain the exact policy-owned traversal value.
- redirect-destination: require one manual HTTP redirect response whose Location exactly equals the policy destination; redirects are never followed automatically.
- sql-semantic-differential: replay the target policy's exact false/true SQL predicates and select the control and probe requests. Both responses must match the target-owned semantic values while the requests differ only by that mutation.
- command-execution-challenge: use the target policy's bounded arithmetic command template and declare its integer challenge. Confirmation replaces it with a fresh challenge and requires the computed output, which is never present in the request; generic OAST callbacks cannot satisfy this proof.
- state-transition: identify before, protected transition, and after requests matching a target-owned state policy. Use distinct sampleIds on otherwise identical before/after reads.
- browser-visible-effect: use the policy's explicit stored-write or fragment-only DOM workflow and a fresh browser artifact.
- browser-state-transition: identify exact before/after reads around a cookie-authenticated mutation initiated by a configured cross-origin policy page.
- oast-callback is SSRF-only network-request evidence. It can never prove command execution; command-execution-challenge is the only command-execution predicate.

Choose a predicate compatible with the vulnerability-specific category and point only to values you observed. Categories with no compatible authoritative predicate cannot yet be submitted. submit_finding first runs the predicate against exploration observations; inspect failed deterministicProof checks before resubmitting. The same predicate must later pass against a fresh replay, and the deterministic result—not the validation model's opinion—decides confirmation.`;
