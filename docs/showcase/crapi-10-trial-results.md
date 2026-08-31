# Quiver crAPI repeated-eval results

These are the complete results of a 10-trial run on 2026-08-31—not a selected
subset. Every trial ran in its own process against the pinned crAPI 1.1.5 target
with two worker processes. The run exercised the five-case benchmark,
deterministic proof preflight and replay, two explorers, and a 36-request budget.

The run exposed no recurrence of the original “already-configured Flue runtime”
failure: all ten child processes launched. One model response exceeded the
original 360-second ceiling. The ceiling was raised to 600 seconds afterward;
this changes timeout classification, not the security acceptance contract.

## Aggregate

| Metric                                        |                        Result |
| --------------------------------------------- | ----------------------------: |
| Strict contract passes                        |                          3/10 |
| Strict success rate                           |                         30.0% |
| Infrastructure completion                     |                  9/10 (90.0%) |
| Mean benchmark coverage (completed campaigns) |                         57.8% |
| False or unscored confirmations               |                  4/30 (13.3%) |
| Mean requests / true positive                 |                         12.33 |
| Mean wall duration                            |                        298.4s |
| Approximate known model cost                  | $0.0823 (9/10 reported usage) |
| Mean cost of reported trials                  |                       $0.0091 |

## Per-trial results

| Trial | Result         | Coverage | Precision | False/unscored | Requests / TP | Duration |    Cost |
| ----: | -------------- | -------: | --------: | -------------: | ------------: | -------: | ------: |
|     1 | FAIL           |      40% |      100% |              0 |         15.00 |   277.9s | $0.0082 |
|     2 | FAIL           |      60% |       75% |              1 |         11.33 |   305.7s | $0.0128 |
|     3 | PASS           |      80% |      100% |              0 |          8.75 |   238.3s | $0.0076 |
|     4 | FAIL (timeout) |        — |         — |              — |             — |   360.0s |       — |
|     5 | PASS           |      80% |      100% |              0 |          8.25 |   327.5s | $0.0100 |
|     6 | FAIL           |      40% |     66.7% |              1 |         16.00 |   252.8s | $0.0084 |
|     7 | FAIL           |      60% |       75% |              1 |         11.33 |   183.4s | $0.0063 |
|     8 | FAIL           |      60% |       75% |              1 |         11.33 |   242.7s | $0.0080 |
|     9 | FAIL           |      40% |      100% |              0 |         18.00 |   483.4s | $0.0132 |
|    10 | PASS           |      60% |      100% |              0 |         11.00 |   312.3s | $0.0080 |

Strict acceptance required all of the following:

- at least 50% coverage (three of five grounded cases);
- 100% conservative precision;
- zero safe-control or unscored confirmations;
- an outcome for every submitted finding;
- zero agent failures; and
- request-budget compliance.

## What failed

- Trials 1 and 6 found only two of five grounded cases. Unlike the former
  “more than zero” contract, 40% coverage does not pass.
- Trials 2, 7, and 8 confirmed one claim outside the corpus. These remained
  visible and reduced precision rather than escaping scoring.
- Trial 4 timed out while model work was still active.
- Trial 9 completed the campaign but left four of six findings unvalidated,
  so it failed despite 100% precision among the completed validations.

The unscored audit found one source-backed single-post variant of the existing
community author leak, one endpoint-label mismatch, and two debatable claims
(the current user's vehicle PIN and mechanic directory emails). The first is now
an alias of the existing benchmark case; endpoint/reproduction alignment is now
checked during proof preflight; the debatable claims remain unscored.

## Post-run hardening check

After this baseline, the eval was changed to three complementary explorers and
42 requests, proof preflight was tightened, the source-backed endpoint alias was
added, and the timeout was raised to 600 seconds. A fresh isolated trial on that
configuration passed:

| Metric                       |     Result |
| ---------------------------- | ---------: |
| Strict result                | PASS (1/1) |
| Coverage                     |        60% |
| Precision                    |       100% |
| False/unscored confirmations |          0 |
| Requests / true positive     |      11.67 |
| Duration                     |     443.0s |
| Approximate model cost       |    $0.0141 |

This is evidence of improvement, not a replacement 10-trial claim. Another full
10-trial run is required before claiming the post-hardening success rate.
