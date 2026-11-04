# Risk-band calibration

Generated 2026-11-04T15:38:19+00:00. Software: {'python': '3.12.0', 'numpy': '2.4.6', 'scikit_learn': '1.7.2'}.

**Synthetic runs only.** Run labels are the generator's own: a scenario is malicious by construction. There are two benign scenarios. Test seeds are drawn from the same generators as the validation seeds, so test figures are optimistic about unseen behaviour. The risk score is a heuristic. These thresholds are an operating point on synthetic runs, not a calibrated probability. Not validated on real employees, real incidents or a live banking environment.

## Selected operating point

| Band | Threshold (risk score) | Independent stages needed | False-flag budget (benign validation runs) |
|---|---|---|---|
| Watch | 37 | none | 25% |
| Elevated | 37 | 2 | 5% |
| Alert | 37 | 3 | 0% |

Anomaly-model corroboration threshold: 0.45.

Rule: lowest threshold whose false-flag rate on benign validation runs is within the band's budget. Chosen on 96 validation runs (72 malicious, 24 benign), seeds 1000-1011.

## Validation (used to choose the thresholds)

96 runs: 72 malicious, 24 benign.

| Band | Threshold | Detected | Missed | False flags | Correct benign | Miss rate | False-flag rate |
|---|---|---|---|---|---|---|---|
| Watch | 37 | 67 | 5 | 6 | 18 | 6.9% | 25.0% |
| Elevated | 37 | 35 | 37 | 0 | 24 | 51.4% | 0.0% |
| Alert | 37 | 22 | 50 | 0 | 24 | 69.4% | 0.0% |

| Scenario | Kind | Runs | Watch | Elevated | Alert |
|---|---|---|---|---|---|
| benign_activity | benign | 12 | 0 | 0 | 0 |
| benign_bulk_transfer | benign | 12 | 6 | 0 | 0 |
| bulk_export | malicious | 12 | 12 | 11 | 4 |
| compromised_account_campaign | malicious | 12 | 12 | 12 | 12 |
| correlated_low_signals | malicious | 12 | 12 | 0 | 0 |
| gradual_collection_staging | malicious | 12 | 12 | 0 | 0 |
| removable_media | malicious | 12 | 7 | 0 | 0 |
| suspicious_external_transfer | malicious | 12 | 12 | 12 | 6 |

Early warning: 18 of 22 malicious runs that reached the Alert band did so before the target's final scored event.

## Held-out test (never used to choose anything)

96 runs: 72 malicious, 24 benign.

| Band | Threshold | Detected | Missed | False flags | Correct benign | Miss rate | False-flag rate |
|---|---|---|---|---|---|---|---|
| Watch | 37 | 67 | 5 | 9 | 15 | 6.9% | 37.5% |
| Elevated | 37 | 35 | 37 | 0 | 24 | 51.4% | 0.0% |
| Alert | 37 | 23 | 49 | 0 | 24 | 68.1% | 0.0% |

| Scenario | Kind | Runs | Watch | Elevated | Alert |
|---|---|---|---|---|---|
| benign_activity | benign | 12 | 0 | 0 | 0 |
| benign_bulk_transfer | benign | 12 | 9 | 0 | 0 |
| bulk_export | malicious | 12 | 12 | 11 | 8 |
| compromised_account_campaign | malicious | 12 | 12 | 12 | 12 |
| correlated_low_signals | malicious | 12 | 12 | 0 | 0 |
| gradual_collection_staging | malicious | 12 | 12 | 0 | 0 |
| removable_media | malicious | 12 | 7 | 0 | 0 |
| suspicious_external_transfer | malicious | 12 | 12 | 12 | 3 |

Early warning: 18 of 23 malicious runs that reached the Alert band did so before the target's final scored event.

## Trade-off for the Alert band (validation)

| Threshold | Missed detections | False flags on benign runs |
|---|---|---|
| 0 | 69.4% (50) | 0.0% (0) |
| 5 | 69.4% (50) | 0.0% (0) |
| 10 | 69.4% (50) | 0.0% (0) |
| 15 | 69.4% (50) | 0.0% (0) |
| 20 | 69.4% (50) | 0.0% (0) |
| 25 | 69.4% (50) | 0.0% (0) |
| 30 | 69.4% (50) | 0.0% (0) |
| 35 | 69.4% (50) | 0.0% (0) |
| 40 | 69.4% (50) | 0.0% (0) |
| 45 | 69.4% (50) | 0.0% (0) |
| 50 | 69.4% (50) | 0.0% (0) |
| 55 | 69.4% (50) | 0.0% (0) |
| 60 | 69.4% (50) | 0.0% (0) |
| 65 | 69.4% (50) | 0.0% (0) |
| 70 | 69.4% (50) | 0.0% (0) |
| 75 | 75.0% (54) | 0.0% (0) |
| 80 | 75.0% (54) | 0.0% (0) |
| 85 | 75.0% (54) | 0.0% (0) |
| 90 | 79.2% (57) | 0.0% (0) |
| 95 | 86.1% (62) | 0.0% (0) |
| 100 | 100.0% (72) | 0.0% (0) |

Raising a threshold removes false flags and adds missed detections; the table shows where this project's synthetic runs sit on that curve. The same thresholds applied to the test runs:

| Threshold | Missed detections | False flags on benign runs |
|---|---|---|
| 0 | 68.1% (49) | 0.0% (0) |
| 5 | 68.1% (49) | 0.0% (0) |
| 10 | 68.1% (49) | 0.0% (0) |
| 15 | 68.1% (49) | 0.0% (0) |
| 20 | 68.1% (49) | 0.0% (0) |
| 25 | 68.1% (49) | 0.0% (0) |
| 30 | 68.1% (49) | 0.0% (0) |
| 35 | 68.1% (49) | 0.0% (0) |
| 40 | 68.1% (49) | 0.0% (0) |
| 45 | 68.1% (49) | 0.0% (0) |
| 50 | 68.1% (49) | 0.0% (0) |
| 55 | 68.1% (49) | 0.0% (0) |
| 60 | 68.1% (49) | 0.0% (0) |
| 65 | 68.1% (49) | 0.0% (0) |
| 70 | 68.1% (49) | 0.0% (0) |
| 75 | 76.4% (55) | 0.0% (0) |
| 80 | 76.4% (55) | 0.0% (0) |
| 85 | 79.2% (57) | 0.0% (0) |
| 90 | 81.9% (59) | 0.0% (0) |
| 95 | 88.9% (64) | 0.0% (0) |
| 100 | 100.0% (72) | 0.0% (0) |

## Findings

* Elevated: the budget alone allowed a threshold of 0; it was raised to 37 so the bands stay ordered. For this band the independent-stage requirement, not the score threshold, is what separates benign runs from malicious ones.
* Alert: the budget alone allowed a threshold of 0; it was raised to 37 so the bands stay ordered. For this band the independent-stage requirement, not the score threshold, is what separates benign runs from malicious ones.
* Watch: the false-flag rate on held-out test runs (37.5%) exceeds the budget (25%) that held on validation (25.0%); a budget met on validation does not guarantee it on new seeds.
* Watch: 67 of 72 malicious test runs detected (93%); 5 missed; 9 of 24 benign runs flagged.
* Elevated: 35 of 72 malicious test runs detected (49%); 37 missed; 0 of 24 benign runs flagged.
* Alert: 23 of 72 malicious test runs detected (32%); 49 missed; 0 of 24 benign runs flagged.

For comparison, the earlier hand-picked thresholds ({'suspicious': 25, 'high_risk': 50, 'critical': 80}) on the same test runs: Watch: 67/72 detected, 12/24 false flags; Elevated: 35/72 detected, 0/24 false flags; Alert: 17/72 detected, 0/24 false flags.
