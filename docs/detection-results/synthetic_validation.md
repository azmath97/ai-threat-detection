**synthetic - validation split** - one window = one user on one calendar day; alerts are scored at the end of the day

alert threshold per model = benign VALIDATION quantile giving false-positive rate 0.005

Destination-category enrichment: enabled

Evaluated: 4,508 labelled windows from 60 users, 37 malicious windows from 15 insiders.

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN | ROC-AUC | AP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| iforest_raw | 0.324 | 0.297 | 0.310 | 0.0051 | 0.703 | 11 | 23 | 26 | 4448 | 0.848 | 0.204 |
| iforest_deviation | 0.405 | 0.405 | 0.405 | 0.0049 | 0.595 | 15 | 22 | 22 | 4449 | 0.942 | 0.428 |
| lof_deviation | 0.489 | 0.595 | 0.537 | 0.0051 | 0.405 | 22 | 23 | 15 | 4448 | 0.967 | 0.659 |
| robust_z_own | 0.465 | 0.540 | 0.500 | 0.0051 | 0.460 | 20 | 23 | 17 | 4448 | 0.873 | 0.457 |
| supervised_gbm_reference | 0.617 | 1.000 | 0.763 | 0.0051 | 0.000 | 37 | 23 | 0 | 4448 | 1.000 | 0.986 |
| rules_correlation | 0.477 | 0.568 | 0.518 | 0.0051 | 0.432 | 21 | 23 | 16 | 4448 | 0.977 | 0.664 |
| hybrid | 0.477 | 0.568 | 0.518 | 0.0051 | 0.432 | 21 | 23 | 16 | 4448 | 0.985 | 0.639 |

Recall at fixed validation false-positive rates (threshold from validation, applied to the evaluated split):

| Model | recall @0.1% FPR | recall @0.5% FPR | recall @1% FPR |
|---|---|---|---|
| iforest_raw | 0.081 (obs. FPR 0.00112) | 0.297 (obs. FPR 0.00514) | 0.460 (obs. FPR 0.01006) |
| iforest_deviation | 0.297 (obs. FPR 0.00067) | 0.405 (obs. FPR 0.00492) | 0.460 (obs. FPR 0.01006) |
| lof_deviation | 0.568 (obs. FPR 0.00112) | 0.595 (obs. FPR 0.00514) | 0.703 (obs. FPR 0.01006) |
| robust_z_own | 0.243 (obs. FPR 0.00067) | 0.540 (obs. FPR 0.00514) | 0.540 (obs. FPR 0.01006) |
| supervised_gbm_reference | 0.946 (obs. FPR 0.00112) | 1.000 (obs. FPR 0.00514) | 1.000 (obs. FPR 0.01006) |
| rules_correlation | 0.540 (obs. FPR 0.00112) | 0.568 (obs. FPR 0.00514) | 0.784 (obs. FPR 0.01006) |
| hybrid | 0.540 (obs. FPR 0.00112) | 0.568 (obs. FPR 0.00514) | 0.784 (obs. FPR 0.01006) |

Per-scenario window recall (share of malicious windows that raised an alert):

| Model | account_misuse | bulk_export | gradual_data_collection | multi_stage_sequence | removable_media_exfiltration |
|---|---|---|---|---|---|
| iforest_raw | 1.000 | 0.000 | 0.000 | 1.000 | 0.467 |
| iforest_deviation | 0.000 | 0.000 | 0.000 | 1.000 | 0.867 |
| lof_deviation | 1.000 | 1.000 | 0.062 | 1.000 | 1.000 |
| robust_z_own | 1.000 | 1.000 | 0.000 | 1.000 | 0.933 |
| supervised_gbm_reference | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| rules_correlation | 0.500 | 1.000 | 0.062 | 1.000 | 1.000 |
| hybrid | 0.500 | 1.000 | 0.062 | 1.000 | 1.000 |

Per-scenario incident recall / median detection delay (hours from first malicious event to the end of the first alerted day) / median share of an incident's events that came after the alert:

| Model | account_misuse | bulk_export | gradual_data_collection | multi_stage_sequence | removable_media_exfiltration | all |
|---|---|---|---|---|---|---|
| iforest_raw | 2/2 | 21.4 h | 0.00 | 0/2 | n/a h | n/a | 0/1 | n/a h | n/a | 2/3 | 1.6 h | 0.00 | 4/6 | 24.7 h | 0.40 | 8/15 | 21.4 h | 0.00 |
| iforest_deviation | 0/2 | n/a h | n/a | 0/2 | n/a h | n/a | 0/1 | n/a h | n/a | 2/3 | 1.6 h | 0.00 | 6/6 | 1.4 h | 0.50 | 8/15 | 1.5 h | 0.40 |
| lof_deviation | 2/2 | 21.4 h | 0.00 | 2/2 | 11.3 h | 0.00 | 1/1 | 206.3 h | 0.71 | 2/3 | 1.6 h | 0.00 | 6/6 | 1.1 h | 0.59 | 13/15 | 1.7 h | 0.00 |
| robust_z_own | 2/2 | 21.4 h | 0.00 | 2/2 | 11.3 h | 0.00 | 0/1 | n/a h | n/a | 2/3 | 1.6 h | 0.00 | 6/6 | 1.1 h | 0.59 | 12/15 | 1.6 h | 0.00 |
| supervised_gbm_reference | 2/2 | 21.4 h | 0.00 | 2/2 | 11.3 h | 0.00 | 1/1 | 14.3 h | 0.98 | 2/3 | 1.6 h | 0.00 | 6/6 | 1.1 h | 0.59 | 13/15 | 1.7 h | 0.00 |
| rules_correlation | 1/2 | 22.7 h | 0.00 | 2/2 | 11.3 h | 0.00 | 1/1 | 518.3 h | 0.00 | 2/3 | 1.6 h | 0.00 | 6/6 | 1.1 h | 0.59 | 12/15 | 1.6 h | 0.00 |
| hybrid | 1/2 | 22.7 h | 0.00 | 2/2 | 11.3 h | 0.00 | 1/1 | 518.3 h | 0.00 | 2/3 | 1.6 h | 0.00 | 6/6 | 1.1 h | 0.59 | 12/15 | 1.6 h | 0.00 |

False-positive rate on benign lookalike windows:

| Model | approved_odd_hours | frequent_authorised_access | legit_large_transfer | routine_removable_media |
|---|---|---|---|---|
| iforest_raw | 0.0933 (14/150) | 0.0000 (0/225) | 0.0000 (0/2) | 0.2857 (8/28) |
| iforest_deviation | 0.0067 (1/150) | 0.0000 (0/225) | 0.0000 (0/2) | 0.2857 (8/28) |
| lof_deviation | 0.0000 (0/150) | 0.0000 (0/225) | 1.0000 (2/2) | 0.2857 (8/28) |
| robust_z_own | 0.0000 (0/150) | 0.0000 (0/225) | 0.0000 (0/2) | 0.0000 (0/28) |
| supervised_gbm_reference | 0.0000 (0/150) | 0.0000 (0/225) | 1.0000 (2/2) | 0.0000 (0/28) |
| rules_correlation | 0.0000 (0/150) | 0.0000 (0/225) | 0.0000 (0/2) | 0.0000 (0/28) |
| hybrid | 0.0000 (0/150) | 0.0000 (0/225) | 0.0000 (0/2) | 0.0000 (0/28) |

95% user-bootstrap intervals (precision / recall / FPR):

* iforest_raw: precision [0.1234, 0.8155], recall [0.1093, 0.6424], FPR [0.0007, 0.0112]
* iforest_deviation: precision [0.2468, 0.5803], recall [0.1475, 0.8534], FPR [0.002, 0.0083]
* lof_deviation: precision [0.2825, 0.7083], recall [0.291, 1.0], FPR [0.0022, 0.0089]
* robust_z_own: precision [0.2856, 0.6288], recall [0.2419, 1.0], FPR [0.0029, 0.0074]
* supervised_gbm_reference: precision [0.3328, 0.7936], recall [1.0, 1.0], FPR [0.0031, 0.0072]
* rules_correlation: precision [0.4, 0.5844], recall [0.2694, 1.0], FPR [0.002, 0.0085]
* hybrid: precision [0.398, 0.5821], recall [0.2694, 1.0], FPR [0.002, 0.0085]

Excluded windows: {'baseline_warmup_windows': 2361, 'ambiguous_or_incident_gap_windows': 0, 'by_note': {}}
Hybrid states on evaluated windows: {'anomalous_activity': 173, 'suspicious_sequence': 35, 'potential_data_exposure': 26}
