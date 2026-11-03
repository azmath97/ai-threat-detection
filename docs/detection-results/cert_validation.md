**cert - validation split** - one window = one user on one calendar day; alerts are scored at the end of the day

alert threshold per model = benign VALIDATION quantile giving false-positive rate 0.005

Destination-category enrichment: enabled

Evaluated: 48,244 labelled windows from 150 users, 151 malicious windows from 10 insiders.

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN | ROC-AUC | AP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| iforest_raw | 0.008 | 0.013 | 0.010 | 0.0050 | 0.987 | 2 | 241 | 149 | 47852 | 0.806 | 0.008 |
| iforest_deviation | 0.077 | 0.133 | 0.097 | 0.0050 | 0.868 | 20 | 241 | 131 | 47852 | 0.946 | 0.056 |
| lof_deviation | 0.024 | 0.040 | 0.030 | 0.0050 | 0.960 | 6 | 240 | 145 | 47853 | 0.819 | 0.020 |
| robust_z_own | 0.024 | 0.040 | 0.030 | 0.0050 | 0.960 | 6 | 241 | 145 | 47852 | 0.769 | 0.013 |
| supervised_gbm_reference | 0.385 | 1.000 | 0.556 | 0.0050 | 0.000 | 151 | 241 | 0 | 47852 | 1.000 | 0.945 |
| rules_correlation | 0.169 | 0.325 | 0.222 | 0.0050 | 0.675 | 49 | 241 | 102 | 47852 | 0.951 | 0.080 |
| hybrid | 0.187 | 0.351 | 0.244 | 0.0048 | 0.649 | 53 | 230 | 98 | 47863 | 0.952 | 0.080 |

Recall at fixed validation false-positive rates (threshold from validation, applied to the evaluated split):

| Model | recall @0.1% FPR | recall @0.5% FPR | recall @1% FPR |
|---|---|---|---|
| iforest_raw | 0.000 (obs. FPR 0.00102) | 0.013 (obs. FPR 0.00501) | 0.020 (obs. FPR 0.01) |
| iforest_deviation | 0.046 (obs. FPR 0.00102) | 0.133 (obs. FPR 0.00501) | 0.159 (obs. FPR 0.00998) |
| lof_deviation | 0.026 (obs. FPR 0.00091) | 0.040 (obs. FPR 0.00499) | 0.053 (obs. FPR 0.00992) |
| robust_z_own | 0.013 (obs. FPR 0.00102) | 0.040 (obs. FPR 0.00501) | 0.086 (obs. FPR 0.01) |
| supervised_gbm_reference | 1.000 (obs. FPR 0.00102) | 1.000 (obs. FPR 0.00501) | 1.000 (obs. FPR 0.01) |
| rules_correlation | 0.007 (obs. FPR 0.00102) | 0.325 (obs. FPR 0.00501) | 0.437 (obs. FPR 0.01) |
| hybrid | 0.026 (obs. FPR 0.00102) | 0.351 (obs. FPR 0.00478) | 0.397 (obs. FPR 0.01) |

Per-scenario window recall (share of malicious windows that raised an alert):

| Model | 1 | 2 | 3 |
|---|---|---|---|
| iforest_raw | 0.000 | 0.000 | 0.500 |
| iforest_deviation | 0.875 | 0.079 | 0.500 |
| lof_deviation | 0.125 | 0.007 | 1.000 |
| robust_z_own | 0.250 | 0.014 | 0.500 |
| supervised_gbm_reference | 1.000 | 1.000 | 1.000 |
| rules_correlation | 0.375 | 0.324 | 0.250 |
| hybrid | 0.625 | 0.331 | 0.500 |

Per-scenario incident recall / median detection delay (hours from first malicious event to the end of the first alerted day) / median share of an incident's events that came after the alert:

| Model | 1 | 2 | 3 | all |
|---|---|---|---|---|
| iforest_raw | 0/3 | n/a h | n/a | 0/5 | n/a h | n/a | 2/2 | 15.7 h | 0.11 | 2/10 | 15.7 h | 0.11 |
| iforest_deviation | 3/3 | 3.5 h | 0.67 | 5/5 | 375.4 h | 0.59 | 1/2 | 16.5 h | 0.12 | 9/10 | 39.9 h | 0.59 |
| lof_deviation | 1/3 | 1.6 h | 0.67 | 1/5 | 231.9 h | 0.70 | 2/2 | 15.7 h | 0.11 | 4/10 | 15.7 h | 0.39 |
| robust_z_own | 2/3 | 70.9 h | 0.53 | 2/5 | 385.5 h | 0.65 | 2/2 | 15.7 h | 0.11 | 6/10 | 28.2 h | 0.38 |
| supervised_gbm_reference | 3/3 | 3.5 h | 0.67 | 5/5 | 15.7 h | 0.98 | 2/2 | 15.7 h | 0.11 | 10/10 | 15.6 h | 0.84 |
| rules_correlation | 3/3 | 3.5 h | 0.67 | 3/5 | 207.9 h | 0.76 | 1/2 | 16.5 h | 0.12 | 7/10 | 140.2 h | 0.67 |
| hybrid | 3/3 | 3.5 h | 0.67 | 4/5 | 303.8 h | 0.71 | 1/2 | 16.5 h | 0.12 | 8/10 | 161.8 h | 0.66 |

95% user-bootstrap intervals (precision / recall / FPR):

* iforest_raw: precision [0.0, 0.0502], recall [0.0, 0.0644], FPR [0.0006, 0.0112]
* iforest_deviation: precision [0.02, 0.1974], recall [0.0544, 0.3134], FPR [0.0022, 0.0091]
* lof_deviation: precision [0.0028, 0.0618], recall [0.0042, 0.1978], FPR [0.0028, 0.0077]
* robust_z_own: precision [0.0066, 0.0493], recall [0.0125, 0.1462], FPR [0.0034, 0.007]
* supervised_gbm_reference: precision [0.1281, 0.6567], recall [1.0, 1.0], FPR [0.002, 0.0089]
* rules_correlation: precision [0.0156, 0.3591], recall [0.0547, 0.6], FPR [0.003, 0.0075]
* hybrid: precision [0.0316, 0.388], recall [0.109, 0.6265], FPR [0.0027, 0.0074]

Excluded windows: {'baseline_warmup_windows': 7899, 'ambiguous_or_incident_gap_windows': 671, 'by_note': {'inside_incident_window_unlisted': 651, 'ambiguous_other_account_events': 20}}
Hybrid states on evaluated windows: {'anomalous_activity': 1604, 'suspicious_sequence': 123, 'potential_data_exposure': 12}
