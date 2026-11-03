**cert - test split** - one window = one user on one calendar day; alerts are scored at the end of the day

alert threshold per model = benign VALIDATION quantile giving false-positive rate 0.005

Destination-category enrichment: enabled

Evaluated: 96,094 labelled windows from 300 users, 275 malicious windows from 21 insiders.

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN | ROC-AUC | AP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| iforest_raw | 0.013 | 0.018 | 0.015 | 0.0040 | 0.982 | 5 | 381 | 270 | 95438 | 0.873 | 0.013 |
| iforest_deviation | 0.150 | 0.149 | 0.150 | 0.0024 | 0.851 | 41 | 232 | 234 | 95587 | 0.961 | 0.083 |
| lof_deviation | 0.011 | 0.044 | 0.018 | 0.0108 | 0.956 | 12 | 1039 | 263 | 94780 | 0.813 | 0.011 |
| robust_z_own | 0.014 | 0.018 | 0.016 | 0.0037 | 0.982 | 5 | 358 | 270 | 95461 | 0.819 | 0.018 |
| supervised_gbm_reference | 0.291 | 0.993 | 0.450 | 0.0070 | 0.007 | 273 | 666 | 2 | 95153 | 1.000 | 0.856 |
| rules_correlation | 0.093 | 0.218 | 0.130 | 0.0061 | 0.782 | 60 | 587 | 215 | 95232 | 0.931 | 0.061 |
| hybrid | 0.170 | 0.229 | 0.195 | 0.0032 | 0.771 | 63 | 307 | 212 | 95512 | 0.943 | 0.074 |

Recall at fixed validation false-positive rates (threshold from validation, applied to the evaluated split):

| Model | recall @0.1% FPR | recall @0.5% FPR | recall @1% FPR |
|---|---|---|---|
| iforest_raw | 0.011 (obs. FPR 0.00073) | 0.018 (obs. FPR 0.00398) | 0.022 (obs. FPR 0.00681) |
| iforest_deviation | 0.054 (obs. FPR 0.00045) | 0.149 (obs. FPR 0.00242) | 0.233 (obs. FPR 0.00558) |
| lof_deviation | 0.029 (obs. FPR 0.0063) | 0.044 (obs. FPR 0.01084) | 0.069 (obs. FPR 0.01595) |
| robust_z_own | 0.007 (obs. FPR 0.00052) | 0.018 (obs. FPR 0.00374) | 0.087 (obs. FPR 0.00751) |
| supervised_gbm_reference | 0.989 (obs. FPR 0.00332) | 0.993 (obs. FPR 0.00695) | 0.996 (obs. FPR 0.01193) |
| rules_correlation | 0.022 (obs. FPR 0.00063) | 0.218 (obs. FPR 0.00613) | 0.298 (obs. FPR 0.011) |
| hybrid | 0.029 (obs. FPR 0.00067) | 0.229 (obs. FPR 0.0032) | 0.349 (obs. FPR 0.01021) |

Per-scenario window recall (share of malicious windows that raised an alert):

| Model | 1 | 2 | 3 |
|---|---|---|---|
| iforest_raw | 0.071 | 0.000 | 0.500 |
| iforest_deviation | 0.857 | 0.095 | 0.625 |
| lof_deviation | 0.143 | 0.008 | 1.000 |
| robust_z_own | 0.071 | 0.004 | 0.375 |
| supervised_gbm_reference | 0.929 | 0.996 | 1.000 |
| rules_correlation | 0.500 | 0.205 | 0.125 |
| hybrid | 0.571 | 0.205 | 0.375 |

Per-scenario incident recall / median detection delay (hours from first malicious event to the end of the first alerted day) / median share of an incident's events that came after the alert:

| Model | 1 | 2 | 3 | all |
|---|---|---|---|---|
| iforest_raw | 1/8 | 4.8 h | 0.50 | 0/9 | n/a h | n/a | 3/4 | 14.3 h | 0.11 | 4/21 | 12.4 h | 0.14 |
| iforest_deviation | 7/8 | 17.4 h | 0.50 | 8/9 | 218.7 h | 0.82 | 4/4 | 13.9 h | 0.13 | 19/21 | 22.3 h | 0.50 |
| lof_deviation | 1/8 | 4.8 h | 0.50 | 2/9 | 206.4 h | 0.80 | 4/4 | 13.9 h | 0.13 | 7/21 | 14.3 h | 0.17 |
| robust_z_own | 1/8 | 4.8 h | 0.50 | 1/9 | 14.0 h | 0.98 | 3/4 | 14.3 h | 0.11 | 5/21 | 14.0 h | 0.14 |
| supervised_gbm_reference | 7/8 | 17.4 h | 0.50 | 9/9 | 14.2 h | 0.98 | 4/4 | 13.9 h | 0.13 | 20/21 | 14.2 h | 0.55 |
| rules_correlation | 4/8 | 19.9 h | 0.50 | 6/9 | 314.9 h | 0.66 | 1/4 | 14.3 h | 0.11 | 11/21 | 206.0 h | 0.50 |
| hybrid | 5/8 | 17.4 h | 0.50 | 6/9 | 386.9 h | 0.62 | 2/4 | 13.9 h | 0.13 | 13/21 | 166.4 h | 0.50 |

95% user-bootstrap intervals (precision / recall / FPR):

* iforest_raw: precision [0.003, 0.0475], recall [0.0036, 0.0506], FPR [0.0008, 0.0075]
* iforest_deviation: precision [0.0733, 0.2464], recall [0.0948, 0.243], FPR [0.0014, 0.0036]
* lof_deviation: precision [0.0029, 0.0342], recall [0.0124, 0.0988], FPR [0.0036, 0.0198]
* robust_z_own: precision [0.0029, 0.0273], recall [0.0033, 0.0433], FPR [0.0027, 0.0047]
* supervised_gbm_reference: precision [0.1428, 0.4907], recall [0.9761, 1.0], FPR [0.0033, 0.011]
* rules_correlation: precision [0.0219, 0.1703], recall [0.0654, 0.3569], FPR [0.0043, 0.0081]
* hybrid: precision [0.0502, 0.3062], recall [0.0757, 0.3784], FPR [0.0021, 0.0044]

Excluded windows: {'baseline_warmup_windows': 7899, 'ambiguous_or_incident_gap_windows': 671, 'by_note': {'inside_incident_window_unlisted': 651, 'ambiguous_other_account_events': 20}}
Hybrid states on evaluated windows: {'anomalous_activity': 2167, 'suspicious_sequence': 152, 'potential_data_exposure': 28}
