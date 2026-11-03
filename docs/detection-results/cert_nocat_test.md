**cert - test split** - one window = one user on one calendar day; alerts are scored at the end of the day

alert threshold per model = benign VALIDATION quantile giving false-positive rate 0.005

Destination-category enrichment: DISABLED (ablation)

Evaluated: 96,094 labelled windows from 300 users, 275 malicious windows from 21 insiders.

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN | ROC-AUC | AP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| iforest_raw | 0.013 | 0.015 | 0.013 | 0.0033 | 0.986 | 4 | 313 | 271 | 95506 | 0.873 | 0.013 |
| iforest_deviation | 0.136 | 0.120 | 0.128 | 0.0022 | 0.880 | 33 | 209 | 242 | 95610 | 0.955 | 0.071 |
| lof_deviation | 0.014 | 0.062 | 0.023 | 0.0122 | 0.938 | 17 | 1166 | 258 | 94653 | 0.816 | 0.010 |
| robust_z_own | 0.016 | 0.018 | 0.017 | 0.0032 | 0.982 | 5 | 306 | 270 | 95513 | 0.806 | 0.018 |
| supervised_gbm_reference | 0.209 | 0.996 | 0.346 | 0.0108 | 0.004 | 274 | 1035 | 1 | 94784 | 0.999 | 0.719 |
| rules_correlation | 0.064 | 0.062 | 0.063 | 0.0026 | 0.938 | 17 | 249 | 258 | 95570 | 0.935 | 0.039 |
| hybrid | 0.117 | 0.120 | 0.119 | 0.0026 | 0.880 | 33 | 248 | 242 | 95571 | 0.949 | 0.061 |

Recall at fixed validation false-positive rates (threshold from validation, applied to the evaluated split):

| Model | recall @0.1% FPR | recall @0.5% FPR | recall @1% FPR |
|---|---|---|---|
| iforest_raw | 0.011 (obs. FPR 0.00063) | 0.015 (obs. FPR 0.00327) | 0.025 (obs. FPR 0.00617) |
| iforest_deviation | 0.047 (obs. FPR 0.00044) | 0.120 (obs. FPR 0.00218) | 0.196 (obs. FPR 0.00498) |
| lof_deviation | 0.029 (obs. FPR 0.00646) | 0.062 (obs. FPR 0.01217) | 0.066 (obs. FPR 0.01542) |
| robust_z_own | 0.011 (obs. FPR 0.00046) | 0.018 (obs. FPR 0.00319) | 0.080 (obs. FPR 0.00713) |
| supervised_gbm_reference | 0.982 (obs. FPR 0.00204) | 0.996 (obs. FPR 0.0108) | 0.996 (obs. FPR 0.01729) |
| rules_correlation | 0.018 (obs. FPR 0.00053) | 0.062 (obs. FPR 0.0026) | 0.178 (obs. FPR 0.00603) |
| hybrid | 0.025 (obs. FPR 0.00054) | 0.120 (obs. FPR 0.00259) | 0.207 (obs. FPR 0.00535) |

Per-scenario window recall (share of malicious windows that raised an alert):

| Model | 1 | 2 | 3 |
|---|---|---|---|
| iforest_raw | 0.071 | 0.000 | 0.375 |
| iforest_deviation | 0.857 | 0.063 | 0.625 |
| lof_deviation | 0.214 | 0.024 | 1.000 |
| robust_z_own | 0.071 | 0.004 | 0.375 |
| supervised_gbm_reference | 1.000 | 0.996 | 1.000 |
| rules_correlation | 0.643 | 0.024 | 0.250 |
| hybrid | 0.857 | 0.063 | 0.625 |

Per-scenario incident recall / median detection delay (hours from first malicious event to the end of the first alerted day) / median share of an incident's events that came after the alert:

| Model | 1 | 2 | 3 | all |
|---|---|---|---|---|
| iforest_raw | 1/8 | 4.8 h | 0.50 | 0/9 | n/a h | n/a | 2/4 | 13.0 h | 0.13 | 3/21 | 10.5 h | 0.17 |
| iforest_deviation | 7/8 | 17.4 h | 0.50 | 8/9 | 242.3 h | 0.75 | 4/4 | 13.9 h | 0.13 | 19/21 | 22.3 h | 0.50 |
| lof_deviation | 2/8 | 11.1 h | 0.50 | 3/9 | 182.8 h | 0.80 | 4/4 | 13.9 h | 0.13 | 9/21 | 15.6 h | 0.50 |
| robust_z_own | 1/8 | 4.8 h | 0.50 | 1/9 | 734.9 h | 0.36 | 3/4 | 14.3 h | 0.11 | 5/21 | 14.3 h | 0.14 |
| supervised_gbm_reference | 7/8 | 17.4 h | 0.50 | 9/9 | 14.2 h | 0.98 | 4/4 | 13.9 h | 0.13 | 20/21 | 14.2 h | 0.55 |
| rules_correlation | 5/8 | 17.4 h | 0.50 | 5/9 | 1118.0 h | 0.09 | 1/4 | 14.3 h | 0.11 | 11/21 | 166.4 h | 0.28 |
| hybrid | 6/8 | 11.1 h | 0.50 | 7/9 | 470.6 h | 0.54 | 3/4 | 14.3 h | 0.11 | 16/21 | 36.7 h | 0.50 |

95% user-bootstrap intervals (precision / recall / FPR):

* iforest_raw: precision [0.0, 0.0544], recall [0.0, 0.045], FPR [0.0003, 0.0067]
* iforest_deviation: precision [0.0695, 0.2168], recall [0.0725, 0.2088], FPR [0.0013, 0.0032]
* lof_deviation: precision [0.004, 0.0415], recall [0.022, 0.1228], FPR [0.0045, 0.0214]
* robust_z_own: precision [0.0037, 0.0347], recall [0.0038, 0.0435], FPR [0.0021, 0.0043]
* supervised_gbm_reference: precision [0.0831, 0.4484], recall [0.9867, 1.0], FPR [0.004, 0.0191]
* rules_correlation: precision [0.0284, 0.1166], recall [0.029, 0.1307], FPR [0.0016, 0.0037]
* hybrid: precision [0.0632, 0.1879], recall [0.0725, 0.2145], FPR [0.0017, 0.0036]

Excluded windows: {'baseline_warmup_windows': 7899, 'ambiguous_or_incident_gap_windows': 671, 'by_note': {'inside_incident_window_unlisted': 651, 'ambiguous_other_account_events': 20}}
Hybrid states on evaluated windows: {'anomalous_activity': 1927, 'suspicious_sequence': 93, 'potential_data_exposure': 28}
