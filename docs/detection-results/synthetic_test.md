**synthetic - test split** - one window = one user on one calendar day; alerts are scored at the end of the day

alert threshold per model = benign VALIDATION quantile giving false-positive rate 0.005

Destination-category enrichment: enabled

Evaluated: 9,008 labelled windows from 120 users, 95 malicious windows from 30 insiders.

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN | ROC-AUC | AP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| iforest_raw | 0.140 | 0.074 | 0.097 | 0.0048 | 0.926 | 7 | 43 | 88 | 8870 | 0.744 | 0.054 |
| iforest_deviation | 0.324 | 0.116 | 0.171 | 0.0026 | 0.884 | 11 | 23 | 84 | 8890 | 0.905 | 0.178 |
| lof_deviation | 0.574 | 0.326 | 0.416 | 0.0026 | 0.674 | 31 | 23 | 64 | 8890 | 0.947 | 0.434 |
| robust_z_own | 0.343 | 0.253 | 0.291 | 0.0052 | 0.747 | 24 | 46 | 71 | 8867 | 0.819 | 0.245 |
| supervised_gbm_reference | 0.559 | 0.990 | 0.715 | 0.0083 | 0.011 | 94 | 74 | 1 | 8839 | 1.000 | 0.983 |
| rules_correlation | 0.590 | 0.242 | 0.343 | 0.0018 | 0.758 | 23 | 16 | 72 | 8897 | 0.951 | 0.564 |
| hybrid | 0.575 | 0.242 | 0.341 | 0.0019 | 0.758 | 23 | 17 | 72 | 8896 | 0.946 | 0.522 |

Recall at fixed validation false-positive rates (threshold from validation, applied to the evaluated split):

| Model | recall @0.1% FPR | recall @0.5% FPR | recall @1% FPR |
|---|---|---|---|
| iforest_raw | 0.032 (obs. FPR 0.00056) | 0.074 (obs. FPR 0.00482) | 0.179 (obs. FPR 0.0129) |
| iforest_deviation | 0.084 (obs. FPR 0.00079) | 0.116 (obs. FPR 0.00258) | 0.147 (obs. FPR 0.00314) |
| lof_deviation | 0.242 (obs. FPR 0.00045) | 0.326 (obs. FPR 0.00258) | 0.474 (obs. FPR 0.00886) |
| robust_z_own | 0.074 (obs. FPR 0.00034) | 0.253 (obs. FPR 0.00516) | 0.284 (obs. FPR 0.01066) |
| supervised_gbm_reference | 0.968 (obs. FPR 0.00146) | 0.990 (obs. FPR 0.0083) | 0.990 (obs. FPR 0.01335) |
| rules_correlation | 0.179 (obs. FPR 0.00067) | 0.242 (obs. FPR 0.0018) | 0.558 (obs. FPR 0.00426) |
| hybrid | 0.179 (obs. FPR 0.00056) | 0.242 (obs. FPR 0.00191) | 0.495 (obs. FPR 0.00381) |

Per-scenario window recall (share of malicious windows that raised an alert):

| Model | account_misuse | bulk_export | gradual_data_collection | multi_stage_sequence | removable_media_exfiltration | unusual_external_transfer |
|---|---|---|---|---|---|---|
| iforest_raw | 0.143 | 0.000 | 0.000 | 1.000 | 0.429 | 0.000 |
| iforest_deviation | 0.000 | 0.167 | 0.000 | 1.000 | 1.000 | 0.000 |
| lof_deviation | 1.000 | 1.000 | 0.059 | 1.000 | 1.000 | 1.000 |
| robust_z_own | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 0.250 |
| supervised_gbm_reference | 1.000 | 1.000 | 0.985 | 1.000 | 1.000 | 1.000 |
| rules_correlation | 0.429 | 1.000 | 0.059 | 1.000 | 1.000 | 0.000 |
| hybrid | 0.429 | 1.000 | 0.059 | 1.000 | 1.000 | 0.000 |

Per-scenario incident recall / median detection delay (hours from first malicious event to the end of the first alerted day) / median share of an incident's events that came after the alert:

| Model | account_misuse | bulk_export | gradual_data_collection | multi_stage_sequence | removable_media_exfiltration | unusual_external_transfer | all |
|---|---|---|---|---|---|---|---|
| iforest_raw | 1/7 | 22.9 h | 0.00 | 0/7 | n/a h | n/a | 0/5 | n/a h | n/a | 3/4 | 1.9 h | 0.00 | 1/3 | 1.0 h | 0.81 | 0/4 | n/a h | n/a | 5/30 | 1.9 h | 0.00 |
| iforest_deviation | 0/7 | n/a h | n/a | 1/7 | 13.4 h | 0.00 | 0/5 | n/a h | n/a | 3/4 | 1.9 h | 0.00 | 3/3 | 1.0 h | 0.70 | 0/4 | n/a h | n/a | 7/30 | 1.9 h | 0.00 |
| lof_deviation | 7/7 | 21.3 h | 0.00 | 6/7 | 13.6 h | 0.00 | 3/5 | 110.7 h | 0.74 | 3/4 | 1.9 h | 0.00 | 3/3 | 1.0 h | 0.70 | 4/4 | 12.0 h | 0.00 | 26/30 | 13.9 h | 0.00 |
| robust_z_own | 7/7 | 21.3 h | 0.00 | 6/7 | 13.6 h | 0.00 | 0/5 | n/a h | n/a | 3/4 | 1.9 h | 0.00 | 3/3 | 1.0 h | 0.70 | 1/4 | 10.8 h | 0.00 | 20/30 | 13.7 h | 0.00 |
| supervised_gbm_reference | 7/7 | 21.3 h | 0.00 | 6/7 | 13.6 h | 0.00 | 5/5 | 14.6 h | 0.96 | 3/4 | 1.9 h | 0.00 | 3/3 | 1.0 h | 0.70 | 4/4 | 12.0 h | 0.00 | 28/30 | 13.9 h | 0.00 |
| rules_correlation | 3/7 | 22.2 h | 0.00 | 6/7 | 13.6 h | 0.00 | 4/5 | 446.8 h | 0.00 | 3/4 | 1.9 h | 0.00 | 3/3 | 1.0 h | 0.70 | 0/4 | n/a h | n/a | 19/30 | 13.8 h | 0.00 |
| hybrid | 3/7 | 22.2 h | 0.00 | 6/7 | 13.6 h | 0.00 | 4/5 | 446.8 h | 0.00 | 3/4 | 1.9 h | 0.00 | 3/3 | 1.0 h | 0.70 | 0/4 | n/a h | n/a | 19/30 | 13.8 h | 0.00 |

False-positive rate on benign lookalike windows:

| Model | approved_odd_hours | frequent_authorised_access | legit_large_transfer | routine_removable_media |
|---|---|---|---|---|
| iforest_raw | 0.0629 (33/525) | 0.0000 (0/525) | 0.0000 (0/3) | 0.2222 (10/45) |
| iforest_deviation | 0.0038 (2/525) | 0.0000 (0/525) | 0.0000 (0/3) | 0.2222 (10/45) |
| lof_deviation | 0.0019 (1/525) | 0.0000 (0/525) | 1.0000 (3/3) | 0.1778 (8/45) |
| robust_z_own | 0.0019 (1/525) | 0.0038 (2/525) | 0.0000 (0/3) | 0.0222 (1/45) |
| supervised_gbm_reference | 0.0095 (5/525) | 0.0000 (0/525) | 1.0000 (3/3) | 0.0000 (0/45) |
| rules_correlation | 0.0000 (0/525) | 0.0000 (0/525) | 0.0000 (0/3) | 0.0000 (0/45) |
| hybrid | 0.0000 (0/525) | 0.0000 (0/525) | 0.0000 (0/3) | 0.0000 (0/45) |

95% user-bootstrap intervals (precision / recall / FPR):

* iforest_raw: precision [0.0292, 0.3802], recall [0.0122, 0.2036], FPR [0.0018, 0.0084]
* iforest_deviation: precision [0.1394, 0.6469], recall [0.0276, 0.2967], FPR [0.0004, 0.0052]
* lof_deviation: precision [0.3824, 0.7964], recall [0.1935, 0.6799], FPR [0.0009, 0.0045]
* robust_z_own: precision [0.2259, 0.4655], recall [0.1157, 0.5884], FPR [0.0038, 0.0066]
* supervised_gbm_reference: precision [0.3658, 0.6886], recall [0.972, 1.0], FPR [0.0063, 0.0104]
* rules_correlation: precision [0.4792, 0.804], recall [0.1333, 0.4837], FPR [0.0003, 0.0033]
* hybrid: precision [0.4706, 0.7735], recall [0.1333, 0.4837], FPR [0.0004, 0.0034]

Excluded windows: {'baseline_warmup_windows': 2361, 'ambiguous_or_incident_gap_windows': 0, 'by_note': {}}
Hybrid states on evaluated windows: {'anomalous_activity': 151, 'suspicious_sequence': 50, 'potential_data_exposure': 29}
