# Evaluation report

Protocol **forward-chaining-v2**, partition evaluated: **test**, generated 2026-11-03T17:58:04.210370+00:00.

> **No combined score.** The three tracks use different data, different ground truth and different guarantees. They are reported separately and must not be averaged or quoted as one headline number. Every dataset used here is synthetic.

## Reproduce

```powershell
python -m ml.detect.run_evaluation --cert-processed data/processed/cert_r4.2 --out reports/evaluation --partition test --final
```

## Provenance

| Item | Value |
|---|---|
| git commit | f9824d844144c2e052975f8c5af074ba32d24e3b |
| uncommitted changes | True |
| random seed | 42 |
| target false-positive rate | 0.005 |
| bootstrap resamples | 300 |
| feature count | 101 |
| hybrid configuration SHA-256 | 372b1f9a8de8f637b21c614ec1557b6a3272b185496a24e3196e0da4fcd3822e |
| matches the configuration frozen before the first CERT test run | yes |
| python | 3.12.0 |
| platform | Windows-11-10.0.26200-SP0 |
| numpy | 2.4.6 |
| pandas | 2.2.2 |
| scikit-learn | 1.7.2 |
| scipy | 1.16.2 |

### Honest notes on this run

* The CERT test users were already evaluated once in the earlier benchmark (whole timeline, user-disjoint split). This protocol re-uses the same frozen configuration on a later time slice of those users, so it is not a fresh, never-seen test set. No rule, feature or weight was changed.
* The synthetic track uses a new generator seed, so its test users and incidents were never seen during development.
* Fitting (peer baseline, destination statistics, models, baseline-rule thresholds) used the train partition; thresholds used benign validation windows only; the evaluated partition's labels were blanked before fitting.
* Time cutoffs are fractions of each dataset's window date range (CERT 45 % / 52 %, synthetic 45 % / 65 %); incidents that straddle a cutoff are listed and excluded rather than half-used. The synthetic generator was run with threat_start_fraction 0.30 so attacks occur across most of the timeline (its default of 0.55 would leave no attacks in a time-ordered training period).

## Track A: held-out CERT r4.2 (dataset ground truth)

### Data

| Item | Value |
|---|---|
| dataset | CERT Insider Threat Test Dataset (Carnegie Mellon SEI CERT Division with ExactData, LLC), synthetic |
| release | r4.2 |
| reference | https://doi.org/10.1184/R1/12841247.v1 |
| licence | CC BY 4.0 |
| answer_key | answers.tar.bz2 (insiders.csv plus the per-incident observables files r4.2-1, r4.2-2, r4.2-3) |
| prepared_directory | data\processed\cert_r4.2 |
| preparation_seed | 42 |
| users | 1000 |
| insiders | 70 |
| windows_total | 330452 |
| destination_category_enrichment | enabled |

**selected_files**

| file | bytes | sha256 |
|---|---|---|
| logon.csv | 58514706 | a770601339829d544535b3cb08b2f2020a1feaa81bd88cdbfc2d452444f12a13 |
| device.csv | 28982749 | 39925627f0219c77dbb39e5a416715298ef47c2fd25322aa44c66cb128d7291d |
| http.csv | 14536257467 | 30c779a3c98d243650e65b6ac77f90327e5b4f0b8a9feb26a55f030f6fa2fb39 |
| email.csv | 1362101939 | 2ac157015873ce139f515b931ed83c6140fcd77cee3568565bea7335b318087f |
| file.csv | 193055265 | 637281bd6d8947b2cccf90bca7096e8cfad711eab1e425c61f886b0e4edfda7f |
| labels.csv | 344459 | 24e17c14bea5349a4ef9a3177e98ef8ea575b780b93a5d976e4683c27f96257b |
| splits.csv | 27408 | 08505a9eb5e50359b3616e61f087b9f56528a4e29e021e9b616c7e3c345a63e7 |

**event_counts**

|  | value |
|---|---|
| logon | 854859 |
| device | 405380 |
| http | 28434423 |
| email | 2629979 |
| file | 445581 |

**label_counts**

|  | value |
|---|---|
| answer_key_events_listed | 7323 |
| labelled_malicious_events | 7273 |
| ambiguous_events_excluded | 50 |
| incidents | 70 |
| labels_csv_rows | 7323 |

**user_splits**

| split | users | insiders |
|---|---|---|
| test | 300 | 21 |
| train | 550 | 39 |
| validation | 150 | 10 |

**source_check**

|  | value |
|---|---|
| event_sources_found | {'cert_r4.2': 32770222} |
| synthetic_rows | 0 |

### Split strategy

| Partition | Definition |
|---|---|
| users | disjoint train / validation / test (whole users) |
| time | forward-chaining cutoffs |
| train end | 2010-08-15 |
| validation end | 2010-09-19 |
| train | train users, days <= train_end |
| validation | validation users, train_end < day <= validation_end |
| test | test users, day > validation_end |

| Partition | Users | Windows | Evaluable | Malicious windows | Insiders | Events | Malicious events | Days |
|---|---|---|---|---|---|---|---|---|
| train | 550 | 87117 | 83340 | 121 | 13 | 8824056 | 768 | 2010-01-02 to 2010-08-15 |
| validation | 143 | 3477 | 3434 | 38 | 4 | 338813 | 287 | 2010-08-16 to 2010-09-19 |
| test | 282 | 44636 | 44266 | 127 | 11 | 4229346 | 1120 | 2010-09-20 to 2011-05-16 |

Incident status (an incident belongs to exactly one user, so it cannot be split across partitions; incidents that straddle a cutoff are excluded, not half-used):

| Split | Status | Incidents |
|---|---|---|
| test | before_test_period | 7 |
| test | evaluated | 12 |
| test | straddles_test_cutoff | 2 |
| train | not_in_test | 35 |
| train | straddles_train_cutoff | 4 |
| validation | not_in_test | 10 |

Windows excluded: warm-up (< 5 baseline days), unlabelled/ambiguous, straddling incidents. Test partition: 268 warm-up, 83 unlabelled, 37 straddling.

### Model configuration and thresholds

| Model | Role | Threshold rule | Threshold |
|---|---|---|---|
| baseline_fixed_rules | simple baseline rules (fixed thresholds, no model) | fixed | 1.00000 |
| robust_z_own | simple baseline: own-history z-scores | validation_quantile (target FPR 0.005) | 0.99170 |
| existing_iforest_raw | existing detector: Isolation Forest on raw volumes | validation_quantile (target FPR 0.005) | 0.99237 |
| iforest_deviation | improved: Isolation Forest on deviation features | validation_quantile (target FPR 0.005) | 0.99701 |
| lof_deviation | improved alternative: Local Outlier Factor | validation_quantile (target FPR 0.005) | 0.99587 |
| rules_correlation | improved: rules + correlation, no model | validation_quantile (target FPR 0.005) | 0.51218 |
| hybrid | improved: rules + correlation + anomaly model | validation_quantile (target FPR 0.005) | 0.51284 |
| supervised_gbm_reference | reference ceiling: supervised, uses labels | validation_quantile (target FPR 0.005) | 0.41896 |

Full hyper-parameters, feature list and baseline-rule thresholds are in `results.json` (`model_configuration`, `features`).

### Window level (one user-day; this is the primary unit)

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN | ROC-AUC | AP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| baseline_fixed_rules | 0.032 | 0.181 | 0.055 | 0.016 | 0.819 | 23 | 689 | 104 | 43450 | 0.802 | 0.015 |
| robust_z_own | 0.015 | 0.024 | 0.018 | 0.004 | 0.976 | 3 | 194 | 124 | 43945 | 0.830 | 0.018 |
| existing_iforest_raw | 0.019 | 0.024 | 0.021 | 0.004 | 0.976 | 3 | 153 | 124 | 43986 | 0.897 | 0.020 |
| iforest_deviation | 0.136 | 0.181 | 0.155 | 0.003 | 0.819 | 23 | 146 | 104 | 43993 | 0.957 | 0.076 |
| lof_deviation | 0.009 | 0.055 | 0.016 | 0.017 | 0.945 | 7 | 729 | 120 | 43410 | 0.798 | 0.009 |
| rules_correlation | 0.149 | 0.158 | 0.153 | 0.003 | 0.843 | 20 | 114 | 107 | 44025 | 0.959 | 0.063 |
| hybrid | 0.158 | 0.197 | 0.175 | 0.003 | 0.803 | 25 | 133 | 102 | 44006 | 0.960 | 0.071 |
| supervised_gbm_reference | 0.162 | 0.291 | 0.208 | 0.004 | 0.709 | 37 | 192 | 90 | 43947 | 0.881 | 0.303 |

### Event level (a window alert flags every event in it; TP/FN count malicious events, FP/TN benign events)

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| baseline_fixed_rules | 0.002 | 0.193 | 0.004 | 0.021 | 0.807 | 176 | 90301 | 735 | 4106266 |
| robust_z_own | 0.002 | 0.038 | 0.003 | 0.005 | 0.962 | 35 | 22186 | 876 | 4174381 |
| existing_iforest_raw | 0.001 | 0.033 | 0.002 | 0.006 | 0.967 | 30 | 24698 | 881 | 4171869 |
| iforest_deviation | 0.009 | 0.222 | 0.017 | 0.005 | 0.778 | 202 | 22197 | 709 | 4174370 |
| lof_deviation | 0.001 | 0.058 | 0.001 | 0.019 | 0.942 | 53 | 78587 | 858 | 4117980 |
| rules_correlation | 0.011 | 0.163 | 0.021 | 0.003 | 0.838 | 148 | 13065 | 763 | 4183502 |
| hybrid | 0.012 | 0.200 | 0.022 | 0.004 | 0.800 | 182 | 15395 | 729 | 4181172 |
| supervised_gbm_reference | 0.018 | 0.301 | 0.034 | 0.004 | 0.699 | 274 | 14885 | 637 | 4181682 |

### User level (flagged if any evaluated window alerted; insider if any evaluated window is malicious)

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| baseline_fixed_rules | 0.320 | 0.727 | 0.444 | 0.063 | 0.273 | 8 | 17 | 3 | 254 |
| robust_z_own | 0.119 | 0.727 | 0.205 | 0.218 | 0.273 | 8 | 59 | 3 | 212 |
| existing_iforest_raw | 0.455 | 0.455 | 0.455 | 0.022 | 0.545 | 5 | 6 | 6 | 265 |
| iforest_deviation | 0.289 | 1.000 | 0.449 | 0.100 | 0.000 | 11 | 27 | 0 | 244 |
| lof_deviation | 0.127 | 0.909 | 0.222 | 0.255 | 0.091 | 10 | 69 | 1 | 202 |
| rules_correlation | 0.296 | 0.727 | 0.421 | 0.070 | 0.273 | 8 | 19 | 3 | 252 |
| hybrid | 0.267 | 0.727 | 0.390 | 0.081 | 0.273 | 8 | 22 | 3 | 249 |
| supervised_gbm_reference | 0.333 | 0.545 | 0.414 | 0.044 | 0.455 | 6 | 12 | 5 | 259 |

### Recall at fixed validation false-positive rates (window level)

| Model | 0.1 % FPR | 0.5 % FPR | 1 % FPR |
|---|---|---|---|
| baseline_fixed_rules | n/a | n/a | n/a |
| robust_z_own | 0.008 (obs. 0.0013) | 0.024 (obs. 0.0044) | 0.102 (obs. 0.0077) |
| existing_iforest_raw | 0.016 (obs. 0.0004) | 0.024 (obs. 0.0035) | 0.032 (obs. 0.0053) |
| iforest_deviation | 0.087 (obs. 0.0013) | 0.181 (obs. 0.0033) | 0.213 (obs. 0.0072) |
| lof_deviation | 0.032 (obs. 0.0095) | 0.055 (obs. 0.0165) | 0.095 (obs. 0.0205) |
| rules_correlation | 0.016 (obs. 0.0011) | 0.158 (obs. 0.0026) | 0.228 (obs. 0.0041) |
| hybrid | 0.024 (obs. 0.0011) | 0.197 (obs. 0.0030) | 0.276 (obs. 0.0043) |
| supervised_gbm_reference | 0.268 (obs. 0.0035) | 0.291 (obs. 0.0043) | 0.307 (obs. 0.0045) |

Alerts per 1,000 evaluated windows: baseline_fixed_rules 16.08, robust_z_own 4.45, existing_iforest_raw 3.52, iforest_deviation 3.82, lof_deviation 16.63, rules_correlation 3.03, hybrid 3.57, supervised_gbm_reference 5.17

### Per scenario (window recall; incidents detected)

| Model | 1 | 2 | 3 |
|---|---|---|---|
| baseline_fixed_rules | 0.889; 5/6 | 0.097; 1/4 | 1.000; 2/2 |
| robust_z_own | 0.000; 0/6 | 0.018; 1/4 | 0.250; 1/2 |
| existing_iforest_raw | 0.000; 0/6 | 0.000; 0/4 | 0.750; 2/2 |
| iforest_deviation | 0.889; 5/6 | 0.105; 4/4 | 0.750; 2/2 |
| lof_deviation | 0.111; 1/6 | 0.018; 1/4 | 1.000; 2/2 |
| rules_correlation | 0.444; 2/6 | 0.140; 3/4 | 0.000; 0/2 |
| hybrid | 0.556; 3/6 | 0.175; 3/4 | 0.000; 0/2 |
| supervised_gbm_reference | 0.556; 4/6 | 0.281; 2/4 | 0.000; 0/2 |

### Detection delay (hours from the first malicious event to the end of the first alerted day) and early-warning share

Share = median fraction of an incident's events that came after the first alert (0 means the alert came after the incident ended). Windows are scored at day end, so a single-day incident cannot be alerted earlier than its own day.

| Model | 1 | 2 | 3 | all |
|---|---|---|---|---|
| baseline_fixed_rules | 22.3 h; 0.50 | 86.6 h; 0.93 | 13.0 h; 0.13 | 19.9 h; 0.33 |
| robust_z_own | n/a h; n/a | 12.7 h; 0.97 | 15.6 h; 0.10 | 14.2 h; 0.53 |
| existing_iforest_raw | n/a h; n/a | n/a h; n/a | 13.0 h; 0.13 | 13.0 h; 0.13 |
| iforest_deviation | 22.3 h; 0.50 | 469.7 h; 0.53 | 13.0 h; 0.13 | 165.1 h; 0.39 |
| lof_deviation | 17.4 h; 0.50 | 182.8 h; 0.87 | 13.0 h; 0.13 | 16.5 h; 0.33 |
| rules_correlation | 19.9 h; 0.50 | 350.8 h; 0.63 | n/a h; n/a | 350.6 h; 0.50 |
| hybrid | 22.3 h; 0.50 | 350.6 h; 0.63 | n/a h; n/a | 198.6 h; 0.50 |
| supervised_gbm_reference | 93.7 h; 0.25 | 50.7 h; 0.95 | n/a h; n/a | 54.5 h; 0.50 |

### 95 % user-bootstrap intervals (window level)

| Model | Precision | Recall | FPR |
|---|---|---|---|
| baseline_fixed_rules | [0.0068, 0.0876] | [0.0363, 0.462] | [0.0052, 0.0273] |
| robust_z_own | [0.0, 0.0457] | [0.0, 0.0764] | [0.0032, 0.006] |
| existing_iforest_raw | [0.0, 0.0833] | [0.0, 0.1043] | [0.0008, 0.0078] |
| iforest_deviation | [0.0494, 0.3018] | [0.0988, 0.3706] | [0.0015, 0.0063] |
| lof_deviation | [0.0016, 0.0314] | [0.0095, 0.158] | [0.0074, 0.0313] |
| rules_correlation | [0.0177, 0.3083] | [0.0378, 0.2968] | [0.0015, 0.004] |
| hybrid | [0.0206, 0.326] | [0.0556, 0.3784] | [0.0018, 0.0045] |
| supervised_gbm_reference | [0.0114, 0.5215] | [0.031, 0.8381] | [0.001, 0.0088] |

## Track B: project-generated synthetic scenarios

### Data

| Item | Value |
|---|---|
| dataset | project-generated synthetic supplement (ml/cert/synthetic.py), source = synthetic_test |
| notice | The CERT Insider Threat Test Dataset is synthetic (generated background activity plus synthetic malicious actors). It is not real banking data and no figure derived from it describes a real organisation. |
| generator_seed | 2026 |
| seed_mode | fixed (reproducible) |
| behaviour_profile | data\processed\cert_r4.2\cert_profile.json (benign events of train-split users only) |
| users | 600 |
| days | 150 |
| start_date | 2010-03-01 |
| threat_start_fraction | 0.3 |
| windows_total | 65534 |

**event_counts**

|  | value |
|---|---|
| events_synthetic_test | 7182038 |

**label_counts**

|  | value |
|---|---|
| malicious_events | 42273 |

**scenarios**

|  | value |
|---|---|
| gradual_data_collection | 7114 |
| bulk_export | 14735 |
| unusual_external_transfer | 43 |
| removable_media_exfiltration | 16396 |
| account_misuse | 1102 |
| multi_stage_sequence | 2883 |
| legit_large_transfer | 30 |
| approved_odd_hours | 353107 |
| frequent_authorised_access | 480017 |
| routine_removable_media | 430 |

**selected_files**

| file | bytes | sha256 |
|---|---|---|
| events_synthetic_test.csv.gz | 130186154 | 9e210244a5424d6f7e1ccf60ad6101585513c6542e5969fd0c60e856c1d57203 |
| labels.csv | 1817767 | d365fc784702f9052204043d77d9fb562472daebaebbde6811f87fb6d5b0ae5f |
| eval_metadata.csv | 43354029 | 4d23d796b7057b47f347895c4648f105b9e0aa5acef7e3a4f1369c70f9c2f77c |
| splits.csv | 16348 | 7a181fb62c829692ccd6d352732c4ee46e3980730b465ae4b00046d8bcc09f3f |
| manifest.json | 3604 | b39208ec6758db65915a3d1bae8610f203b858c672915787bd8c76bac2c894f4 |

**user_splits**

| split | users | insiders |
|---|---|---|
| test | 180 | 45 |
| train | 330 | 83 |
| validation | 90 | 22 |

### Split strategy

| Partition | Definition |
|---|---|
| users | disjoint train / validation / test (whole users) |
| time | forward-chaining cutoffs |
| train end | 2010-05-13 |
| validation end | 2010-06-14 |
| train | train users, days <= train_end |
| validation | validation users, train_end < day <= validation_end |
| test | test users, day > validation_end |

| Partition | Users | Windows | Evaluable | Malicious windows | Insiders | Events | Malicious events | Days |
|---|---|---|---|---|---|---|---|---|
| train | 330 | 18019 | 16170 | 27 | 20 | 1969191 | 5614 | 2010-03-01 to 2010-05-13 |
| validation | 90 | 2003 | 1980 | 3 | 3 | 216892 | 1286 | 2010-05-14 to 2010-06-14 |
| test | 180 | 5817 | 5759 | 39 | 11 | 642350 | 4585 | 2010-06-15 to 2010-08-04 |

Incident status (an incident belongs to exactly one user, so it cannot be split across partitions; incidents that straddle a cutoff are excluded, not half-used):

| Split | Status | Incidents |
|---|---|---|
| test | before_test_period | 30 |
| test | evaluated | 13 |
| test | straddles_test_cutoff | 2 |
| train | not_in_test | 81 |
| train | straddles_train_cutoff | 2 |
| validation | not_in_test | 22 |

Windows excluded: warm-up (< 5 baseline days), unlabelled/ambiguous, straddling incidents. Test partition: 47 warm-up, 0 unlabelled, 12 straddling.

### Model configuration and thresholds

| Model | Role | Threshold rule | Threshold |
|---|---|---|---|
| baseline_fixed_rules | simple baseline rules (fixed thresholds, no model) | fixed | 1.00000 |
| robust_z_own | simple baseline: own-history z-scores | validation_quantile (target FPR 0.005) | 0.99245 |
| existing_iforest_raw | existing detector: Isolation Forest on raw volumes | validation_quantile (target FPR 0.005) | 0.99412 |
| iforest_deviation | improved: Isolation Forest on deviation features | validation_quantile (target FPR 0.005) | 0.99682 |
| lof_deviation | improved alternative: Local Outlier Factor | validation_quantile (target FPR 0.005) | 0.99742 |
| rules_correlation | improved: rules + correlation, no model | validation_quantile (target FPR 0.005) | 0.25346 |
| hybrid | improved: rules + correlation + anomaly model | validation_quantile (target FPR 0.005) | 0.41567 |
| supervised_gbm_reference | reference ceiling: supervised, uses labels | validation_quantile (target FPR 0.005) | 0.00031 |

Full hyper-parameters, feature list and baseline-rule thresholds are in `results.json` (`model_configuration`, `features`).

### Window level (one user-day; this is the primary unit)

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN | ROC-AUC | AP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| baseline_fixed_rules | 0.367 | 0.282 | 0.319 | 0.003 | 0.718 | 11 | 19 | 28 | 5701 | 0.951 | 0.326 |
| robust_z_own | 0.444 | 0.308 | 0.364 | 0.003 | 0.692 | 12 | 15 | 27 | 5705 | 0.818 | 0.328 |
| existing_iforest_raw | 0.172 | 0.128 | 0.147 | 0.004 | 0.872 | 5 | 24 | 34 | 5696 | 0.737 | 0.135 |
| iforest_deviation | 0.167 | 0.282 | 0.209 | 0.010 | 0.718 | 11 | 55 | 28 | 5665 | 0.891 | 0.273 |
| lof_deviation | 0.237 | 0.718 | 0.357 | 0.016 | 0.282 | 28 | 90 | 11 | 5630 | 0.945 | 0.476 |
| rules_correlation | 0.341 | 0.795 | 0.477 | 0.011 | 0.205 | 31 | 60 | 8 | 5660 | 0.944 | 0.530 |
| hybrid | 0.313 | 0.667 | 0.426 | 0.010 | 0.333 | 26 | 57 | 13 | 5663 | 0.926 | 0.468 |
| supervised_gbm_reference | 0.395 | 0.385 | 0.390 | 0.004 | 0.615 | 15 | 23 | 24 | 5697 | 0.701 | 0.344 |

### Event level (a window alert flags every event in it; TP/FN count malicious events, FP/TN benign events)

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| baseline_fixed_rules | 0.453 | 0.836 | 0.588 | 0.006 | 0.164 | 3067 | 3703 | 601 | 629713 |
| robust_z_own | 0.499 | 0.849 | 0.628 | 0.005 | 0.151 | 3113 | 3131 | 555 | 630285 |
| existing_iforest_raw | 0.319 | 0.240 | 0.274 | 0.003 | 0.760 | 879 | 1873 | 2789 | 631543 |
| iforest_deviation | 0.254 | 0.644 | 0.364 | 0.011 | 0.356 | 2361 | 6953 | 1307 | 626463 |
| lof_deviation | 0.222 | 0.959 | 0.360 | 0.019 | 0.041 | 3518 | 12335 | 150 | 621081 |
| rules_correlation | 0.265 | 0.974 | 0.417 | 0.016 | 0.026 | 3573 | 9896 | 95 | 623520 |
| hybrid | 0.278 | 0.948 | 0.430 | 0.014 | 0.052 | 3476 | 9039 | 192 | 624377 |
| supervised_gbm_reference | 0.426 | 0.851 | 0.568 | 0.007 | 0.149 | 3123 | 4203 | 545 | 629213 |

### User level (flagged if any evaluated window alerted; insider if any evaluated window is malicious)

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| baseline_fixed_rules | 0.364 | 0.727 | 0.485 | 0.083 | 0.273 | 8 | 14 | 3 | 155 |
| robust_z_own | 0.429 | 0.818 | 0.562 | 0.071 | 0.182 | 9 | 12 | 2 | 157 |
| existing_iforest_raw | 0.312 | 0.455 | 0.370 | 0.065 | 0.545 | 5 | 11 | 6 | 158 |
| iforest_deviation | 0.421 | 0.727 | 0.533 | 0.065 | 0.273 | 8 | 11 | 3 | 158 |
| lof_deviation | 0.367 | 1.000 | 0.537 | 0.112 | 0.000 | 11 | 19 | 0 | 150 |
| rules_correlation | 0.500 | 1.000 | 0.667 | 0.065 | 0.000 | 11 | 11 | 0 | 158 |
| hybrid | 0.688 | 1.000 | 0.815 | 0.030 | 0.000 | 11 | 5 | 0 | 164 |
| supervised_gbm_reference | 0.367 | 1.000 | 0.537 | 0.112 | 0.000 | 11 | 19 | 0 | 150 |

### Recall at fixed validation false-positive rates (window level)

| Model | 0.1 % FPR | 0.5 % FPR | 1 % FPR |
|---|---|---|---|
| baseline_fixed_rules | n/a | n/a | n/a |
| robust_z_own | 0.308 (obs. 0.0009) | 0.308 (obs. 0.0026) | 0.308 (obs. 0.0089) |
| existing_iforest_raw | 0.103 (obs. 0.0021) | 0.128 (obs. 0.0042) | 0.231 (obs. 0.0091) |
| iforest_deviation | 0.231 (obs. 0.0000) | 0.282 (obs. 0.0096) | 0.308 (obs. 0.0208) |
| lof_deviation | 0.564 (obs. 0.0044) | 0.718 (obs. 0.0157) | 0.821 (obs. 0.0229) |
| rules_correlation | 0.615 (obs. 0.0051) | 0.795 (obs. 0.0105) | 0.821 (obs. 0.0168) |
| hybrid | 0.513 (obs. 0.0044) | 0.667 (obs. 0.0100) | 0.692 (obs. 0.0156) |
| supervised_gbm_reference | 0.359 (obs. 0.0009) | 0.385 (obs. 0.0040) | 0.385 (obs. 0.0075) |

Alerts per 1,000 evaluated windows: baseline_fixed_rules 5.21, robust_z_own 4.69, existing_iforest_raw 5.04, iforest_deviation 11.46, lof_deviation 20.49, rules_correlation 15.8, hybrid 14.41, supervised_gbm_reference 6.6

### Per scenario (window recall; incidents detected)

| Model | account_misuse | bulk_export | gradual_data_collection | multi_stage_sequence | removable_media_exfiltration |
|---|---|---|---|---|---|
| baseline_fixed_rules | 0.000; 0/2 | 1.000; 2/2 | 0.000; 0/2 | 1.000; 3/4 | 1.000; 3/3 |
| robust_z_own | 1.000; 1/2 | 1.000; 2/2 | 0.000; 0/2 | 1.000; 3/4 | 1.000; 3/3 |
| existing_iforest_raw | 0.000; 0/2 | 0.000; 0/2 | 0.000; 0/2 | 1.000; 3/4 | 0.333; 2/3 |
| iforest_deviation | 1.000; 1/2 | 0.500; 1/2 | 0.000; 0/2 | 1.000; 3/4 | 1.000; 3/3 |
| lof_deviation | 1.000; 1/2 | 1.000; 2/2 | 0.593; 2/2 | 1.000; 3/4 | 1.000; 3/3 |
| rules_correlation | 1.000; 1/2 | 1.000; 2/2 | 0.704; 2/2 | 1.000; 3/4 | 1.000; 3/3 |
| hybrid | 1.000; 1/2 | 1.000; 2/2 | 0.518; 2/2 | 1.000; 3/4 | 1.000; 3/3 |
| supervised_gbm_reference | 1.000; 1/2 | 1.000; 2/2 | 0.111; 2/2 | 1.000; 3/4 | 1.000; 3/3 |

### Detection delay (hours from the first malicious event to the end of the first alerted day) and early-warning share

Share = median fraction of an incident's events that came after the first alert (0 means the alert came after the incident ended). Windows are scored at day end, so a single-day incident cannot be alerted earlier than its own day.

| Model | account_misuse | bulk_export | gradual_data_collection | multi_stage_sequence | removable_media_exfiltration | all |
|---|---|---|---|---|---|---|
| baseline_fixed_rules | n/a h; n/a | 10.9 h; 0.00 | n/a h; n/a | 2.0 h; 0.00 | 1.3 h; 0.52 | 2.4 h; 0.00 |
| robust_z_own | 21.1 h; 0.00 | 10.9 h; 0.00 | n/a h; n/a | 2.0 h; 0.00 | 1.3 h; 0.52 | 2.9 h; 0.00 |
| existing_iforest_raw | n/a h; n/a | n/a h; n/a | n/a h; n/a | 2.0 h; 0.00 | 37.1 h; 0.12 | 2.9 h; 0.00 |
| iforest_deviation | 21.1 h; 0.00 | 12.6 h; 0.00 | n/a h; n/a | 2.0 h; 0.00 | 1.3 h; 0.52 | 2.4 h; 0.00 |
| lof_deviation | 21.1 h; 0.00 | 10.9 h; 0.00 | 193.4 h; 0.63 | 2.0 h; 0.00 | 1.3 h; 0.52 | 9.1 h; 0.00 |
| rules_correlation | 21.1 h; 0.00 | 10.9 h; 0.00 | 133.5 h; 0.75 | 2.0 h; 0.00 | 1.3 h; 0.52 | 9.1 h; 0.00 |
| hybrid | 21.1 h; 0.00 | 10.9 h; 0.00 | 217.4 h; 0.57 | 2.0 h; 0.00 | 1.3 h; 0.52 | 9.1 h; 0.00 |
| supervised_gbm_reference | 21.1 h; 0.00 | 10.9 h; 0.00 | 181.4 h; 0.49 | 2.0 h; 0.00 | 1.3 h; 0.52 | 9.1 h; 0.00 |

### False alerts on benign lookalike windows (legitimate large transfers, odd hours, routine USB use)

| Model | approved_odd_hours | frequent_authorised_access | legit_large_transfer | routine_removable_media |
|---|---|---|---|---|
| baseline_fixed_rules | 5/231 | 7/384 | 3/3 | 0/32 |
| robust_z_own | 0/231 | 2/384 | 0/3 | 0/32 |
| existing_iforest_raw | 17/231 | 1/384 | 0/3 | 3/32 |
| iforest_deviation | 4/231 | 1/384 | 0/3 | 3/32 |
| lof_deviation | 7/231 | 0/384 | 3/3 | 3/32 |
| rules_correlation | 2/231 | 0/384 | 0/3 | 4/32 |
| hybrid | 0/231 | 0/384 | 0/3 | 0/32 |
| supervised_gbm_reference | 1/231 | 0/384 | 3/3 | 0/32 |

### 95 % user-bootstrap intervals (window level)

| Model | Precision | Recall | FPR |
|---|---|---|---|
| baseline_fixed_rules | [0.1296, 0.6046] | [0.0833, 1.0] | [0.0016, 0.0055] |
| robust_z_own | [0.1579, 0.6759] | [0.0993, 1.0] | [0.0013, 0.0042] |
| existing_iforest_raw | [0.0444, 0.3913] | [0.0284, 0.6081] | [0.0016, 0.0074] |
| iforest_deviation | [0.0869, 0.2599] | [0.0833, 1.0] | [0.0041, 0.0165] |
| lof_deviation | [0.0948, 0.3827] | [0.6313, 1.0] | [0.0089, 0.025] |
| rules_correlation | [0.1601, 0.5039] | [0.7167, 1.0] | [0.0052, 0.0165] |
| hybrid | [0.1586, 0.5122] | [0.5633, 1.0] | [0.0038, 0.017] |
| supervised_gbm_reference | [0.1944, 0.5842] | [0.2018, 1.0] | [0.0024, 0.006] |

## Track C: manually created unit-test scenarios

### Data

| Item | Value |
|---|---|
| dataset | manually created unit-test scenarios (ml/detect/scenarios.py) |
| generator_seed | 5 |
| users | 40 |
| days | 75 |
| windows_total | 2205 |
| note | 36 ordinary users (24 train, 12 validation) and 4 scenario users held out as the test partition |

**event_counts**

|  | value |
|---|---|
| events | 121884 |

**label_counts**

|  | value |
|---|---|
| malicious_events | 688 |

**scenarios**

|  | value |
|---|---|
| S0039 (bulk_export) | malicious |
| S0038 (gradual_data_collection) | malicious |
| S0037 (legit_large_transfer) | benign |
| S0036 (routine_large_transfers) | benign |

### Split strategy

| Partition | Definition |
|---|---|
| users | disjoint train / validation / test (whole users) |
| time | none (users only) |
| train end | None |
| validation end | None |
| train | train users, all days |
| validation | validation users, all days |
| test | test users, all days |

| Partition | Users | Windows | Evaluable | Malicious windows | Insiders | Events | Malicious events | Days |
|---|---|---|---|---|---|---|---|---|
| train | 24 | 1320 | 1200 | 0 | 0 | 72918 | 0 | 2010-03-01 to 2010-05-14 |
| validation | 12 | 660 | 600 | 0 | 0 | 36109 | 0 | 2010-03-01 to 2010-05-14 |
| test | 4 | 225 | 200 | 12 | 2 | 12857 | 688 | 2010-03-01 to 2010-05-14 |

Incident status (an incident belongs to exactly one user, so it cannot be split across partitions; incidents that straddle a cutoff are excluded, not half-used):

| Split | Status | Incidents |
|---|---|---|
| test | evaluated | 2 |

Windows excluded: warm-up (< 5 baseline days), unlabelled/ambiguous, straddling incidents. Test partition: 25 warm-up, 0 unlabelled, 0 straddling.

### Model configuration and thresholds

| Model | Role | Threshold rule | Threshold |
|---|---|---|---|
| baseline_fixed_rules | simple baseline rules (fixed thresholds, no model) | fixed | 1.00000 |
| robust_z_own | simple baseline: own-history z-scores | validation_quantile (target FPR 0.005) | 0.99084 |
| existing_iforest_raw | existing detector: Isolation Forest on raw volumes | validation_quantile (target FPR 0.005) | 0.99750 |
| iforest_deviation | improved: Isolation Forest on deviation features | validation_quantile (target FPR 0.005) | 0.99667 |
| lof_deviation | improved alternative: Local Outlier Factor | validation_quantile (target FPR 0.005) | 0.99750 |
| rules_correlation | improved: rules + correlation, no model | validation_quantile (target FPR 0.005) | 0.17782 |
| hybrid | improved: rules + correlation + anomaly model | validation_quantile (target FPR 0.005) | 0.29102 |

Skipped: supervised_gbm_reference (only 0 labelled malicious train windows (minimum 20))

Full hyper-parameters, feature list and baseline-rule thresholds are in `results.json` (`model_configuration`, `features`).

### Window level (one user-day; this is the primary unit)

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN | ROC-AUC | AP |
|---|---|---|---|---|---|---|---|---|---|---|---|
| baseline_fixed_rules | 0.071 | 0.083 | 0.077 | 0.069 | 0.917 | 1 | 13 | 11 | 175 | 0.911 | 0.348 |
| robust_z_own | 1.000 | 0.083 | 0.154 | 0.000 | 0.917 | 1 | 0 | 11 | 188 | 0.711 | 0.238 |
| existing_iforest_raw | 0.000 | 0.000 | 0.000 | 0.005 | 1.000 | 0 | 1 | 12 | 187 | 0.607 | 0.092 |
| iforest_deviation | 0.500 | 0.167 | 0.250 | 0.011 | 0.833 | 2 | 2 | 10 | 186 | 0.815 | 0.298 |
| lof_deviation | 0.421 | 0.667 | 0.516 | 0.059 | 0.333 | 8 | 11 | 4 | 177 | 0.829 | 0.330 |
| rules_correlation | 0.500 | 0.583 | 0.538 | 0.037 | 0.417 | 7 | 7 | 5 | 181 | 0.750 | 0.634 |
| hybrid | 0.583 | 0.583 | 0.583 | 0.027 | 0.417 | 7 | 5 | 5 | 183 | 0.747 | 0.600 |

### Event level (a window alert flags every event in it; TP/FN count malicious events, FP/TN benign events)

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| baseline_fixed_rules | 0.382 | 0.699 | 0.494 | 0.070 | 0.301 | 481 | 777 | 207 | 10278 |
| robust_z_own | 0.901 | 0.699 | 0.787 | 0.005 | 0.301 | 481 | 53 | 207 | 11002 |
| existing_iforest_raw | 0.000 | 0.000 | 0.000 | 0.006 | 1.000 | 0 | 69 | 688 | 10986 |
| iforest_deviation | 0.677 | 0.701 | 0.689 | 0.021 | 0.299 | 482 | 230 | 206 | 10825 |
| lof_deviation | 0.373 | 0.933 | 0.533 | 0.098 | 0.067 | 642 | 1080 | 46 | 9975 |
| rules_correlation | 0.436 | 0.908 | 0.589 | 0.073 | 0.092 | 625 | 809 | 63 | 10246 |
| hybrid | 0.468 | 0.908 | 0.618 | 0.064 | 0.092 | 625 | 710 | 63 | 10345 |

### User level (flagged if any evaluated window alerted; insider if any evaluated window is malicious)

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| baseline_fixed_rules | 0.333 | 0.500 | 0.400 | 1.000 | 0.500 | 1 | 2 | 1 | 0 |
| robust_z_own | 1.000 | 0.500 | 0.667 | 0.000 | 0.500 | 1 | 0 | 1 | 2 |
| existing_iforest_raw | 0.000 | 0.000 | 0.000 | 0.500 | 1.000 | 0 | 1 | 2 | 1 |
| iforest_deviation | 0.667 | 1.000 | 0.800 | 0.500 | 0.000 | 2 | 1 | 0 | 1 |
| lof_deviation | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 2 | 0 | 0 | 2 |
| rules_correlation | 0.667 | 1.000 | 0.800 | 0.500 | 0.000 | 2 | 1 | 0 | 1 |
| hybrid | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 2 | 0 | 0 | 2 |

### Recall at fixed validation false-positive rates (window level)

| Model | 0.1 % FPR | 0.5 % FPR | 1 % FPR |
|---|---|---|---|
| baseline_fixed_rules | n/a | n/a | n/a |
| robust_z_own | 0.083 (obs. 0.0000) | 0.083 (obs. 0.0000) | 0.167 (obs. 0.0053) |
| existing_iforest_raw | 0.000 (obs. 0.0053) | 0.000 (obs. 0.0053) | 0.000 (obs. 0.0160) |
| iforest_deviation | 0.167 (obs. 0.0106) | 0.167 (obs. 0.0106) | 0.167 (obs. 0.0213) |
| lof_deviation | 0.000 (obs. 0.0000) | 0.667 (obs. 0.0585) | 0.750 (obs. 0.1064) |
| rules_correlation | 0.583 (obs. 0.0319) | 0.583 (obs. 0.0372) | 0.667 (obs. 0.0585) |
| hybrid | 0.583 (obs. 0.0213) | 0.583 (obs. 0.0266) | 0.583 (obs. 0.0425) |

Alerts per 1,000 evaluated windows: baseline_fixed_rules 70.0, robust_z_own 5.0, existing_iforest_raw 5.0, iforest_deviation 20.0, lof_deviation 95.0, rules_correlation 70.0, hybrid 60.0

### Per scenario (window recall; incidents detected)

| Model | bulk_export | gradual_data_collection |
|---|---|---|
| baseline_fixed_rules | 1.000; 1/1 | 0.000; 0/1 |
| robust_z_own | 1.000; 1/1 | 0.000; 0/1 |
| existing_iforest_raw | 0.000; 0/1 | 0.000; 0/1 |
| iforest_deviation | 1.000; 1/1 | 0.091; 1/1 |
| lof_deviation | 1.000; 1/1 | 0.636; 1/1 |
| rules_correlation | 1.000; 1/1 | 0.545; 1/1 |
| hybrid | 1.000; 1/1 | 0.545; 1/1 |

### Detection delay (hours from the first malicious event to the end of the first alerted day) and early-warning share

Share = median fraction of an incident's events that came after the first alert (0 means the alert came after the incident ended). Windows are scored at day end, so a single-day incident cannot be alerted earlier than its own day.

| Model | bulk_export | gradual_data_collection | all |
|---|---|---|---|
| baseline_fixed_rules | 13.9 h; 0.00 | n/a h; n/a | 13.9 h; 0.00 |
| robust_z_own | 13.9 h; 0.00 | n/a h; n/a | 13.9 h; 0.00 |
| existing_iforest_raw | n/a h; n/a | n/a h; n/a | n/a h; n/a |
| iforest_deviation | 13.9 h; 0.00 | 350.5 h; 0.00 | 182.2 h; 0.00 |
| lof_deviation | 13.9 h; 0.00 | 110.5 h; 0.70 | 62.2 h; 0.35 |
| rules_correlation | 13.9 h; 0.00 | 182.5 h; 0.58 | 98.2 h; 0.29 |
| hybrid | 13.9 h; 0.00 | 182.5 h; 0.58 | 98.2 h; 0.29 |

### False alerts on benign lookalike windows (legitimate large transfers, odd hours, routine USB use)

| Model | legit_large_transfer |
|---|---|
| baseline_fixed_rules | 13/13 |
| robust_z_own | 0/13 |
| existing_iforest_raw | 1/13 |
| iforest_deviation | 0/13 |
| lof_deviation | 0/13 |
| rules_correlation | 1/13 |
| hybrid | 0/13 |

### 95 % user-bootstrap intervals (window level)

| Model | Precision | Recall | FPR |
|---|---|---|---|
| baseline_fixed_rules | [0.0, 0.8875] | [0.0, 1.0] | [0.0, 0.1831] |
| robust_z_own | [1.0, 1.0] | [0.0, 1.0] | [0.0, 0.0] |
| existing_iforest_raw | [0.0, 0.0] | [0.0, 0.0] | [0.0, 0.0151] |
| iforest_deviation | [0.0, 1.0] | [0.0909, 1.0] | [0.0, 0.0232] |
| lof_deviation | [0.2, 0.5] | [0.6364, 1.0] | [0.0, 0.1257] |
| rules_correlation | [0.0, 0.6667] | [0.5455, 1.0] | [0.0124, 0.0664] |
| hybrid | [0.5, 0.6] | [0.5455, 1.0] | [0.0, 0.0719] |

## Limitations

* The CERT Insider Threat Test Dataset is synthetic (generated background users plus synthetic malicious actors). It is not real banking data, and its scenarios (removable-media theft, job-site browsing, an administrator keylogger) may not represent real organisations.
* CERT r4.2 is a "dense needles" release: malicious activity is far more common than in reality, so precision and F1 are inflated relative to a real deployment and must not be extrapolated.
* Labels may be incomplete. The answer key lists the events the red team injected; an insider's unlisted activity is treated as benign by convention (or excluded when inside the incident window), and events listed under another account are excluded as ambiguous.
* There are few incidents in the held-out CERT partition, so intervals are wide and per-scenario figures (especially scenario 3) are indicative only.
* Validation windows used for calibration cover a short period, so thresholds are noisy: the false-positive rate observed on the test partition differs from the target, and models should be compared in the fixed-FPR recall table as well as at the operating point.
* Detection delay is measured on day windows scored at day end; it cannot show earlier-than-a-day detection, and single-day incidents cannot be alerted before they end. Early warning is only demonstrable for incidents that span several days.
* The synthetic and unit-test tracks were created by this project, so their scenarios reflect its own assumptions and the destination-category lists were written after reading the CERT scenario descriptions (results with them are optimistic for those scenarios).
* The 'existing detector' is the original approach (Isolation Forest on raw per-day volumes). The live application engine scores individual events with IP-based features that do not exist in CERT, so it cannot be run on this data.
* This project has not been validated for live banking use. It does not protect a real network; containment is a simulation of application state.
