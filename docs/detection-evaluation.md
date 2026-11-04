# Detection quality: features, models, evaluation and what the numbers do and do not show

This document covers the offline detection pipeline in `ml/detect/` and how it was evaluated. It does not claim that the
system prevents attacks on a real bank. All data is synthetic: the CERT Insider Threat Test Dataset r4.2
([docs/cert-dataset.md](cert-dataset.md)) and a separate project-generated supplement. Containment in the application
is a controlled simulation of application state.

Full result tables are in [docs/detection-results/](detection-results): `cert_test.md` (primary), `cert_nocat_test.md`
(ablation), `synthetic_test.md` (controlled scenarios, a separate report), and the `*_validation.md` development runs.

## 1. What was wrong, reproduced on held-out users

The first version scored each session with an Isolation Forest on raw volume features. On the project's earlier
synthetic sessions it caught only 3.3 % of bare bulk exports (README, "Machine learning in detail"); the volume guard
fixed that for the live engine. To check the weakness on *held-out users with a proper evaluation*, the same kind of
model ("iforest_raw": Isolation Forest on log-scaled per-day raw counts, no baselines) was evaluated here:

| Held-out evaluation | iforest_raw result |
|---|---|
| Synthetic supplement, test users, `bulk_export` | **0 of 7 incidents detected, window recall 0.000** |
| Synthetic supplement, test users, `gradual_data_collection` | 0 of 5, window recall 0.000 |
| CERT r4.2, test users, all scenarios | 4 of 21 incidents, window recall 0.018, precision 0.013 |

So the weakness is real and general: unsupervised anomaly detection on raw magnitudes does not reliably see bulk-export or
exfiltration-like behaviour. Everything below is the attempt to fix that without hiding its limits.

## 2. Windows and features

**Unit:** one *window* = one user on one calendar day, from the canonical event schema (`ml/detect/windows.py`). An alert
for a window is raised **at the end of that day** (this matters for the early-warning results in section 6).

Rules the pipeline obeys (each has a test in `tests/test_detection_pipeline.py`): duplicate event ids are dropped; rows
with an unusable timestamp or no entity are dropped and counted; missing fields are treated as absent, never imputed
(`n_incomplete_events` counts them); all aggregates are order independent, so events arriving out of order give identical
windows; a window's features use only earlier days; no feature reads a label or identity column
(`ml.cert.leakage.assert_no_leakage(FEATURE_COLUMNS)`).

| Group | Features (all in `ml/detect/features.py`, documented in `FEATURE_DOC`) | Window |
|---|---|---|
| Daily volumes | counts of removable-media connects and file copies, e-mails (external, bytes, attachments), web visits, distinct / first-time / rare destinations, hosts used, failed logons, after-hours events, copy bursts, copies while a device was connected | 1 day (burst: 10 min; copy-while-connected: 4 h) |
| Own-history deviation | `z_own_*`: z-score of log1p(volume) against the user's active days of the same day type (weekday/weekend) in the previous 28 days (needs >= 5); start/end hour deviation | 28 days before |
| Excess over own maximum | `excess_max28_*`: log1p(x) minus log1p(largest day in the previous 28), robust for zero-inflated quantities like external e-mail bytes | 28 days before |
| Peer-group deviation | `z_peer_*`: the same z-score against the user's peer group (LDAP role), fitted on **benign train users only** | fitted offline |
| Gradual change | `log_ratio7_*`: last 7 days against the 28 days before them | 7 vs 28 days |
| Sustained drift | `z_long_*` against a **lagged** own baseline (days d-112 to d-29), and leaky one-sided CUSUMs of it and of the peer z-score | 84 days, lagged 28 |
| Sequences | rare destination then removable-media activity within 3 h; removable media then external e-mail the same day; file access then external e-mail | 3 h / 1 day |
| Destination categories (optional) | visits to job-search sites and to file-sharing / document-leak sites | 1 day |

Why the lagged baseline and CUSUM: a plain 28-day baseline quietly *absorbs* a slow increase (the "boiling frog"), which is
exactly what CERT scenario 2 is. Measured on the **train split** before designing the rules (single-feature AUC for scenario 2
against benign windows): own-history 7/14/28-day ratios about 0.58, requiring both the own and the peer deviation to be high
0.73, the peer-group CUSUM of thumb-drive use 0.92, and the CUSUM against a lagged own baseline 0.73. The rules therefore use
sustained drift against *both* a lagged own baseline and the peer group, which also keeps chronically heavy users quiet.

**Destination categories are an enrichment and are optimistic.** The CERT hosts are real site names and benign users visit
job and file-sharing sites heavily, so only *change against the user's own history* is informative. The two small exact-name
lists (`CATEGORY_JOB`, `CATEGORY_EXFIL` in `windows.py`) stand in for a web-categorisation feed; they were written after
reading the public scenario descriptions, so the CERT results *with* them are optimistic for scenarios 1 and 2. Everything
is therefore also reported **without** them (section 5).

## 3. Models compared

All unsupervised models are fitted on benign **train** windows only; scores are normalised by the empirical CDF of the training
scores so they are comparable.

| Name | What it is |
|---|---|
| `iforest_raw` | Isolation Forest on raw log volumes, no baselines (the original approach) |
| `iforest_deviation` | the same Isolation Forest on all deviation, drift and sequence features |
| `lof_deviation` | Local Outlier Factor (novelty mode, 30 000-window subsample) on the same features |
| `robust_z_own` | non-ML: mean of the three largest positive own-history z-scores of the day |
| `rules_correlation` | explicit behavioural rules + correlation over a decaying 7-day window, no anomaly model |
| `hybrid` | rules + correlation + the anomaly model (`iforest_deviation`), see below |
| `supervised_gbm_reference` | gradient boosting trained on **labelled** train windows. A reference ceiling only: real deployments rarely have labels, and it was trained on the same scenarios it is tested on |

## 4. The hybrid risk: auditable and not double-counted

(`ml/detect/hybrid.py`)

* **Evidence families, each counted once.** Every rule belongs to one family (collection, staging, destination, transfer,
  access, timing). A family's strength is the **maximum** of its rules, never the sum. The anomaly model is a sixth family
  and is credited only for the part of its score the rules do not already explain (`anomaly x (1 - strongest rule family)`).
* **Deviation, not magnitude.** Volume rules need deviation from the user's own history *and* the peer group, so a power user
  or a role with large normal transfers is not flagged for them. There is **no** "large transfer = critical" rule: the
  transfer family alone can contribute at most its weight (0.55), and the alert threshold is calibrated, not fixed.
* **Correlation.** Each family's evidence decays by 0.70 per day; two or more families active inside the window make a
  *suspicious sequence*; each family still counts once.
* **Risk** = `1 - prod(1 - weight x strength)` over families: bounded, every term visible. `hybrid.explain()` returns the
  reason codes with strengths, each family's weight and marginal contribution to the risk, evidence timestamps and the states
  (a test recomputes the risk from the displayed weights and strengths).
* **Weights and ramps are fixed constants chosen by judgement and then adjusted only using train and validation data**;
  they are not learned from the test users. The configuration hash of the final run is stored in
  `final_test_run_*.json`.

## 5. Evaluation protocol

* **Split:** whole users: train 550, validation 150, test 300 (CERT); fixed seed. No user appears on two sides.
* **Training:** benign train windows only (the supervised reference also uses labelled train windows).
* **Calibration:** each model's alert threshold is the benign **validation** quantile that gives a 0.5 % false-positive
  rate; test users never influence a threshold. Recall is also reported at 0.1 %, 0.5 % and 1 % validation-calibrated FPRs.
* **Test set used once:** `benchmark.run` refuses to evaluate the test split without `--final` and refuses a second run
  (`final_test_run_*.json`). Development decisions used the train and validation splits. The only second test run is the
  pre-declared ablation without destination categories, with no change made in between.
* **Labels:** a window is malicious if any of its events is listed in the answer key under the insider's own account;
  ambiguous windows (events listed under another account) and an insider's unlisted days *inside* their incident window are
  excluded, and warm-up windows (< 5 baseline days) are excluded. The excluded counts are in each report.
* **Uncertainty:** 95 % intervals come from a user-level bootstrap (resampling users).

## 6. Results (held-out test users)

### CERT r4.2 (primary), enrichment enabled

96,094 labelled windows from 300 users; 275 malicious windows from 21 insiders (0.29 % malicious: r4.2 is a "dense needles"
release, so precision here is **not** representative of a real organisation).

| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN | Incidents detected |
|---|---|---|---|---|---|---|---|---|---|---|
| iforest_raw | 0.013 | 0.018 | 0.015 | 0.0040 | 0.982 | 5 | 381 | 270 | 95,438 | 4 / 21 |
| iforest_deviation | 0.150 | 0.149 | 0.150 | 0.0024 | 0.851 | 41 | 232 | 234 | 95,587 | 19 / 21 |
| lof_deviation | 0.011 | 0.044 | 0.018 | 0.0108 | 0.956 | 12 | 1,039 | 263 | 94,780 | 7 / 21 |
| robust_z_own | 0.014 | 0.018 | 0.016 | 0.0037 | 0.982 | 5 | 358 | 270 | 95,461 | 5 / 21 |
| rules_correlation | 0.093 | 0.218 | 0.130 | 0.0061 | 0.782 | 60 | 587 | 215 | 95,232 | 11 / 21 |
| **hybrid** | **0.170** | **0.229** | **0.195** | **0.0032** | 0.771 | 63 | 307 | 212 | 95,512 | **13 / 21** |
| supervised_gbm_reference | 0.291 | 0.993 | 0.450 | 0.0070 | 0.007 | 273 | 666 | 2 | 95,153 | 20 / 21 |

Per scenario (window recall; incidents detected): scenario 1 (after-hours removable media and upload): hybrid 0.571 and
5/8; scenario 2 (job-site browsing then heavy thumb-drive use, about 55 days): hybrid 0.205 and 6/9; scenario 3
(administrator keylogger, about 1.4 days): hybrid 0.375 and 2/4. 95 % user-bootstrap intervals for the hybrid: precision
0.05 to 0.31, recall 0.08 to 0.38, FPR 0.002 to 0.004: they are wide because there are only 21 insiders.

**Ablation without destination categories** (`cert_nocat_test.md`): hybrid precision 0.117, recall 0.120, F1 0.119,
FPR 0.0026, 16 / 21 incidents; scenario 2 window recall falls from 0.205 to 0.063. The category lists help window-level
recall, so that part of the gain is the optimistic part. (Incident-level recall was *higher* without them, 16 versus 13: the
two runs have different validation-calibrated thresholds and the number of incidents is small, so this difference should not
be over-read.)

**What this shows, honestly.** The new features and the hybrid improve on the original raw-feature Isolation Forest by an
order of magnitude (recall 0.018 to 0.229, F1 0.015 to 0.195), but the unsupervised detectors remain far from the supervised
reference. The plain Isolation Forest on the new deviation features is a strong competitor: better incident recall (19 / 21)
than the hybrid at the chosen operating point and nearly the same F1, while the hybrid has the better recall at a fixed
1 % validation FPR (0.349 versus 0.233) and is the only one whose evidence is itemised. LOF's validation-calibrated threshold
did not transfer (test FPR 1.08 % against a 0.5 % target): calibrating on 150 users is noisy.

### Synthetic supplement (separate report): bulk export, gradual exfiltration, benign lookalikes

Different data, different generator, scenarios designed by this project: **do not combine with the CERT numbers.** 9,008
labelled windows from 120 users; 95 malicious windows from 30 insiders.

| Scenario (window recall; incidents) | iforest_raw | iforest_deviation | lof_deviation | hybrid | supervised ref. |
|---|---|---|---|---|---|
| bulk_export | 0.000; 0/7 | 0.167; 1/7 | 1.000; 6/7 | **1.000; 6/7** | 1.000; 6/7 |
| gradual_data_collection | 0.000; 0/5 | 0.000; 0/5 | 0.059; 3/5 | 0.059; 4/5 | 0.985; 5/5 |
| unusual_external_transfer | 0.000; 0/4 | 0.000; 0/4 | 1.000; 4/4 | **0.000; 0/4** | 1.000; 4/4 |
| removable_media_exfiltration | 0.429; 1/3 | 1.000; 3/3 | 1.000; 3/3 | 1.000; 3/3 | 1.000; 3/3 |
| account_misuse | 0.143; 1/7 | 0.000; 0/7 | 1.000; 7/7 | 0.429; 3/7 | 1.000; 7/7 |
| multi_stage_sequence | 1.000; 3/4 | 1.000; 3/4 | 1.000; 3/4 | 1.000; 3/4 | 1.000; 3/4 |

**Benign large transfers (false-positive rate on benign lookalike windows):** the hybrid raised **0** false alerts on
`legit_large_transfer` (0/3), `approved_odd_hours` (0/525), `frequent_authorised_access` (0/525) and `routine_removable_media`
(0/45). LOF and the supervised model alerted on **3 of 3** legitimate large transfers (they learned "large transfer =
bad"), and the raw Isolation Forest flagged 6.3 % of approved-odd-hours windows. Overall synthetic test results: hybrid
precision 0.575, recall 0.242, F1 0.341, FPR 0.0019; only 3 benign large-transfer windows exist, so that comparison is
indicative, not statistically strong.

**Where the hybrid is weak:** it never detected `unusual_external_transfer` (0 / 4), missed 4 of 7 `account_misuse` incidents,
and its gradual-collection detections were late (see below).

### Detection delay and early warning

Delay is measured from the first malicious event of an incident to the **end of the first alerted day** (windows are
scored at day end). "Share after alert" is the median fraction of an incident's listed events that happened *after* that alert.

| Incident type | Hybrid median delay | Median share of events after the alert | Early warning? |
|---|---|---|---|
| CERT scenario 2 (about 55 days) | 387 h (16 days) | 0.62 | **Yes**: most of the incident was still ahead |
| CERT scenario 1 (about 5 days) | 17 h | 0.50 | partial |
| CERT scenario 3 (about 1.4 days) | 14 h | 0.13 | **No**: the alert came after almost all of it |
| Synthetic, single-day patterns (bulk export, removable media, multi-stage, misuse) | 1 to 23 h | 0.00 to 0.70 | essentially **no** for single-day bulk export |
| Synthetic gradual collection | 447 h | 0.00 | **No**: detected only after the campaign ended |

So the early-warning goal is supported only for incidents that span many days. With whole-day windows scored at day end, a
single-day bulk export is flagged after it has happened, and this evaluation does **not** show early detection of it. The
application's live engine scores every event as it arrives and alerts before the final transfer in the simulation
(README "The simulated attack, step by step"), but that is a different mechanism and a scripted scenario; intra-day windows
in this pipeline are the obvious next step.

## 7. Metrics that cannot be computed reliably

* **Per-scenario precision / false-positive rate on CERT:** benign windows do not belong to a scenario, so there is no
  per-scenario denominator. Only per-scenario *recall* is reported.
* **A bulk-export-specific CERT result:** r4.2 has no bulk-export scenario (scenario 1 is the nearest). Bulk-export results
  come only from the synthetic supplement.
* **Precision in the real world:** r4.2 is a dense-needles dataset, so precision and F1 are inflated relative to real prevalence.
* **Delay for undetected incidents** is undefined (shown as n/a), and the medians use few incidents (scenario 3 has 4 in the test set).
* **Whether labelled windows are complete:** the answer key lists the events the red team injected; unlisted insider activity
  is treated as benign by convention (or excluded when inside the incident window), which can only be reported, not corrected.
* **FPR transfer:** thresholds from 150 validation users do not give exactly the target FPR on test users (0.24 % to 1.08 %
  across models), so compare models at the fixed-FPR recall table, not only at the operating point.

## 8. The five states in the application

`backend/detection_states.py`, shown in the SOC overview and on every investigation page with the reason for each state.

| State | Switches on when | Can a prediction set it? |
|---|---|---|
| Anomalous activity detected | the anomaly score (0-1, not a probability) reaches the corroboration threshold chosen on validation runs (`ML_CORROBORATION_THRESHOLD`) | yes: it is a model output |
| Suspicious sequence correlated | two or more independent attack stages are correlated | yes: an inference from events |
| Potential data exposure | sensitive access, export or external-transfer evidence exists; the basis says whether an export/transfer event itself is verified | yes, but labelled "potential" |
| Confirmed malicious (simulation ground truth) | the activity was generated by the simulation, which knows it is malicious | **no**: never for live activity or a prediction |
| Simulated containment completed | a containment action completed against the simulated environment | no: it records an action |

Known limitation of the live engine: its risk score is a hand-weighted heuristic, not a probability. Earlier versions summed five
components (anomaly, rules, correlation, baseline, stage) that all restated the same evidence; the live score is now only rule
evidence (each event counted once through its strongest rule) plus the anomaly score, with the independent-stage count gating the
risk band instead of adding points. The risk-band thresholds are chosen on synthetic validation runs (`python -m ml.calibrate_scoring`,
`reports/calibration/`). The live engine still does not use the evidence-family design of section 4, and none of its numbers has been
validated on real incidents. Impact severity and evidence strength are reported separately from the score (README, "How the scores
are defined"); the investigation page itemises every component, event reference, model output and feature deviation under "How the
heuristic risk score was built".

## 9. Reproduce

```powershell
python -m ml.cert.synthetic --out data/processed/synthetic_eval --seed 42 --users 400 --days 110 --profile data/processed/cert_r4.2/cert_profile.json
python -m ml.detect.benchmark --dataset cert --processed data/processed/cert_r4.2 --eval-split validation        # development
python -m ml.detect.benchmark --dataset cert --processed data/processed/cert_r4.2 --eval-split test --final       # once
python -m ml.detect.benchmark --dataset cert --processed data/processed/cert_r4.2 --eval-split test --final --no-categories
python -m ml.detect.benchmark --dataset synthetic --processed data/processed/synthetic_eval --eval-split test --final
python -m ml.detect.summary data/processed/reports/cert_test.json --out docs/detection-results/cert_test.md
python -m pytest tests/test_detection_pipeline.py tests/test_detection_states.py -q
```

The first CERT run builds the windows (two passes over `http.csv`, about 10 minutes) and caches them next to the data.

## 10. Rigorous evaluation protocol (one command)

`ml/detect/run_evaluation.py` re-evaluates the detectors under a stricter protocol than section 5 and writes one report per
run. It supersedes nothing: section 6 is the earlier whole-timeline benchmark.

```powershell
python -m ml.detect.run_evaluation --cert-processed data/processed/cert_r4.2 --out reports/evaluation --partition test --final
python -m ml.detect.run_evaluation --out data/processed/eval_dev --partition validation      # development run, not a result
python -m pytest tests/test_evaluation_protocol.py -q
```

The committed output of the first command is in [reports/evaluation/](../reports/evaluation) (`report.md`, `results.json`,
`manifest.json`, per-track CSVs). Its manifest records the git commit and states that the working tree had uncommitted
changes when it ran (these tests and docs were added after); the frozen-hybrid check in it reads "yes".

**Protocol.** Users are split into disjoint train/validation/test sets, *and* time is cut with forward-chaining cutoffs
(CERT 45 % / 52 % of the window range: train to 2010-08-15, validation to 2010-09-19, test after that). An incident belongs
to one user; incidents that straddle a cutoff are excluded and listed, not half-used. Peer baselines, destination
statistics, models and baseline-rule thresholds are fitted on train windows; alert thresholds are the benign validation
quantile at 0.5 % FPR; the evaluated partition's labels are blanked before fitting (`blind_partition`), and a test checks
that corrupting them changes nothing. The test partition needs `--final` and runs once per output directory.

**Three tracks, never combined.** (A) held-out CERT r4.2 with dataset ground truth; (B) project-generated synthetic scenarios
(fresh seed 2026, 600 users, 150 days, attacks starting from 30 % of the timeline so that training has positives); (C) 40-user
hand-built unit scenarios (bulk export, gradual collection, a one-off legitimate large transfer, a user who routinely sends
large transfers). Each has its own thresholds and tables; the report states "no combined score".

**Compared:** the existing detector (Isolation Forest on raw volumes), simple baselines (four fixed rules with
benign-train-quantile thresholds; own-history robust z-scores), Isolation Forest and LOF on deviation features, rules +
correlation, the frozen hybrid, and the supervised reference (a ceiling that uses labels). Metrics are given at window,
event and user level, with confusion matrices, recall at fixed FPRs, per-scenario recall and incidents detected, detection
delay with the share of an incident's events after the first alert, benign-lookalike false alerts and user-bootstrap
intervals.

**What the first test run showed** (window level, 0.5 % validation-FPR operating point; read the report for the rest):

| Window-level F1 | CERT (12 incidents) | Synthetic (B) | Unit (C) |
|---|---|---|---|
| existing raw Isolation Forest | 0.021 | 0.147 | 0.000 |
| fixed-rule baseline | 0.055 | 0.319 | 0.077 |
| Isolation Forest, deviation features | 0.155 | 0.209 | 0.250 |
| hybrid (frozen) | 0.175 | 0.426 | 0.583 |
| rules + correlation only | 0.153 | 0.477 | 0.538 |
| supervised reference | 0.208 | 0.390 | n/a (no training positives) |

These are three different datasets, shown side by side only to compare models inside each column; they are not a score.

* On CERT the hybrid and the deviation Isolation Forest are clearly better than the original model, but precision is low
  (hybrid 0.158) and the hybrid missed both scenario-3 incidents (0/2) that the fixed-rule baseline and the deviation
  Isolation Forest caught. Its recall of 0.197 means most malicious days are still missed; incidents detected were 3/6, 3/4
  and 0/2 for scenarios 1, 2 and 3.
* On the synthetic track the hybrid detected bulk export 2/2 with no false alerts on the 3 legitimate large transfers, while
  the fixed-rule baseline and LOF alerted on all 3. Rules + correlation alone scored a higher F1 than the hybrid, so the
  anomaly model did not help on this track.
* In the unit track the hybrid detected both malicious users, and the bulk export alert came at the end of that day
  (0 % of the incident's events after it), so single-day exfiltration is still not caught early.
* The supervised reference is not an upper bound everywhere (it scored lower than the hybrid on the synthetic track), so
  the "ceiling" wording describes its role, not a guarantee.

**Caveats that matter.** The CERT test users were already evaluated once in section 6, so this is the same frozen
configuration on a later time slice of the same users, not a fresh unseen set. The synthetic and unit tracks are the
project's own generators and reflect its assumptions. CERT r4.2 is a synthetic "dense needles" release. The short CERT
validation period (3,434 evaluable windows) makes thresholds noisy: the observed test FPR ranged from 0.3 % to 1.7 %
across models against a 0.5 % target. Small incident counts give wide intervals. Nothing here validates the system for live
banking use.

**Leakage tests** (`tests/test_evaluation_protocol.py`) fail if an answer-key, label or identity column reaches a model, if
a feature copies the label, if a synthetic or other-source record appears in the CERT event files, if train, validation and
test users overlap or the cutoffs are out of order, or if the evaluated partition's labels influence fitting or thresholds.
