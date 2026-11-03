"""Markdown report and flat CSV tables from the evaluation results. Tracks are always reported separately: there is no
combined or averaged headline number across CERT, the synthetic supplement and the unit-test scenarios."""
import pandas as pd

from ml.detect.evaluate import MODEL_ROLES

ORDER = ["baseline_fixed_rules", "robust_z_own", "existing_iforest_raw", "iforest_deviation", "lof_deviation", "rules_correlation", "hybrid",
         "supervised_gbm_reference"]
TRACK_TITLES = {"cert": "Track A: held-out CERT r4.2 (dataset ground truth)", "synthetic": "Track B: project-generated synthetic scenarios",
                "unit_scenarios": "Track C: manually created unit-test scenarios"}


def _f(v, d=3):
    return "n/a" if v is None else (f"{v:.{d}f}" if isinstance(v, float) else str(v))


def _models(track: dict) -> list[str]:
    return [m for m in ORDER if m in track["models"]]


def flatten(track: dict, extra: dict) -> dict[str, pd.DataFrame]:
    name = track["track"]
    rows, scen, thr = [], [], []
    for model in _models(track):
        m = track["models"][model]
        for level in ("window_level", "event_level", "user_level"):
            row = m[level]
            rows.append({"track": name, "model": model, "role": m["role"], "level": level.replace("_level", ""), **{k: row.get(k) for k in (
                "precision", "recall", "f1", "false_positive_rate", "false_negative_rate", "tp", "fp", "fn", "tn", "roc_auc", "average_precision")},
                "threshold": m["threshold"], "threshold_kind": m["threshold_kind"]})
        scenarios = set(m["per_scenario_windows"]) | set(m["incidents"])
        for s in sorted(scenarios):
            w, i = m["per_scenario_windows"].get(s, {}), m["incidents"].get(s, {})
            scen.append({"track": name, "model": model, "scenario": s, "malicious_windows": w.get("malicious_windows"), "alerted_windows": w.get("alerted_windows"),
                         "window_recall": w.get("window_recall"), "incidents": i.get("incidents"), "incidents_detected": i.get("detected"),
                         "incident_recall": i.get("incident_recall"), "median_delay_hours": i.get("median_delay_hours"),
                         "median_share_of_events_after_alert": i.get("median_share_of_events_after_alert")})
        t = track["thresholds"].get(model, {})
        thr.append({"track": name, "model": model, "kind": t.get("kind"), "value": t.get("value"), "target_fpr": t.get("target_fpr"),
                    **{k: v for k, v in t.items() if k.startswith("fpr_")}})
    incidents = pd.DataFrame(extra["incident_rows"])
    if len(incidents):
        incidents.insert(0, "track", name)
    status = extra["incident_status"].copy()
    if len(status):
        status.insert(0, "track", name)
    return {f"{name}_models.csv": pd.DataFrame(rows), f"{name}_scenarios.csv": pd.DataFrame(scen), f"{name}_thresholds.csv": pd.DataFrame(thr),
            f"{name}_incidents.csv": incidents, f"{name}_incident_status.csv": status}


def _table(header: list[str], rows: list[list]) -> list[str]:
    return ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)] + ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]


def render_track(track: dict) -> list[str]:
    name = track["track"]
    part = track["evaluated_partition"]
    L = [f"## {TRACK_TITLES[name]}", ""]
    if track["development_run"]:
        L += ["> **Development run on the validation partition.** Thresholds were calibrated on these windows, so the numbers below are "
              "optimistic and are not a held-out result.", ""]
    d = track["dataset"]
    L += ["### Data", "", *_table(["Item", "Value"], [[k, v] for k, v in d.items() if not isinstance(v, (dict, list))]), ""]
    for key, val in d.items():
        if isinstance(val, dict):
            L += [f"**{key}**", "", *_table(["", "value"], [[k, v] for k, v in val.items()]), ""]
        elif isinstance(val, list) and val and isinstance(val[0], dict):
            L += [f"**{key}**", "", *_table(list(val[0]), [[_f(v) if isinstance(v, float) else v for v in r.values()] for r in val]), ""]
    s = track["split_strategy"]
    L += ["### Split strategy", "", *_table(["Partition", "Definition"], [["users", s["users"]], ["time", s["time"]], ["train end", s["train_end"]],
                                                                         ["validation end", s["validation_end"]], ["train", s["train"]],
                                                                         ["validation", s["validation"]], ["test", s["test"]]]), ""]
    P = track["partitions"]
    L += _table(["Partition", "Users", "Windows", "Evaluable", "Malicious windows", "Insiders", "Events", "Malicious events", "Days"],
                [[p, P[p]["users"], P[p]["windows"], P[p]["evaluable_windows"], P[p]["malicious_windows"], P[p]["insiders"], P[p]["events"],
                  P[p]["malicious_events"], f"{P[p]['first_day']} to {P[p]['last_day']}"] for p in ("train", "validation", "test")])
    if track["incident_status"]:
        L += ["", "Incident status (an incident belongs to exactly one user, so it cannot be split across partitions; incidents that straddle a "
              "cutoff are excluded, not half-used):", "", *_table(["Split", "Status", "Incidents"], [[r["split"], r["status"], r["incidents"]] for r in track["incident_status"]])]
    L += ["", f"Windows excluded: warm-up (< 5 baseline days), unlabelled/ambiguous, straddling incidents. Test partition: "
          f"{P['test']['baseline_warmup_windows_excluded']} warm-up, {P['test']['unlabelled_windows_excluded']} unlabelled, "
          f"{P['test']['straddling_incident_windows_excluded']} straddling.", ""]
    L += ["### Model configuration and thresholds", ""]
    rows = []
    for m in _models(track):
        t = track["thresholds"][m]
        rows.append([m, MODEL_ROLES[m], t["kind"] + (f" (target FPR {t['target_fpr']})" if t.get("target_fpr") else ""), _f(float(t["value"]), 5)])
    L += _table(["Model", "Role", "Threshold rule", "Threshold"], rows)
    if track["skipped_models"]:
        L += ["", "Skipped: " + "; ".join(f"{k} ({v})" for k, v in track["skipped_models"].items())]
    L += ["", "Full hyper-parameters, feature list and baseline-rule thresholds are in `results.json` (`model_configuration`, `features`).", ""]
    for level, title in (("window_level", "Window level (one user-day; this is the primary unit)"),
                         ("event_level", "Event level (a window alert flags every event in it; TP/FN count malicious events, FP/TN benign events)"),
                         ("user_level", "User level (flagged if any evaluated window alerted; insider if any evaluated window is malicious)")):
        L += [f"### {title}", "", *_table(["Model", "Precision", "Recall", "F1", "FPR", "FNR", "TP", "FP", "FN", "TN"] + (["ROC-AUC", "AP"] if level == "window_level" else []),
              [[m] + [_f(track["models"][m][level].get(k)) if k not in ("tp", "fp", "fn", "tn") else track["models"][m][level].get(k)
                      for k in ("precision", "recall", "f1", "false_positive_rate", "false_negative_rate", "tp", "fp", "fn", "tn")]
               + ([_f(track["models"][m][level].get("roc_auc")), _f(track["models"][m][level].get("average_precision"))] if level == "window_level" else [])
               for m in _models(track)]), ""]
    L += ["### Recall at fixed validation false-positive rates (window level)", "", *_table(
        ["Model", "0.1 % FPR", "0.5 % FPR", "1 % FPR"],
        [[m] + [(f"{_f(track['models'][m]['recall_at_validation_fpr'].get(k, {}).get('recall'))} (obs. {_f(track['models'][m]['recall_at_validation_fpr'].get(k, {}).get('observed_fpr'), 4)})"
                 if track["models"][m]["recall_at_validation_fpr"] else "n/a") for k in ("0.001", "0.005", "0.01")] for m in _models(track)]), "",
          "Alerts per 1,000 evaluated windows: " + ", ".join(f"{m} {track['models'][m]['alerts_per_1000_window_days']}" for m in _models(track)), ""]
    scenarios = sorted({s for m in track["models"].values() for s in list(m["per_scenario_windows"]) + list(m["incidents"]) if s != "all"})
    if scenarios:
        L += ["### Per scenario (window recall; incidents detected)", "", *_table(
            ["Model"] + scenarios, [[m] + [f"{_f(track['models'][m]['per_scenario_windows'].get(s, {}).get('window_recall'))}; "
                                          f"{track['models'][m]['incidents'].get(s, {}).get('detected', 'n/a')}/{track['models'][m]['incidents'].get(s, {}).get('incidents', 'n/a')}"
                                          for s in scenarios] for m in _models(track)]), "",
              "### Detection delay (hours from the first malicious event to the end of the first alerted day) and early-warning share", "",
              "Share = median fraction of an incident's events that came after the first alert (0 means the alert came after the incident ended). "
              "Windows are scored at day end, so a single-day incident cannot be alerted earlier than its own day.", "", *_table(
                  ["Model"] + scenarios + ["all"], [[m] + [("n/a" if not track["models"][m]["incidents"].get(s) else
                                                              f"{_f(track['models'][m]['incidents'][s]['median_delay_hours'], 1)} h; {_f(track['models'][m]['incidents'][s]['median_share_of_events_after_alert'], 2)}")
                                                             for s in scenarios + ["all"]] for m in _models(track)]), ""]
    look = sorted({s for m in track["models"].values() for s in m["benign_lookalikes"]})
    if look:
        L += ["### False alerts on benign lookalike windows (legitimate large transfers, odd hours, routine USB use)", "", *_table(
            ["Model"] + look, [[m] + [f"{track['models'][m]['benign_lookalikes'].get(s, {}).get('false_alerts', 0)}/{track['models'][m]['benign_lookalikes'].get(s, {}).get('benign_windows', 0)}"
                                     for s in look] for m in _models(track)]), ""]
    L += ["### 95 % user-bootstrap intervals (window level)", "", *_table(
        ["Model", "Precision", "Recall", "FPR"], [[m] + [str(track["models"][m]["ci95_user_bootstrap"].get(k)) for k in ("precision", "recall", "false_positive_rate")]
                                                  for m in _models(track)]), ""]
    return L


def render(results: dict) -> str:
    man = results["manifest"]
    L = ["# Evaluation report", "", f"Protocol **{man['protocol']['name']}**, partition evaluated: **{man['partition']}**, generated {man['generated_at']}.", "",
         "> **No combined score.** The three tracks use different data, different ground truth and different guarantees. They are reported "
         "separately and must not be averaged or quoted as one headline number. Every dataset used here is synthetic.", "",
         "## Reproduce", "", "```powershell", man["command"], "```", "",
         "## Provenance", "", *_table(["Item", "Value"], [["git commit", man["git"]["commit"]], ["uncommitted changes", man["git"]["uncommitted_changes"]],
                                                          ["random seed", man["protocol"]["seed"]], ["target false-positive rate", man["protocol"]["target_fpr"]],
                                                          ["bootstrap resamples", man["protocol"]["bootstrap_resamples"]],
                                                          ["feature count", man["feature_count"]], ["hybrid configuration SHA-256", man["hybrid_config_sha256"]],
                                                          ["matches the configuration frozen before the first CERT test run", man["frozen_config_check"]],
                                                          *[[k, v] for k, v in man["software"].items()]]), "",
         "### Honest notes on this run", ""]
    L += [f"* {n}" for n in man["notes"]]
    L.append("")
    for t in results["tracks"].values():
        L += render_track(t)
    L += ["## Limitations", ""] + [f"* {x}" for x in results["limitations"]] + [""]
    return "\n".join(L)
