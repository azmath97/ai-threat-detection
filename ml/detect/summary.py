"""Print a benchmark report (ml.detect.benchmark JSON) as compact Markdown tables.

    python -m ml.detect.summary data/processed/reports/cert_test.json
"""
import json
import sys


def _f(v, digits=3):
    return "n/a" if v is None else (f"{v:.{digits}f}" if isinstance(v, float) else str(v))


def render(report: dict) -> str:
    models = report["models"]
    lines = [f"**{report['dataset']} - {report['evaluated_split']} split** - {report['unit']}", "", report["operating_point"], ""]
    if "domain_categories_enabled" in report:
        lines += [f"Destination-category enrichment: {'enabled' if report['domain_categories_enabled'] else 'DISABLED (ablation)'}", ""]
    c = report["split_counts"][report["evaluated_split"]]
    lines += [f"Evaluated: {c['windows']:,} labelled windows from {c['users']} users, {c['malicious']} malicious windows from {c['insiders']} insiders.", ""]
    lines += ["| Model | Precision | Recall | F1 | FPR | FNR | TP | FP | FN | TN | ROC-AUC | AP |", "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, m in models.items():
        lines.append(f"| {name} | {_f(m['precision'])} | {_f(m['recall'])} | {_f(m['f1'])} | {_f(m['false_positive_rate'], 4)} | {_f(m['false_negative_rate'])} | "
                     f"{m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {_f(m['roc_auc'])} | {_f(m['average_precision'])} |")
    lines += ["", "Recall at fixed validation false-positive rates (threshold from validation, applied to the evaluated split):", "",
              "| Model | recall @0.1% FPR | recall @0.5% FPR | recall @1% FPR |", "|---|---|---|---|"]
    for name, m in models.items():
        r = m["recall_at_validation_fpr"]
        lines.append(f"| {name} | " + " | ".join(f"{_f(r[k]['recall'])} (obs. FPR {r[k]['observed_fpr']})" for k in ("0.001", "0.005", "0.01")) + " |")
    scenarios = sorted({s for m in models.values() for s in m["per_scenario_windows"]})
    lines += ["", "Per-scenario window recall (share of malicious windows that raised an alert):", "", "| Model | " + " | ".join(scenarios) + " |",
              "|---|" + "---|" * len(scenarios)]
    for name, m in models.items():
        lines.append(f"| {name} | " + " | ".join(_f(m["per_scenario_windows"].get(s, {}).get("window_recall")) for s in scenarios) + " |")
    lines += ["", "Per-scenario incident recall / median detection delay (hours from first malicious event to the end of the first alerted day) / "
              "median share of an incident's events that came after the alert:", "", "| Model | " + " | ".join(scenarios + ["all"]) + " |", "|---|" + "---|" * (len(scenarios) + 1)]
    for name, m in models.items():
        cells = []
        for s in scenarios + ["all"]:
            i = m["incidents"].get(s)
            cells.append("n/a" if not i else f"{i['detected']}/{i['incidents']} | {_f(i['median_delay_hours'], 1)} h | {_f(i['median_share_of_events_after_alert'], 2)}")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    look = sorted({s for m in models.values() for s in m["benign_lookalikes"]})
    if look:
        lines += ["", "False-positive rate on benign lookalike windows:", "", "| Model | " + " | ".join(look) + " |", "|---|" + "---|" * len(look)]
        for name, m in models.items():
            lines.append(f"| {name} | " + " | ".join(f"{_f(m['benign_lookalikes'].get(s, {}).get('false_positive_rate'), 4)} ({m['benign_lookalikes'].get(s, {}).get('false_alerts', 0)}/{m['benign_lookalikes'].get(s, {}).get('benign_windows', 0)})" for s in look) + " |")
    lines += ["", "95% user-bootstrap intervals (precision / recall / FPR):", ""]
    for name, m in models.items():
        ci = m["ci95_user_bootstrap"]
        lines.append(f"* {name}: precision {ci['precision']}, recall {ci['recall']}, FPR {ci['false_positive_rate']}")
    lines += ["", f"Excluded windows: {report['excluded_windows']}", f"Hybrid states on evaluated windows: {report['hybrid_state_counts_on_evaluated_windows']}"]
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("--out", help="write the Markdown here instead of printing it")
    args = parser.parse_args()
    text = render(json.load(open(args.report, encoding="utf-8")))
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
