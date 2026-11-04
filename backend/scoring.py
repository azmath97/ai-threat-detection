"""Definitions of the four separate quantities an analyst sees, and the arithmetic behind them.

None of them is a probability. There is no labelled real-world data in this project from which a probability could be
calibrated, so every number below is either a model output on its own scale or a hand-assigned heuristic weight, and the
interface says which.

* **Heuristic risk score (0-100)**: `100 x (w_rules x rule_evidence + w_ml x anomaly)`.
    - `rule_evidence` (0-1) combines the weights of the rule groups that fired (noisy-OR). Each event contributes through
      its single strongest rule, and repeats of one rule on one target add only a discounted amount, so the same evidence is
      never counted twice. The rule weights are hand-assigned (backend/detection_rules.json).
    - `anomaly` (0-1) is the Isolation Forest output rescaled against normal training behaviour (not a probability). The
      model sees the same events as the rules, so its share is small and it never raises the corroboration gates below.
    - Attack stage, correlation and baseline deviation are **not** added to the score. They are properties of the same rule
      evidence, so adding them would count it again. Corroboration is applied as a gate instead (next item).
* **Risk band** (Normal / Watch / Elevated / Alert): the score compared with thresholds chosen on validation runs
  (backend/operating_point.json), limited by the number of independent attack stages (at least 2 for Elevated, 3 for Alert).
  It decides triage order and whether an alert is raised.
* **Impact severity** (None to Critical): what the evidence shows was accessed, exported or changed. It is derived from
  that evidence only (never from the score or the model), so a high-impact finding can exist while the detector is uncertain.
* **Evidence strength** (None / Weak / Moderate / Strong): a qualitative reading of how many independent attack stages the
  rule evidence spans and whether the anomaly model independently agrees.
"""
from backend.catalog import IMPACT_LABELS, IMPACT_RANK, STRENGTH_LABELS
from backend.config import get_settings
from backend.detection_engine import level_for

SCORE_FORMULA = "risk_score = 100 x (w_rules x rule_evidence + w_ml x anomaly_score)"

# What each number or label is, in the words the dashboards use. `kind` says where the value comes from.
DEFINITIONS = {
    "risk_score": {"label": "Heuristic risk score", "range": "0-100", "kind": "heuristic", "is_probability": False,
                   "text": "A hand-weighted evidence score: 80% rule evidence, 20% anomaly model. It ranks activity for triage. "
                           "It is not a probability of an attack and it has not been calibrated against real incidents."},
    "risk_band": {"label": "Risk band", "range": "Normal / Watch / Elevated / Alert", "kind": "threshold on the heuristic score",
                  "is_probability": False,
                  "text": "The risk score compared with thresholds chosen on validation runs, limited by how many independent attack "
                          "stages the evidence spans. It decides triage order and whether an alert is raised. It does not measure impact."},
    "impact_severity": {"label": "Impact severity", "range": "None / Low / Medium / High / Critical", "kind": "rule-based judgement of the evidence",
                        "is_probability": False,
                        "text": "What the evidence shows was accessed, exported or changed (records, privileges, confirmed transfer). It is "
                                "independent of the risk score and of the model, so a high-impact finding can have weak evidence."},
    "evidence_strength": {"label": "Evidence strength", "range": "None / Weak / Moderate / Strong", "kind": "qualitative",
                          "is_probability": False,
                          "text": "How well independent evidence corroborates the finding: attack stages spanned by rule evidence, and "
                                  "whether the anomaly model independently agrees. A reading, not a percentage."},
    "anomaly_score": {"label": "Anomaly score", "range": "0-1", "kind": "model output",
                      "is_probability": False,
                      "text": "Isolation Forest output rescaled against normal training behaviour (the upper edge of typical behaviour maps "
                              "to 0, a fixed span above it to 1), plus a guard for volumes beyond anything in training. Not a probability."},
    "rule_weight": {"label": "Rule weight", "range": "0-1", "kind": "hand-assigned",
                    "is_probability": False,
                    "text": "How strongly one rule counts as evidence. Assigned by hand in backend/detection_rules.json; it is not impact and "
                            "not a probability. Stored on events as 'risk points' (weight x 100)."},
}


def operating_point_summary() -> dict:
    """The recorded operating point, for the API and dashboards. Says plainly when none has been recorded."""
    from backend.config import load_operating_point

    s = get_settings()
    recorded = load_operating_point()
    base = {"thresholds": {"suspicious": s.threat_suspicious_threshold, "high_risk": s.threat_high_threshold,
                           "critical": s.threat_critical_threshold},
            "ml_corroboration_threshold": s.ml_corroboration_threshold, "source": s.thresholds_source}
    if not recorded:
        return {**base, "status": "uncalibrated defaults",
                "note": "No operating point has been recorded. Run `python -m ml.calibrate_scoring`. These thresholds are hand-picked."}
    keep = ("status", "selected_on", "targets", "validation", "test", "tradeoff", "generated_at", "software", "limitations")
    return {**base, **{k: recorded[k] for k in keep if k in recorded}}

HIGH_IMPACT_STAGES = {"privilege_escalation", "persistence", "lateral_movement"}
MEDIUM_IMPACT_STAGES = {"credential_misuse", "sensitive_resource_access", "collection"}


def combine(values: dict[str, float], weights: dict[str, float]) -> float:
    """Weighted sum of components in [0, 1] with weights summing to 1, scaled to 0-100: bounded by construction."""
    total = sum(weights[name] * min(1.0, max(0.0, values[name])) for name in weights)
    return round(min(100.0, max(0.0, 100.0 * total)), 2)


def band_for(score: float, counted_stages: int) -> tuple[str, str, bool]:
    """(band, band implied by the score alone, whether the corroboration gate lowered it)."""
    from backend import rules

    by_score = level_for(score)
    band = by_score
    if counted_stages < rules.scoring("min_stages_for_high_risk") and band in ("high_risk", "critical"):
        band = "suspicious"
    elif counted_stages < rules.scoring("min_stages_for_critical") and band == "critical":
        band = "high_risk"
    return band, by_score, band != by_score


def stored_band(explanation: dict | None, score: float) -> str:
    """The risk band recorded with an investigation (it includes the corroboration gate); older ones fall back to the score alone."""
    recorded = ((explanation or {}).get("risk_assessment") or {}).get("risk_band")
    return recorded if recorded else level_for(score)


def impact_severity(exposure: dict, stages: list[str], has_evidence: bool) -> dict:
    """Impact from the evidence alone. Returns {"level", "label", "reasons"}."""
    s = get_settings()
    stage_set = set(stages)
    status = exposure.get("status", "none")
    exposed = exposure.get("records_potentially_exposed", 0)
    reasons: list[str] = []
    level = "none"

    def raise_to(new: str, why: str) -> None:
        nonlocal level
        reasons.append(why)
        if IMPACT_RANK[new] > IMPACT_RANK[level]:
            level = new

    if exposure.get("external_transfer_confirmed"):
        raise_to("critical", f"{exposure.get('records_confirmed_external', 0):,} records confirmed transferred to an external destination")
    if stage_set & {"persistence", "lateral_movement"} and status in ("confirmed_export", "confirmed_external_transfer"):
        raise_to("critical", "a persistent or lateral-movement foothold exists alongside a confirmed export")
    if exposed >= s.bulk_record_threshold:
        raise_to("high", f"{exposed:,} sensitive records exported (bulk threshold {s.bulk_record_threshold:,})")
    if stage_set & HIGH_IMPACT_STAGES:
        raise_to("high", "privileges were escalated or a foothold was created: " + ", ".join(sorted(stage_set & HIGH_IMPACT_STAGES)))
    if status in ("confirmed_export", "suspicious_access"):
        raise_to("medium", exposure.get("statement", "sensitive records accessed or exported"))
    if stage_set & MEDIUM_IMPACT_STAGES:
        raise_to("medium", "credential misuse, sensitive-resource access or collection was observed: "
                 + ", ".join(sorted(stage_set & MEDIUM_IMPACT_STAGES)))
    if level == "none" and (has_evidence or stage_set):
        raise_to("low", "suspicious activity without access to sensitive data or privilege change")
    if level == "none":
        reasons.append("no suspicious evidence in the window")
    return {"level": level, "label": IMPACT_LABELS[level], "reasons": reasons}


def evidence_strength(*, rule_groups: int, counted_stages: int, ml_score: float | None, ml_mode: str | None) -> dict:
    """Qualitative corroboration of the finding by independent evidence. Not a probability."""
    threshold = get_settings().ml_corroboration_threshold
    model_agrees = bool(ml_mode == "isolation_forest" and ml_score is not None and ml_score >= threshold)
    reasons = [f"{rule_groups} rule evidence group(s) across {counted_stages} independent attack stage(s)"]
    if ml_mode == "isolation_forest":
        reasons.append(f"anomaly model {'agrees' if model_agrees else 'does not agree'} "
                       f"(score {ml_score:.2f}, corroboration threshold {threshold:.2f})")
    else:
        reasons.append("anomaly model unavailable: the heuristic fallback is not counted as independent corroboration")
    if rule_groups == 0:
        level = "none"
    elif counted_stages >= 3 or (counted_stages >= 2 and model_agrees):
        level = "strong"
    elif counted_stages >= 2 or (counted_stages >= 1 and model_agrees):
        level = "moderate"
    else:
        level = "weak"
    if level == "weak":
        reasons.append("a single stage without model agreement can be explained by routine work")
    return {"level": level, "label": STRENGTH_LABELS[level], "model_agrees": model_agrees, "reasons": reasons}
