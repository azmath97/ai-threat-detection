"""Hybrid risk: explicit behavioural rules + an anomaly model + correlation over a decaying 7-day window.

Design rules (all visible in the output of `explain`):

* **Evidence families, each counted once.** Every signal belongs to exactly one family (COLLECTION, STAGING, DESTINATION,
  TRANSFER, TIMING). A family's strength is the MAXIMUM of its rules (never the sum), so two rules that look at the same
  behaviour cannot add up. The anomaly model is a sixth family, credited only for the part of its score that the rule
  families do not already explain.
* **Deviation, not magnitude.** Rules fire on deviation from the user's own history AND from the peer group (both must
  deviate for volume rules), so a user whose normal is large, or a role whose normal is large, is not flagged for it.
  There is no "large transfer = critical" rule: a transfer family alone can reach at most its weight (0.5), and the alert
  threshold is calibrated on validation data, not fixed here.
* **Correlation.** A family's evidence decays by 0.70 per day (a day of evidence does not vanish at midnight, but old
  evidence fades quickly). Evidence is correlated when two or more distinct families are active within the window; each family
  still counts once.
* **Auditable.** `explain` returns the reason codes, their families, strengths, the observed values and thresholds, the
  weights, each family's marginal contribution to the risk, and the evidence timestamps.

The constants below were fixed by judgement before looking at any test data and may only be changed using train or
validation data (docs/detection-evaluation.md).
"""
from dataclasses import dataclass

import numpy as np
import pandas as pd

DECAY_PER_DAY = 0.70
CORRELATED_FAMILY_STRENGTH = 0.30     # a family counts as "active" for the descriptive states at this decayed strength
EXPOSURE_FAMILY_STRENGTH = 0.50
FAMILY_WEIGHTS = {"collection": 0.60, "staging": 0.55, "destination": 0.50, "transfer": 0.55, "access": 0.50, "timing": 0.25, "anomaly": 0.40}
ANOMALY_START, ANOMALY_FULL = 0.98, 0.999        # ECDF of benign train scores


def squash(z, start: float, full: float):
    """Linear ramp: 0 at `start`, 1 at `full`."""
    return np.clip((np.asarray(z, dtype=float) - start) / (full - start), 0.0, 1.0)


def both(own, peer, own_range=(2.5, 6.0), peer_range=(2.0, 5.0)):
    """A volume rule needs deviation from the user's own history and from the peer group."""
    return np.minimum(squash(own, *own_range), squash(peer, *peer_range))


@dataclass(frozen=True)
class Rule:
    code: str
    family: str
    description: str


RULES = [
    Rule("COLLECTION_COPY_VOLUME", "collection", "file copies to removable media far above own history and peers"),
    Rule("COLLECTION_FILE_ACCESS_VOLUME", "collection", "file access far above own history and peers"),
    Rule("COLLECTION_COPY_BURST", "collection", "burst of copies inside 10 minutes far above own history"),
    Rule("COLLECTION_GRADUAL_7D", "collection", "7-day collection volume far above the preceding 28 days"),
    Rule("COLLECTION_SUSTAINED_DRIFT", "collection", "persistent collection above the user's long baseline AND the peer group (CUSUM)"),
    Rule("STAGING_REMOVABLE_USE", "staging", "removable-media connects above own history and peers"),
    Rule("STAGING_REMOVABLE_AFTER_HOURS", "staging", "removable-media activity out of hours, above own history"),
    Rule("STAGING_GRADUAL_7D", "staging", "7-day removable-media use far above the preceding 28 days"),
    Rule("STAGING_SUSTAINED_DRIFT", "staging", "persistent removable-media use above the user's long baseline AND the peer group (CUSUM)"),
    Rule("DESTINATION_RARE", "destination", "visits to destinations that few users visit, above own history and peers"),
    Rule("DESTINATION_NEW", "destination", "many first-time destinations compared with the user's history"),
    Rule("DESTINATION_SUSTAINED_NEW", "destination", "persistently many first-time destinations versus long baseline and peers (CUSUM)"),
    Rule("DESTINATION_CATEGORY_JOB", "destination", "job-search site visits above own history (category enrichment)"),
    Rule("DESTINATION_CATEGORY_EXFIL", "destination", "file-sharing / document-leak site visits above own history (category enrichment)"),
    Rule("DESTINATION_THEN_REMOVABLE", "destination", "rare destination followed by removable-media activity within 3 h"),
    Rule("TRANSFER_EXTERNAL_VOLUME", "transfer", "external e-mail volume far above own history and peers"),
    Rule("TRANSFER_EXTERNAL_COUNT", "transfer", "external e-mail count far above own history and peers"),
    Rule("TRANSFER_SUSTAINED_EXTERNAL", "transfer", "persistently many external e-mails versus long baseline and peers (CUSUM)"),
    Rule("TRANSFER_AFTER_COLLECTION", "transfer", "external e-mail after removable use or file access the same day, with a deviation"),
    Rule("ACCESS_FAILED_LOGONS", "access", "failed logons far above own history"),
    Rule("ACCESS_HOST_SPREAD", "access", "more distinct machines in a day than own history and peers"),
    Rule("TIMING_OFF_PATTERN_HOURS", "timing", "first/last activity far from the user's usual hours"),
    Rule("TIMING_AFTER_HOURS_ACTIVITY", "timing", "after-hours activity far above own history"),
    Rule("TIMING_SUSTAINED_AFTER_HOURS", "timing", "persistent after-hours activity versus long baseline and peers (CUSUM)"),
    Rule("ANOMALY_MODEL", "anomaly", "behaviour unusual for the whole feature profile (anomaly model), net of rule evidence"),
]
FAMILIES = list(FAMILY_WEIGHTS)


def rule_strengths(F: pd.DataFrame) -> pd.DataFrame:
    """Strength 0..1 of every non-anomaly rule for each window (vectorised)."""
    z = lambda name: F[f"z_own_{name}"].to_numpy(dtype=float)
    p = lambda name: F[f"z_peer_{name}"].to_numpy(dtype=float)
    r = lambda name: F[f"log_ratio7_{name}"].to_numpy(dtype=float)
    x = lambda name: F[f"excess_max28_{name}"].to_numpy(dtype=float)

    def drift(*names, own=(2.5, 8.0), peer=(3.0, 10.0)):
        """Sustained drift: the user's CUSUM against their long baseline AND the peer group's CUSUM must both be high."""
        long_ = np.max([F[f"cusum_long_{n}"].to_numpy(dtype=float) for n in names], axis=0)
        peers = np.max([F[f"cusum_peer_{n}"].to_numpy(dtype=float) for n in names], axis=0)
        return np.minimum(squash(long_, *own), squash(peers, *peer))
    copy_dev = np.maximum(squash(z("n_file_copy"), 2.0, 5.0), squash(z("n_device_connect"), 2.0, 5.0))
    ext_dev = np.maximum(np.maximum(squash(z("email_bytes_external"), 2.0, 5.0), squash(x("email_bytes_external"), 2.0, 5.0)),
                         squash(z("n_email_external"), 2.0, 5.0))
    out = {
        "COLLECTION_COPY_VOLUME": both(z("n_file_copy"), p("n_file_copy")),
        "COLLECTION_FILE_ACCESS_VOLUME": both(z("n_file_access"), p("n_file_access")),
        "COLLECTION_COPY_BURST": squash(z("copy_burst_10min"), 3.0, 7.0) * (F["log_n_file_copy"].to_numpy() >= np.log1p(3)),
        "COLLECTION_GRADUAL_7D": np.minimum(squash(np.maximum(r("n_file_copy"), r("n_file_access")), 0.4, 1.1),
                                            squash(np.maximum(z("n_file_copy"), z("n_file_access")), 1.0, 2.2)),
        "STAGING_REMOVABLE_USE": both(z("n_device_connect"), p("n_device_connect")),
        "STAGING_REMOVABLE_AFTER_HOURS": squash(z("n_removable_after_hours"), 2.0, 5.0),
        "STAGING_GRADUAL_7D": np.minimum(squash(r("n_device_connect"), 0.8, 2.0), squash(z("n_device_connect"), 0.5, 2.0)),
        "DESTINATION_RARE": both(z("n_rare_domains"), p("n_rare_domains")),
        "DESTINATION_NEW": both(z("n_new_domains"), p("n_new_domains"), (3.0, 7.0), (2.5, 6.0)),
        "DESTINATION_THEN_REMOVABLE": 0.9 * F["seq_rare_then_removable"].to_numpy() * np.maximum(squash(z("n_rare_domains"), 1.0, 3.0), copy_dev),
        "TRANSFER_EXTERNAL_VOLUME": np.maximum(both(z("email_bytes_external"), p("email_bytes_external"), (1.5, 4.5), (1.5, 4.0)),
                                               np.minimum(squash(x("email_bytes_external"), 2.0, 5.0), squash(p("email_bytes_external"), 1.5, 4.0))),
        "TRANSFER_EXTERNAL_COUNT": np.maximum(both(z("n_email_external"), p("n_email_external")),
                                              np.minimum(squash(x("n_email_external"), 1.5, 3.0), squash(p("n_email_external"), 2.0, 5.0))),
        "TRANSFER_AFTER_COLLECTION": 0.8 * np.maximum(F["seq_removable_then_external"].to_numpy(), F["seq_access_then_external"].to_numpy()) * np.minimum(
            np.maximum(copy_dev, squash(z("n_file_access"), 2.0, 5.0)), ext_dev),
        "ACCESS_FAILED_LOGONS": squash(z("n_logon_failed"), 2.0, 4.5),
        "COLLECTION_SUSTAINED_DRIFT": drift("n_file_copy", "n_file_access"),
        "STAGING_SUSTAINED_DRIFT": drift("n_device_connect"),
        "DESTINATION_SUSTAINED_NEW": drift("n_new_domains", own=(3.0, 9.0)),
        "DESTINATION_CATEGORY_JOB": np.maximum(both(z("n_cat_job"), p("n_cat_job"), (2.5, 6.0), (1.5, 4.0)), drift("n_cat_job")),
        "DESTINATION_CATEGORY_EXFIL": np.maximum(both(z("n_cat_exfil"), p("n_cat_exfil"), (2.5, 6.0), (1.5, 4.0)), drift("n_cat_exfil")),
        "TRANSFER_SUSTAINED_EXTERNAL": drift("n_email_external"),
        "TIMING_SUSTAINED_AFTER_HOURS": drift("n_events_after_hours"),
        "ACCESS_HOST_SPREAD": both(z("n_hosts"), p("n_hosts"), (1.0, 2.5), (1.0, 2.5)) * (F["log_n_hosts"].to_numpy() >= np.log1p(2)),
        "TIMING_OFF_PATTERN_HOURS": np.maximum(squash(F["start_hour_dev_own"].to_numpy(), 2.5, 5.0), squash(F["end_hour_dev_own"].to_numpy(), 2.5, 5.0)),
        "TIMING_AFTER_HOURS_ACTIVITY": np.maximum(squash(z("n_events_after_hours"), 2.5, 6.0), squash(z("n_logon_after_hours"), 2.5, 6.0)),
    }
    return pd.DataFrame(out, index=F.index)


def family_matrix(rules: pd.DataFrame) -> pd.DataFrame:
    """Family strength = max over the family's rules (a family is never summed)."""
    out = {}
    for family in FAMILIES:
        codes = [r.code for r in RULES if r.family == family and r.code in rules]
        out[family] = rules[codes].max(axis=1).to_numpy() if codes else np.zeros(len(rules))
    return pd.DataFrame(out, index=rules.index)


def decayed_max(frame: pd.DataFrame, entity: pd.Series, day: pd.Series) -> pd.DataFrame:
    """Per entity, F(d) = max(s(d), 0.85^gap x F(previous window)): each family keeps its strongest recent evidence."""
    values = frame.to_numpy(dtype=float)
    out = np.zeros_like(values)
    ent, d = entity.to_numpy(), day.to_numpy().astype("datetime64[D]").astype(np.int64)
    prev_e, prev_d, prev_f = None, 0, None
    for i in range(len(values)):
        if ent[i] == prev_e:
            f = np.maximum(values[i], prev_f * DECAY_PER_DAY ** (d[i] - prev_d))
        else:
            f = values[i]
        out[i] = f
        prev_e, prev_d, prev_f = ent[i], d[i], f
    return pd.DataFrame(out, columns=frame.columns, index=frame.index)


def risk_from_families(F: pd.DataFrame) -> np.ndarray:
    """1 - prod(1 - w_f x F_f): bounded 0..1, each family counted once."""
    survive = np.ones(len(F))
    for family, weight in FAMILY_WEIGHTS.items():
        survive *= 1.0 - weight * F[family].to_numpy()
    return 1.0 - survive


@dataclass
class HybridResult:
    rules: pd.DataFrame          # per-rule strength of the day
    daily: pd.DataFrame          # per-family strength of the day (rules max; anomaly net of rules)
    active: pd.DataFrame         # per-family strength after decay over the window (what the risk uses)
    risk: np.ndarray
    anomaly: np.ndarray
    states: pd.DataFrame         # boolean state columns (model-derived states only)


def score_hybrid(F: pd.DataFrame, anomaly: np.ndarray, entity: pd.Series, day: pd.Series) -> HybridResult:
    rules = rule_strengths(F)
    fam = family_matrix(rules)
    rule_peak = fam[[f for f in FAMILIES if f != "anomaly"]].max(axis=1).to_numpy()
    a = squash(anomaly, ANOMALY_START, ANOMALY_FULL)
    fam["anomaly"] = a * (1.0 - rule_peak)                         # credited only for what the rules do not explain
    active = decayed_max(fam, entity, day)
    risk = risk_from_families(active)
    rule_families = [f for f in FAMILIES if f != "anomaly"]
    n_active = (active[rule_families] >= CORRELATED_FAMILY_STRENGTH).sum(axis=1)
    states = pd.DataFrame({
        "anomalous_activity": anomaly >= ANOMALY_START,
        "suspicious_sequence": (n_active >= 2).to_numpy(),
        "potential_data_exposure": (((active["transfer"] >= EXPOSURE_FAMILY_STRENGTH) | ((active["collection"] >= EXPOSURE_FAMILY_STRENGTH)
                                                                                       & ((active["staging"] >= CORRELATED_FAMILY_STRENGTH) | (active["transfer"] >= CORRELATED_FAMILY_STRENGTH))))).to_numpy(),
    }, index=F.index)
    return HybridResult(rules, fam, active, risk, anomaly, states)


def rules_only_risk(F: pd.DataFrame, entity: pd.Series, day: pd.Series) -> np.ndarray:
    """The hybrid without the anomaly family (explicit rules + correlation only)."""
    fam = family_matrix(rule_strengths(F))
    fam["anomaly"] = 0.0
    return risk_from_families(decayed_max(fam, entity, day))


def explain(F_row: pd.Series, result: HybridResult, position: int, evidence: dict | None = None, top: int = 6) -> dict:
    """Audit record for one window: reason codes, weights, marginal contributions, evidence times and states."""
    rule_row = result.rules.iloc[position]
    active = result.active.iloc[position]
    daily = result.daily.iloc[position]
    risk = float(result.risk[position])
    contributions = []
    for family, weight in FAMILY_WEIGHTS.items():
        without = 1.0 - np.prod([1.0 - FAMILY_WEIGHTS[f] * active[f] for f in FAMILY_WEIGHTS if f != family])
        contributions.append({"family": family, "weight": weight, "strength_after_decay": round(float(active[family]), 4),
                              "strength_today": round(float(daily[family]), 4), "marginal_risk": round(risk - float(without), 4)})
    codes = [{"code": rule.code, "family": rule.family, "strength": round(float(rule_row[rule.code]), 4), "description": rule.description}
             for rule in RULES if rule.code in rule_row and rule_row[rule.code] > 0.05]
    codes.sort(key=lambda c: -c["strength"])
    states = {k: bool(v) for k, v in result.states.iloc[position].items()}
    return {
        "risk": round(risk, 4), "reason_codes": codes[:top], "family_contributions": sorted(contributions, key=lambda c: -c["marginal_risk"]),
        "states": states, "anomaly_score": round(float(result.anomaly[position]), 4), "evidence": evidence or {},
        "note": ("Each family is counted once (max of its rules); anomaly is net of rule evidence. 'Potential data exposure' and "
                 "'suspicious sequence' are model inferences, never confirmations."),
    }
