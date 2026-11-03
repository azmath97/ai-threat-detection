"""Simple, transparent baseline rules.

Fixed thresholds taken from the benign TRAIN windows (99.9th percentile of the daily volume, or the stated constant), then
frozen. This is the kind of rule a SOC starts with: no per-user baseline, no peer group, no correlation, no model.
"""
import numpy as np
import pandas as pd

RULES = {
    "external_transfer_volume": ("email_bytes_external", "99.9th percentile of benign train windows, at least 10 MB"),
    "after_hours_removable_media": ("n_removable_after_hours", "any removable-media activity outside 07:00-19:00 or on a weekend"),
    "bulk_copy_or_access": ("n_file_copy+n_file_access", "99.9th percentile of benign train windows, at least 50 files"),
    "failed_logon_burst": ("n_logon_failed", "5 or more failed logons in a day"),
}


class FixedRuleBaseline:
    name = "baseline_fixed_rules"

    def fit(self, windows: pd.DataFrame) -> "FixedRuleBaseline":
        bulk = windows["n_file_copy"] + windows["n_file_access"]
        self.thresholds = {
            "external_transfer_volume": max(float(np.quantile(windows["email_bytes_external"], 0.999)), 1e7),
            "after_hours_removable_media": 1.0,
            "bulk_copy_or_access": max(float(np.quantile(bulk, 0.999)), 50.0),
            "failed_logon_burst": 5.0,
        }
        return self

    def _ratios(self, w: pd.DataFrame) -> np.ndarray:
        values = {"external_transfer_volume": w["email_bytes_external"], "after_hours_removable_media": w["n_removable_after_hours"],
                  "bulk_copy_or_access": w["n_file_copy"] + w["n_file_access"], "failed_logon_burst": w["n_logon_failed"]}
        return np.column_stack([values[k].to_numpy(dtype=float) / self.thresholds[k] for k in RULES])

    def alerts(self, w: pd.DataFrame) -> np.ndarray:
        """Native operation: alert when any rule reaches its fixed threshold."""
        return (self._ratios(w) >= 1.0).any(axis=1)

    def score(self, w: pd.DataFrame) -> np.ndarray:
        """Continuous version (largest threshold ratio, capped) used only for ROC-AUC and the fixed-FPR recall table."""
        return np.minimum(self._ratios(w).max(axis=1), 5.0) / 5.0

    def describe(self) -> dict:
        return {"rules": {k: {"field": RULES[k][0], "rule": RULES[k][1], "threshold": round(v, 3)} for k, v in self.thresholds.items()},
                "alert_logic": "any rule at or above its fixed threshold (native); no calibration"}
