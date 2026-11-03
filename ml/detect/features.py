"""Window features: raw volumes, deviation from the user's own history, deviation from a peer group, multi-day trends.

Everything is causal: a window's own-history baseline uses only the 28 calendar days *before* it, the peer baseline is
fitted on benign train-split users only, and no label or identity column is ever read (FEATURE_COLUMNS is the contract
checked by ml.cert.leakage.assert_no_leakage).

Documentation of every feature, its window and the fields it is derived from is in FEATURE_DOC (and
docs/detection-evaluation.md).
"""
import numpy as np
import pandas as pd
from numpy.lib.stride_tricks import sliding_window_view

from ml.cert.leakage import assert_no_leakage

BASELINE_DAYS = 28            # own-history window: the 28 calendar days before the window day
MIN_BASELINE_ACTIVE = 5       # needs this many active days of the same day type (weekday/weekend) in the baseline
LOG_FLOOR_SD = 0.5            # in log1p units; stops tiny variance from exploding a z-score
TIME_FLOOR_SD = 1.0           # hours
Z_CLIP = 12.0
LONG_BASELINE = (112, 28)     # long own baseline: the days [day-112, day-28)
MIN_LONG_ACTIVE = 15
CUSUM_LEAK, CUSUM_ALLOWANCE = 0.9, 0.5
# Features that also get a long-baseline z-score, a CUSUM of it and a CUSUM against the peer group (sustained drift).
LONG_FEATURES = ["n_device_connect", "n_file_copy", "n_file_access", "n_new_domains", "n_email_external", "n_events_after_hours",
                 "n_cat_job", "n_cat_exfil"]

# Volume features that get an own-history and a peer z-score (computed on log1p of the raw count/bytes).
VOLUME_FEATURES = [
    "n_device_connect", "n_file_copy", "n_file_access", "n_email", "n_email_external", "email_bytes_external", "email_attach_total",
    "n_web", "n_new_domains", "n_rare_domains", "n_cat_job", "n_cat_exfil", "n_events_after_hours", "n_removable_after_hours", "n_logon_after_hours",
    "n_hosts", "n_logon_failed", "copy_burst_10min", "n_copy_while_connected",
]
# Features accumulated over several days (gradual collection / exfiltration).
TREND_FEATURES = ["n_file_copy", "n_device_connect", "n_rare_domains", "email_bytes_external", "n_file_access", "n_removable_after_hours"]
FLAG_FEATURES = ["seq_rare_then_removable", "seq_removable_then_external", "seq_access_then_external"]
# Excess over the user's own 28-day maximum (log units): robust for zero-inflated quantities such as external e-mail bytes.
EXCESS_FEATURES = ["n_file_copy", "n_file_access", "email_bytes_external", "n_email_external", "n_rare_domains", "n_device_connect"]
RAW_FEATURES = [f"log_{c}" for c in VOLUME_FEATURES] + ["first_hour_raw", "last_hour_raw", "is_weekend"] + FLAG_FEATURES
OWN_FEATURES = [f"z_own_{c}" for c in VOLUME_FEATURES] + ["start_hour_dev_own", "end_hour_dev_own"]
PEER_FEATURES = [f"z_peer_{c}" for c in VOLUME_FEATURES]
TREND_COLUMNS = [f"log_ratio7_{c}" for c in TREND_FEATURES]
EXCESS_COLUMNS = [f"excess_max28_{c}" for c in EXCESS_FEATURES]
LONG_COLUMNS = [f"{p}_{c}" for c in LONG_FEATURES for p in ("z_long", "cusum_long")]
PEER_CUSUM_COLUMNS = [f"cusum_peer_{c}" for c in LONG_FEATURES]
DEVIATION_FEATURES = OWN_FEATURES + PEER_FEATURES + TREND_COLUMNS + EXCESS_COLUMNS + LONG_COLUMNS + PEER_CUSUM_COLUMNS + FLAG_FEATURES + ["is_weekend"]
FEATURE_COLUMNS = list(dict.fromkeys(RAW_FEATURES + DEVIATION_FEATURES))

FEATURE_DOC = {
    "log_<feature>": ("log1p of the day's raw count or byte total for each of VOLUME_FEATURES", "1 day", "event counts, size, attachment_count"),
    "n_device_connect / n_file_copy": ("removable-media connects and file copies to removable media", "1 day", "device.csv, file.csv"),
    "n_file_access": ("generic file access events (not present in CERT r4.2, so constant 0 there)", "1 day", "synthetic supplement only"),
    "n_email / n_email_external": ("e-mails sent / with at least one non-organisation recipient", "1 day", "email.csv to,cc,bcc,from"),
    "email_bytes_external, email_attach_total": ("message bytes of external e-mails; attachments on all e-mails", "1 day", "email.csv size, attachments"),
    "n_web, n_new_domains, n_rare_domains": ("web visits; domains the user visited for the first time that day; domains seen by <= 5 train users", "1 day (+ history to date for 'new')", "http.csv url host"),
    "n_events_after_hours": ("events outside 07:00-19:00 or on a weekend (dataset clock)", "1 day", "timestamps"),
    "n_removable_after_hours / n_logon_after_hours": ("removable-media activity / logons in those hours", "1 day", "device, file, logon"),
    "n_hosts": ("distinct PCs used", "1 day", "pc"),
    "n_logon_failed": ("failed logons (not present in CERT r4.2, constant 0 there)", "1 day", "auth_result"),
    "copy_burst_10min": ("largest number of file copies in one 10-minute bucket", "10 minutes", "file.csv timestamps"),
    "n_copy_while_connected": ("file copies made while the last device event (<= 4 h earlier) was a connect", "4 hours", "device + file"),
    "first_hour_raw / last_hour_raw / is_weekend": ("hour of the first / last event of the day; weekend flag", "1 day", "timestamps"),
    "seq_rare_then_removable": ("a rare-destination visit followed by removable-media activity within 3 h", "3 hours", "http + device/file"),
    "seq_removable_then_external": ("removable-media activity followed by an external e-mail the same day", "1 day", "device/file + email"),
    "seq_access_then_external": ("file access followed by an external e-mail the same day", "1 day", "file_access + email (synthetic only)"),
    "z_own_<feature>": ("(log1p(x) - mean) / max(std, 0.5) over the user's active days of the same day type in the previous 28 days; needs >= 5 such days", "28 days before", "own history"),
    "z_peer_<feature>": ("same z-score against the user's peer group (LDAP role; one group when there is none), fitted on benign train users", "fitted offline", "peer group"),
    "start_hour_dev_own / end_hour_dev_own": ("|first/last event hour - own mean| / max(std, 1 h) over the previous 28 days", "28 days before", "own history"),
    "log_ratio7_<feature>": ("log((sum over the last 7 days + 1) / (7 x mean daily rate in the 28 days before that + 1))", "7 days vs the 28 before", "own history"),
    "excess_max28_<feature>": ("max(0, log1p(x) - log1p(largest daily value in the previous 28 days)); 0 until a baseline exists", "28 days before", "own history"),
    "z_long_<feature> / cusum_long_<feature>": ("z-score against the user's own LAGGED baseline (days d-112..d-29, >= 15 active days) and its leaky one-sided CUSUM (S = max(0, 0.9 S + z - 0.5) over the user's windows)", "84 days, lagged 28", "own history"),
    "cusum_peer_<feature>": ("the same leaky CUSUM of the peer-group z-score", "per-window recursion", "peer group"),
}


# ---------------------------------------------------------------------------------------------------- own history
def _dense(windows: pd.DataFrame):
    entities = pd.Index(sorted(windows["entity_id"].unique()))
    day0 = windows["day"].min()
    n_days = int((windows["day"].max() - day0).days) + 1
    ei = entities.get_indexer(windows["entity_id"])
    di = (windows["day"] - day0).dt.days.to_numpy()
    return entities, day0, n_days, ei, di


def _grid(values: np.ndarray, ei, di, shape) -> np.ndarray:
    g = np.zeros(shape, dtype=float)
    g[ei, di] = np.nan_to_num(values.astype(float))
    return g


def _cum(a: np.ndarray) -> np.ndarray:
    c = np.zeros((a.shape[0], a.shape[1] + 1))
    np.cumsum(a, axis=1, out=c[:, 1:])
    return c


def _window_sum(cum: np.ndarray, start: np.ndarray, stop: np.ndarray) -> np.ndarray:
    """Sum of grid[:, start:stop] for every day (start/stop are per-day index arrays, clipped to [0, D])."""
    return cum[:, stop] - cum[:, start]


def _cusum(z: np.ndarray, entity: np.ndarray, leak: float = CUSUM_LEAK, allowance: float = CUSUM_ALLOWANCE) -> np.ndarray:
    """Leaky one-sided CUSUM per entity over the windows in order: S = max(0, leak x S + z - allowance).

    Accumulates mild but persistent deviations that a single day's z-score cannot reveal; bounded by
    (z - allowance) / (1 - leak). Windows must be sorted by (entity, day), which build_windows guarantees.
    """
    out = np.zeros(len(z))
    previous, s = None, 0.0
    for i in range(len(z)):
        if entity[i] != previous:
            previous, s = entity[i], 0.0
        s = max(0.0, leak * s + z[i] - allowance)
        out[i] = s
    return out


def own_baseline_features(windows: pd.DataFrame) -> pd.DataFrame:
    """Raw log features, own-history z-scores, timing deviations and multi-day ratios for every window."""
    w = windows.reset_index(drop=True)
    entities, day0, n_days, ei, di = _dense(w)
    shape = (len(entities), n_days)
    days = np.arange(n_days)
    weekend_day = np.asarray((day0 + pd.to_timedelta(days, unit="D")).weekday) >= 5
    start = np.clip(days - BASELINE_DAYS, 0, n_days)
    stop = np.clip(days, 0, n_days)
    active = _grid(np.ones(len(w)), ei, di, shape) > 0

    sets = {}
    for t in (False, True):
        mask = (weekend_day == t)[None, :]
        sets[t] = _cum((active & mask).astype(float))
    long_start, long_stop = np.clip(days - LONG_BASELINE[0], 0, n_days), np.clip(days - LONG_BASELINE[1], 0, n_days)

    def stats(values: np.ndarray, lo=start, hi=stop, min_active=MIN_BASELINE_ACTIVE):
        """Mean and std over active same-type days in [day-lo, day-hi) gathered at each window."""
        grid = _grid(values, ei, di, shape)
        out_mean, out_std = np.full(shape, np.nan), np.full(shape, np.nan)
        for t in (False, True):
            mask = (weekend_day == t)[None, :] & active
            c1, c2 = _cum(np.where(mask, grid, 0.0)), _cum(np.where(mask, grid ** 2, 0.0))
            n = _window_sum(sets[t], lo, hi)
            with np.errstate(invalid="ignore", divide="ignore"):
                mean = _window_sum(c1, lo, hi) / n
                var = np.maximum(_window_sum(c2, lo, hi) / n - mean ** 2, 0.0)
            ok = (n >= min_active) & (weekend_day == t)[None, :]
            out_mean = np.where(ok, mean, out_mean)
            out_std = np.where(ok, np.sqrt(var), out_std)
        return out_mean[ei, di], out_std[ei, di]

    out = pd.DataFrame(index=w.index)
    ready = None
    for column in VOLUME_FEATURES:
        x = np.log1p(w[column].to_numpy(dtype=float))
        out[f"log_{column}"] = x
        mean, std = stats(x)
        z = (x - mean) / np.maximum(std, LOG_FLOOR_SD)
        out[f"z_own_{column}"] = np.clip(np.nan_to_num(z, nan=0.0), -Z_CLIP, Z_CLIP)
        ready = ~np.isnan(mean) if ready is None else ready & ~np.isnan(mean)
    for src, name in (("first_hour", "start_hour_dev_own"), ("last_hour", "end_hour_dev_own")):
        hours = w[src].to_numpy(dtype=float)
        out[f"{src}_raw"] = np.nan_to_num(hours, nan=12.0)
        mean, std = stats(np.nan_to_num(hours, nan=12.0))
        out[name] = np.clip(np.nan_to_num(np.abs(hours - mean) / np.maximum(std, TIME_FLOOR_SD), nan=0.0), 0.0, Z_CLIP)
    out["baseline_ready"] = ready.astype(float)
    # excess over the user's own largest day in the previous 28 calendar days (zeros for inactive days)
    for column in EXCESS_FEATURES:
        grid = np.log1p(_grid(w[column].to_numpy(dtype=float), ei, di, shape))
        padded = np.concatenate([np.zeros((shape[0], BASELINE_DAYS)), grid], axis=1)
        prev_max = sliding_window_view(padded, BASELINE_DAYS, axis=1)[:, :n_days, :].max(axis=2)
        excess = np.maximum(np.log1p(w[column].to_numpy(dtype=float)) - prev_max[ei, di], 0.0)
        out[f"excess_max28_{column}"] = np.where(ready, np.clip(excess, 0.0, Z_CLIP), 0.0)
    out["is_weekend"] = w["is_weekend"].to_numpy(dtype=float)
    # long, lagged own baseline ([day-112, day-28)): a slow increase cannot be absorbed into it, unlike the 28-day baseline
    for column in LONG_FEATURES:
        x = np.log1p(w[column].to_numpy(dtype=float))
        mean, std = stats(x, long_start, long_stop, MIN_LONG_ACTIVE)
        z = np.clip(np.nan_to_num((x - mean) / np.maximum(std, LOG_FLOOR_SD), nan=0.0), -Z_CLIP, Z_CLIP)
        out[f"z_long_{column}"] = z
        out[f"cusum_long_{column}"] = _cusum(z, w["entity_id"].to_numpy())
    for column in FLAG_FEATURES:
        out[column] = w[column].to_numpy(dtype=float)
    # multi-day ratios: last 7 days against the 28 days before them (calendar days, zeros included)
    s7, e7 = np.clip(days - 6, 0, n_days), np.clip(days + 1, 0, n_days)
    sb, eb = np.clip(days - 34, 0, n_days), np.clip(days - 6, 0, n_days)
    for column in TREND_FEATURES:
        cum = _cum(_grid(w[column].to_numpy(dtype=float), ei, di, shape))
        recent = _window_sum(cum, s7, e7)
        prior = _window_sum(cum, sb, eb)
        have = np.maximum(eb - sb, 1)
        ratio = np.log((recent + 1.0) / (7.0 * prior / have[None, :] + 1.0))
        ratio = np.where((days >= 34)[None, :], ratio, 0.0)
        out[f"log_ratio7_{column}"] = np.clip(ratio[ei, di], -Z_CLIP, Z_CLIP)
    return out


# ---------------------------------------------------------------------------------------------------- peer group
class PeerBaseline:
    """Mean/std of each log1p volume feature per (peer group, weekday/weekend), from benign train windows only."""

    def __init__(self):
        self.table: dict[tuple[str, float], tuple[np.ndarray, np.ndarray]] = {}
        self.default: dict[float, tuple[np.ndarray, np.ndarray]] = {}

    def fit(self, features: pd.DataFrame, groups: pd.Series) -> "PeerBaseline":
        cols = [f"log_{c}" for c in VOLUME_FEATURES]
        frame = features[cols].assign(_g=groups.to_numpy(), _w=features["is_weekend"].to_numpy())
        for weekend, part in frame.groupby("_w"):
            values = part[cols].to_numpy(dtype=float)
            self.default[weekend] = (values.mean(axis=0), values.std(axis=0))
            for group, sub in part.groupby("_g"):
                if len(sub) >= 50:
                    v = sub[cols].to_numpy(dtype=float)
                    self.table[(group, weekend)] = (v.mean(axis=0), v.std(axis=0))
        return self

    def transform(self, features: pd.DataFrame, groups: pd.Series) -> pd.DataFrame:
        cols = [f"log_{c}" for c in VOLUME_FEATURES]
        x = features[cols].to_numpy(dtype=float)
        mean = np.zeros_like(x)
        std = np.ones_like(x)
        keys = list(zip(groups.to_numpy(), features["is_weekend"].to_numpy()))
        fallback = next(iter(self.default.values()))
        for i, key in enumerate(keys):
            m, s = self.table.get(key) or self.default.get(key[1]) or fallback
            mean[i], std[i] = m, s
        z = np.clip((x - mean) / np.maximum(std, LOG_FLOOR_SD), -Z_CLIP, Z_CLIP)
        return pd.DataFrame(z, columns=[f"z_peer_{c}" for c in VOLUME_FEATURES], index=features.index)


def peer_groups(windows: pd.DataFrame, attributes: pd.DataFrame | None) -> pd.Series:
    if attributes is None or "role" not in attributes:
        return pd.Series("all", index=windows.index)
    mapping = dict(zip(attributes["entity_id"], attributes["role"].fillna("unknown")))
    return windows["entity_id"].map(mapping).fillna("unknown")


def build_features(windows: pd.DataFrame, peer: PeerBaseline, attributes: pd.DataFrame | None = None) -> pd.DataFrame:
    """Full feature frame (FEATURE_COLUMNS + baseline_ready) aligned with `windows`."""
    own = own_baseline_features(windows)
    own.index = windows.index
    peers = peer.transform(own, peer_groups(windows, attributes))
    drift = pd.DataFrame({f"cusum_peer_{c}": _cusum(peers[f"z_peer_{c}"].to_numpy(), windows["entity_id"].to_numpy()) for c in LONG_FEATURES},
                         index=windows.index)
    frame = pd.concat([own, peers, drift], axis=1)
    assert_no_leakage(FEATURE_COLUMNS)
    return frame
