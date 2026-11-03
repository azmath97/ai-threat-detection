"""Event records -> per-user, per-day behaviour windows.

Input is the canonical event schema produced by ml.cert.prepare (or ml.cert.synthetic). One window = one entity
(pseudonymous user) on one calendar day, using the dataset's own clock (CERT timestamps carry no UTC offset).

Every aggregate is order independent (counts, sums, min/max), duplicate event ids are dropped, missing fields are
treated as absent (never invented), and nothing here reads labels.
"""
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

AFTER_HOURS_START, AFTER_HOURS_END = 19, 7       # outside 07:00-19:00, or any weekend day
RARE_MAX_USERS = 5                               # a destination seen by <= this many training users is "rare"
TS_FORMAT = "%Y-%m-%dT%H:%M:%S"
TYPES_REMOVABLE = ("device_connect", "file_copy_removable")

# Optional destination-category enrichment, standing in for a web-categorisation feed. Exact host names only (no keyword
# matching, which would misfire on names like redbox.com). The lists were written after reading the public scenario
# descriptions, so results WITH it are optimistic for those scenarios; the benchmark reports an ablation without it
# (`--no-categories`).
CATEGORY_JOB = {"careerbuilder.com", "monster.com", "simplyhired.com", "indeed.com", "job-hunt.org", "jobhuntersbible.com",
                "glassdoor.com", "hotjobs.yahoo.com", "linkup.com"}
CATEGORY_EXFIL = {"mediafire.com", "dropbox.com", "megaupload.com", "4shared.com", "wetransfer.com", "sendspace.com", "rapidshare.com",
                  "hightail.com", "filefactory.com", "depositfiles.com", "zippyshare.com", "wikileaks.org", "cryptome.org"}


def prepare_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Parse timestamps, drop duplicate ids and rows without a usable timestamp or entity; add day/hour/after-hours."""
    df = df.copy()
    for column, default in (("destination", ""), ("resource", ""), ("host", ""), ("auth_result", ""), ("activity", "")):
        if column not in df:
            df[column] = default
        df[column] = df[column].fillna("").astype(str)
    for column in ("bytes", "attachment_count", "recipient_count", "external_recipient_count"):
        if column not in df:
            df[column] = np.nan
        df[column] = pd.to_numeric(df[column], errors="coerce")
    if "removable_media" not in df:
        df["removable_media"] = False
    df["removable_media"] = df["removable_media"].fillna(False).astype(bool)
    df["_ts"] = pd.to_datetime(df["timestamp_utc"].astype(str).str.slice(0, 19), format=TS_FORMAT, errors="coerce")
    df = df[df["_ts"].notna() & df["entity_id"].notna()]
    if "event_id" in df:
        df = df.drop_duplicates("event_id")
    df["day"] = df["_ts"].dt.normalize()
    df["hour"] = df["_ts"].dt.hour + df["_ts"].dt.minute / 60.0
    weekend = df["_ts"].dt.weekday >= 5
    df["after_hours"] = weekend | (df["hour"] < AFTER_HOURS_END) | (df["hour"] >= AFTER_HOURS_START)
    return df


# ---------------------------------------------------------------------------------------------------- destinations
@dataclass
class DomainContext:
    """Destination statistics: when each user first visited a domain, and how many training users ever did."""
    train_entities: set | None = None
    first_seen: pd.Series = field(default_factory=lambda: pd.Series(dtype="datetime64[ns]"))
    popularity: pd.Series = field(default_factory=lambda: pd.Series(dtype=float))
    _parts: list = field(default_factory=list)

    def update(self, prepared_web: pd.DataFrame) -> None:
        web = prepared_web[prepared_web["destination"] != ""]
        if web.empty:
            return
        self._parts.append(web.groupby(["entity_id", "destination"])["_ts"].min())
        if len(self._parts) >= 8:
            self._consolidate()

    def _consolidate(self) -> None:
        if self._parts:
            self._parts = [pd.concat(self._parts).groupby(level=[0, 1]).min()]

    def finalize(self) -> "DomainContext":
        self._consolidate()
        pairs = self._parts[0] if self._parts else pd.Series(dtype="datetime64[ns]", index=pd.MultiIndex.from_arrays([[], []]))
        frame = pairs.reset_index()
        frame.columns = ["entity_id", "destination", "first_ts"]
        self.first_seen = pd.Series(frame["first_ts"].to_numpy(), index=frame["entity_id"] + "|" + frame["destination"])
        counted = frame if self.train_entities is None else frame[frame["entity_id"].isin(self.train_entities)]
        self.popularity = counted.groupby("destination")["entity_id"].nunique()
        self._parts = []
        return self

    @classmethod
    def from_events(cls, prepared: pd.DataFrame, train_entities: set | None = None) -> "DomainContext":
        ctx = cls(train_entities)
        ctx.update(prepared[prepared["event_type"] == "web_visit"])
        return ctx.finalize()


def aggregate_web(prepared_web: pd.DataFrame, ctx: DomainContext) -> pd.DataFrame:
    """Per (entity, day) web features. `prepared_web` must hold complete days."""
    if prepared_web.empty:
        return pd.DataFrame()
    web = prepared_web.copy()
    has = web["destination"] != ""
    pop = web["destination"].map(ctx.popularity).fillna(0)
    web["_rare"] = has & (pop <= RARE_MAX_USERS)
    first = (web["entity_id"] + "|" + web["destination"]).map(ctx.first_seen)
    web["_new"] = has & (web["_ts"] == first)
    keys = ["entity_id", "day"]
    out = web.groupby(keys).agg(n_web=("event_id", "size"), web_after_hours=("after_hours", "sum"),
                                web_first_hour=("hour", "min"), web_last_hour=("hour", "max"),
                                web_first_ts=("_ts", "min"), web_last_ts=("_ts", "max"))
    out["n_domains"] = web[has].groupby(keys)["destination"].nunique()
    out["n_cat_job"] = web[web["destination"].isin(CATEGORY_JOB)].groupby(keys).size()
    out["n_cat_exfil"] = web[web["destination"].isin(CATEGORY_EXFIL)].groupby(keys).size()
    out["n_new_domains"] = web[web["_new"]].drop_duplicates(keys + ["destination"]).groupby(keys).size()
    rare = web[web["_rare"]]
    out["n_rare_domains"] = rare.groupby(keys)["destination"].nunique()
    out["rare_first_ts"] = rare.groupby(keys)["_ts"].min()
    out["rare_last_ts"] = rare.groupby(keys)["_ts"].max()
    out["n_web_missing_destination"] = (~has).groupby([web["entity_id"], web["day"]]).sum()
    return out.reset_index()


def aggregate_other(df: pd.DataFrame) -> pd.DataFrame:
    """Per (entity, day) features from every non-web event type, including cross-event sequence helpers."""
    if df.empty:
        return pd.DataFrame()
    d = df.copy()
    et = d["event_type"]
    failed = d["auth_result"].str.lower() == "failure"
    ext = (et == "email_send") & (d["external_recipient_count"].fillna(0) > 0)
    removable = et.isin(TYPES_REMOVABLE)
    d["_logon"] = (et == "logon") & ~failed
    d["_logon_failed"] = (et == "logon") & failed
    d["_logoff"] = et == "logoff"
    d["_connect"] = et == "device_connect"
    d["_copy"] = et == "file_copy_removable"
    d["_access"] = et == "file_access"
    d["_email"] = et == "email_send"
    d["_ext"] = ext
    d["_ext_bytes"] = np.where(ext, d["bytes"].fillna(0), 0.0)
    d["_bytes"] = np.where(et == "email_send", d["bytes"].fillna(0), 0.0)
    d["_attach"] = np.where(et == "email_send", d["attachment_count"].fillna(0), 0.0)
    d["_logon_ah"] = d["_logon"] & d["after_hours"]
    d["_rem_ah"] = removable & d["after_hours"]
    d["_ah"] = d["after_hours"]
    # events missing a field that their type normally carries (kept as a data-quality signal, never imputed)
    d["_incomplete"] = ((et == "email_send") & (d["bytes"].isna() | (d["destination"] == ""))) | (d["host"] == "")
    keys = ["entity_id", "day"]
    sums = ["_logon", "_logon_failed", "_logoff", "_connect", "_copy", "_access", "_email", "_ext", "_ext_bytes", "_bytes",
            "_attach", "_logon_ah", "_rem_ah", "_ah", "_incomplete"]
    out = d.groupby(keys)[sums].sum()
    out.columns = ["n_logon", "n_logon_failed", "n_logoff", "n_device_connect", "n_file_copy", "n_file_access", "n_email",
                   "n_email_external", "email_bytes_external", "email_bytes_total", "email_attach_total",
                   "n_logon_after_hours", "n_removable_after_hours", "n_other_after_hours", "n_incomplete_events"]
    out["n_other"] = d.groupby(keys).size()
    out["other_first_hour"] = d.groupby(keys)["hour"].min()
    out["other_last_hour"] = d.groupby(keys)["hour"].max()
    out["other_first_ts"] = d.groupby(keys)["_ts"].min()
    out["other_last_ts"] = d.groupby(keys)["_ts"].max()
    out["n_hosts"] = d[d["host"] != ""].groupby(keys)["host"].nunique()
    for name, mask in (("removable", removable), ("ext_email", ext), ("access", d["_access"])):
        sub = d[mask].groupby(keys)["_ts"]
        out[f"{name}_first_ts"], out[f"{name}_last_ts"] = sub.min(), sub.max()
    # copies made while a removable device was connected (last device event within 4 h was a connect)
    device = d[et.isin(["device_connect", "device_disconnect"])][["entity_id", "_ts", "event_type"]]
    copies = d[d["_copy"]][["entity_id", "day", "_ts"]]
    if not copies.empty:
        if device.empty:
            out["n_copy_while_connected"] = 0
        else:
            merged = pd.merge_asof(copies.sort_values("_ts"), device.sort_values("_ts").rename(columns={"_ts": "_dts", "event_type": "_dtype"}),
                                   left_on="_ts", right_on="_dts", by="entity_id", tolerance=pd.Timedelta("4h"))
            out["n_copy_while_connected"] = (merged["_dtype"] == "device_connect").groupby([merged["entity_id"], merged["day"]]).sum()
        burst = copies.assign(_bucket=copies["_ts"].dt.floor("10min")).groupby(keys + ["_bucket"]).size()
        out["copy_burst_10min"] = burst.groupby(level=[0, 1]).max()
    return out.reset_index()


_COUNT_COLUMNS = (
    "n_web", "n_domains", "n_new_domains", "n_rare_domains", "n_cat_job", "n_cat_exfil", "n_logon", "n_logon_failed", "n_logoff", "n_device_connect",
    "n_file_copy", "n_file_access", "n_email", "n_email_external", "n_removable_after_hours", "n_copy_while_connected",
    "copy_burst_10min", "n_hosts", "n_other", "n_other_after_hours", "n_logon_after_hours", "n_incomplete_events",
    "email_bytes_external", "email_bytes_total", "email_attach_total", "web_after_hours", "n_web_missing_destination",
)
_TS_COLUMNS = ("rare_first_ts", "rare_last_ts", "removable_first_ts", "removable_last_ts", "ext_email_first_ts", "ext_email_last_ts",
               "access_first_ts", "access_last_ts", "web_first_ts", "web_last_ts", "other_first_ts", "other_last_ts")


def combine_windows(web: pd.DataFrame, other: pd.DataFrame) -> pd.DataFrame:
    """Merge the web and non-web partial aggregates and derive the cross-source sequence flags."""
    keys = ["entity_id", "day"]
    if web is None or web.empty:
        w = other.copy()
    elif other is None or other.empty:
        w = web.copy()
    else:
        w = web.merge(other, on=keys, how="outer")
    for column in _COUNT_COLUMNS:
        w[column] = w[column].fillna(0) if column in w else 0.0
    for column in ("web_first_hour", "other_first_hour", "web_last_hour", "other_last_hour"):
        if column not in w:
            w[column] = np.nan
    for column in _TS_COLUMNS:
        if column not in w:
            w[column] = pd.NaT
    w["n_events"] = w["n_web"] + w["n_other"]
    w["n_events_after_hours"] = w["web_after_hours"] + w["n_other_after_hours"]
    w["first_hour"] = w[["web_first_hour", "other_first_hour"]].min(axis=1)
    w["last_hour"] = w[["web_last_hour", "other_last_hour"]].max(axis=1)
    w["first_event_ts"] = w[["web_first_ts", "other_first_ts"]].min(axis=1)
    w["last_event_ts"] = w[["web_last_ts", "other_last_ts"]].max(axis=1)
    w["n_incomplete_events"] = w["n_incomplete_events"] + w["n_web_missing_destination"]
    gap = pd.Timedelta("3h")
    w["seq_rare_then_removable"] = (w["rare_first_ts"].notna() & w["removable_last_ts"].notna()
                                    & (w["removable_last_ts"] >= w["rare_first_ts"]) & ((w["removable_last_ts"] - w["rare_first_ts"]) <= gap)).astype(float)
    w["seq_removable_then_external"] = (w["removable_first_ts"].notna() & w["ext_email_last_ts"].notna()
                                        & (w["ext_email_last_ts"] >= w["removable_first_ts"])).astype(float)
    w["seq_access_then_external"] = (w["access_first_ts"].notna() & w["ext_email_last_ts"].notna()
                                     & (w["ext_email_last_ts"] >= w["access_first_ts"])).astype(float)
    w["weekday"] = w["day"].dt.weekday
    w["is_weekend"] = (w["weekday"] >= 5).astype(float)
    return w.sort_values(["entity_id", "day"]).reset_index(drop=True)


def build_windows(events: pd.DataFrame, *, train_entities: set | None = None, ctx: DomainContext | None = None) -> pd.DataFrame:
    """In-memory entry point (tests, the synthetic supplement, small datasets)."""
    prepared = prepare_frame(events)
    if ctx is None:
        ctx = DomainContext.from_events(prepared, train_entities)
    web = aggregate_web(prepared[prepared["event_type"] == "web_visit"], ctx)
    other = aggregate_other(prepared[prepared["event_type"] != "web_visit"])
    return combine_windows(web, other)
