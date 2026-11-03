"""Synthetic supplement for gaps in the CERT release and for controlled test cases.

    python -m ml.cert.synthetic --out data/processed/synthetic_test --seed 42 [--profile data/processed/cert_r4.2/cert_profile.json]
    python -m ml.cert.synthetic --out ... --random-seed          # interactive demos: new seed each run, recorded in the manifest

Everything here is tagged `source = synthetic_test` and `is_synthetic = True`, is written to its own directory and is
never mixed into the CERT records or the held-out CERT test set (ml.cert.leakage.assert_cert_only enforces that).
All users, hosts and destinations are invented: users SYN-Uxxxx, hosts SYNPC-xxxx and reserved `.example` / `.invalid`
domains. The behaviour distributions follow cert_profile.json (hour-of-day and per-user-day volumes of benign CERT
train-split users) when supplied, otherwise documented defaults.
"""
import argparse
import hashlib
import json
import math
import random
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from ml.cert.schema import EVENT_COLUMNS, SOURCE_SYNTHETIC, SYNTHETIC_NOTICE
from ml.cert.split import split_users

INTERNAL_DOMAIN = "corp.example"
PARTNER_DOMAINS = ["partner-a.example", "partner-b.example", "audit-firm.example"]
LEAK_DOMAIN = "files.drop-sim.invalid"
JOB_DOMAIN = "jobs.example"
BENIGN_SITES = ["intranet.example", "news.example", "search.example", "wiki.corp.example", "docs.corp.example",
                "mail.corp.example", "shopping.example", "weather.example"]
EXTENSIONS = ["doc", "pdf", "xls", "txt", "zip", "jpg"]
DEFAULT_PROFILE = {
    "basis": "documented defaults (no CERT profile supplied)",
    "hour_of_day": {"logon": [0.0] * 6 + [0.05, 0.25, 0.4, 0.2, 0.06, 0.02, 0.01, 0.01] + [0.0] * 10},
    "per_user_day": {"file_access": {"mean": 10.0}, "web_visit": {"mean": 35.0}, "email_send": {"mean": 8.0},
                     "device_connect": {"mean": 1.0}},
    "email_size_bytes": {"0.5": 30_000, "0.9": 90_000, "0.99": 400_000},
}

SCENARIOS = {
    "gradual_data_collection": {"kind": "threat", "reason": "CERT scenario 4 style slow accumulation over weeks; tests whether "
        "drift is caught before the final transfer."},
    "bulk_export": {"kind": "threat", "reason": "Large burst of file access followed by a large outbound attachment; CERT r4.2 "
        "has no explicit volume-based export scenario."},
    "unusual_external_transfer": {"kind": "threat", "reason": "Large external transfer to an unapproved destination; CERT "
        "r4.2 e-mail records carry sizes but its insiders do not use this pattern."},
    "removable_media_exfiltration": {"kind": "threat", "reason": "After-hours removable-media copy of many files (CERT scenario 1/2 "
        "style) with controllable intensity."},
    "account_misuse": {"kind": "threat", "reason": "Failed then successful logons on a foreign host out of hours (CERT r4.2 has no "
        "failed-authentication field, so this pattern cannot be evaluated on it)."},
    "multi_stage_sequence": {"kind": "threat", "reason": "Sequence across event types: odd-hours logon, leak-site and job-site "
        "browsing, removable media, external e-mail."},
    "legit_large_transfer": {"kind": "benign_lookalike", "reason": "Approved large attachment to a known partner during business "
        "hours; must not be flagged like an exfiltration."},
    "approved_odd_hours": {"kind": "benign_lookalike", "reason": "A night-shift user whose normal hours look unusual to a "
        "day-shift baseline."},
    "frequent_authorised_access": {"kind": "benign_lookalike", "reason": "A power user whose file volume is always high; high "
        "volume alone is not misuse."},
    "routine_removable_media": {"kind": "benign_lookalike", "reason": "Regular business-hours USB use by a user whose role needs it."},
}


@dataclass
class SyntheticConfig:
    seed: int = 42
    n_users: int = 60
    days: int = 56
    start: str = "2010-03-01"
    threat_fraction: float = 0.25          # share of users who get one threat scenario
    lookalike_fraction: float = 0.20       # share of users who get one benign lookalike
    missing_rate: float = 0.03             # per optional field, per event
    typo_logon_rate: float = 0.02          # benign failed-then-successful logons


def _pick_hour(rng: random.Random, weights: list[float]) -> float:
    hour = rng.choices(range(24), weights=[max(w, 0) for w in weights])[0]
    return hour + rng.random()


def _poisson(rng: random.Random, mean: float) -> int:
    if mean <= 0:
        return 0
    if mean > 30:
        return max(0, round(rng.gauss(mean, math.sqrt(mean))))
    limit, k, p = math.exp(-mean), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


class _Builder:
    def __init__(self, cfg: SyntheticConfig, profile: dict, rng: random.Random):
        self.cfg, self.profile, self.rng = cfg, profile, rng
        self.rows: list[dict] = []
        self.labels: list[dict] = []
        self.meta: list[dict] = []
        self.counter = 0
        self.start = datetime.fromisoformat(cfg.start).replace(tzinfo=timezone.utc)

    # ---- low-level helpers -------------------------------------------------------------------------
    def emit(self, user: dict, when: datetime, event_type: str, *, label: int = 0, scenario: str = "", host: str | None = None,
             **fields) -> None:
        self.counter += 1
        event_id = f"SYN-{self.counter:07d}"
        row = {"event_id": event_id, "source": SOURCE_SYNTHETIC, "timestamp_utc": when.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
               "entity_id": user["entity_id"], "host": host if host is not None else user["host"], "event_type": event_type,
               "activity": fields.pop("activity", ""), "auth_result": fields.pop("auth_result", ""),
               "destination": fields.pop("destination", ""), "resource": fields.pop("resource", ""),
               "bytes": fields.pop("bytes", math.nan), "attachment_count": fields.pop("attachment_count", math.nan),
               "recipient_count": fields.pop("recipient_count", math.nan),
               "external_recipient_count": fields.pop("external_recipient_count", math.nan),
               "removable_media": fields.pop("removable_media", False), "is_synthetic": True}
        self.rows.append(row)
        if label:
            self.labels.append({"event_id": event_id, "label": 1.0, "label_basis": "synthetic_threat_scenario"})
        if scenario:
            self.meta.append({"event_id": event_id, "scenario": scenario, "insider_user": user["user_id"],
                              "incident_file": "", "incident_start": "", "incident_end": ""})

    def _noisy(self, row: dict) -> None:
        """Randomly drop optional fields so detectors face missing data."""
        for column in ("host", "destination", "bytes"):
            if self.rng.random() < self.cfg.missing_rate:
                row[column] = math.nan if column == "bytes" else ""

    def at(self, day: datetime, hour: float) -> datetime:
        return day + timedelta(hours=hour)

    def email_size(self, scale: float = 1.0) -> float:
        q = self.profile.get("email_size_bytes", DEFAULT_PROFILE["email_size_bytes"])
        median = float(q.get("0.5", q.get(0.5, 30_000)))
        p90 = float(q.get("0.9", q.get(0.9, 90_000)))
        sigma = max(0.2, math.log(max(p90, median + 1) / max(median, 1)) / 1.2816)
        return max(500.0, median * scale * math.exp(self.rng.gauss(0, sigma)))

    # ---- behaviour -----------------------------------------------------------------------------------
    def normal_day(self, user: dict, day: datetime, *, extra_files: float = 0.0, night: bool = False) -> None:
        rng, prof = self.rng, self.profile
        per_day = {**DEFAULT_PROFILE["per_user_day"], **prof.get("per_user_day", {})}
        weights = prof.get("hour_of_day", {}).get("logon") or DEFAULT_PROFILE["hour_of_day"]["logon"]
        start = (_pick_hour(rng, weights) if not night else 21.5 + rng.random()) if not user.get("start_hour") else user["start_hour"] + rng.gauss(0, 0.4)
        if not night:
            start = min(max(start, 5.0), 12.0)
        end = start + 8.5 + rng.gauss(0, 0.7)
        host = user["host"]
        if rng.random() < self.cfg.typo_logon_rate:
            self.emit(user, self.at(day, start - 0.02), "logon", activity="logon", auth_result="failure", host=host)
        self.emit(user, self.at(day, start), "logon", activity="logon", auth_result="success", host=host)
        mean = lambda key: per_day.get(key, {}).get("mean", 5.0)
        n_files = _poisson(rng, mean("file_access") * user["file_rate"] + extra_files)
        n_web, n_mail = _poisson(rng, mean("web_visit")), _poisson(rng, mean("email_send"))
        for _ in range(n_files):
            self.emit(user, self.at(day, rng.uniform(start, end)), "file_access",
                      resource=f"{rng.randrange(10**8):08x}.{rng.choice(EXTENSIONS)}")
        for _ in range(n_web):
            site = rng.choice(BENIGN_SITES)
            self.emit(user, self.at(day, rng.uniform(start, end)), "web_visit", destination=site, resource=site)
        for _ in range(n_mail):
            internal = rng.random() < 0.93
            n_rcpt = rng.randint(1, 4)
            external = 0 if internal else rng.randint(1, min(2, n_rcpt))
            domain = INTERNAL_DOMAIN if internal else rng.choice(PARTNER_DOMAINS)
            self.emit(user, self.at(day, rng.uniform(start, end)), "email_send", recipient_count=n_rcpt,
                      external_recipient_count=external, destination=domain, bytes=self.email_size(),
                      attachment_count=rng.choice([0, 0, 0, 1, 2]))
        if user["usb"] and rng.random() < user["usb_rate"]:
            t = rng.uniform(start + 1, end - 1)
            self.emit(user, self.at(day, t), "device_connect", activity="connect", removable_media=True)
            self.emit(user, self.at(day, t + rng.uniform(0.05, 0.6)), "device_disconnect", activity="disconnect", removable_media=True)
        self.emit(user, self.at(day, end), "logoff", activity="logoff", host=host)

    # ---- scenarios -----------------------------------------------------------------------------------
    def threat(self, name: str, user: dict, first_day: datetime) -> None:
        rng = self.rng
        L = dict(label=1, scenario=name)
        if name == "gradual_data_collection":
            span = rng.randint(14, 21)
            for i in range(span):
                day = first_day + timedelta(days=i)
                if day.weekday() >= 5:
                    continue
                extra = round(8 * (1 + 4 * i / span))
                for _ in range(extra):
                    self.emit(user, self.at(day, rng.uniform(9, 17)), "file_access",
                              resource=f"proj-{rng.randrange(10**6):06x}.{rng.choice(['xls', 'doc', 'pdf'])}", **L)
            final = first_day + timedelta(days=span)
            self.emit(user, self.at(final, 18.2), "email_send", recipient_count=1, external_recipient_count=1,
                      destination="mailbox-sim.invalid", bytes=self.email_size(120), attachment_count=rng.randint(4, 9), **L)
        elif name == "bulk_export":
            t = rng.uniform(10, 15)
            for _ in range(rng.randint(300, 800)):
                self.emit(user, self.at(first_day, t + rng.random() * 0.5), "file_access",
                          resource=f"db-export-{rng.randrange(10**6):06x}.zip", **L)
            self.emit(user, self.at(first_day, t + 0.6), "email_send", recipient_count=1, external_recipient_count=1,
                      destination=PARTNER_DOMAINS[0], bytes=rng.uniform(30e6, 90e6), attachment_count=rng.randint(5, 15), **L)
        elif name == "unusual_external_transfer":
            for _ in range(rng.randint(1, 3)):
                self.emit(user, self.at(first_day, rng.uniform(8, 20)), "email_send", recipient_count=1, external_recipient_count=1,
                          destination=LEAK_DOMAIN, bytes=rng.uniform(20e6, 60e6), attachment_count=rng.randint(2, 6), **L)
        elif name == "removable_media_exfiltration":
            for d in range(rng.randint(2, 4)):
                day = first_day + timedelta(days=d)
                t = rng.uniform(22, 23.5)
                self.emit(user, self.at(day, t - 0.05), "logon", activity="logon", auth_result="success", **L)
                self.emit(user, self.at(day, t), "device_connect", activity="connect", removable_media=True, **L)
                for _ in range(rng.randint(100, 300)):
                    self.emit(user, self.at(day, t + rng.random() * 0.8), "file_copy_removable", removable_media=True,
                              resource=f"{rng.randrange(10**8):08x}.{rng.choice(EXTENSIONS)}", **L)
                self.emit(user, self.at(day, t + 0.9), "device_disconnect", activity="disconnect", removable_media=True, **L)
                self.emit(user, self.at(day, t + 1.0), "logoff", activity="logoff", **L)
        elif name == "account_misuse":
            foreign = f"SYNPC-{rng.randrange(9000, 9999)}"
            t = rng.uniform(1, 4)
            for _ in range(rng.randint(4, 8)):
                self.emit(user, self.at(first_day, t), "logon", activity="logon", auth_result="failure", host=foreign, **L)
                t += 0.01
            self.emit(user, self.at(first_day, t), "logon", activity="logon", auth_result="success", host=foreign, **L)
            for _ in range(rng.randint(20, 60)):
                self.emit(user, self.at(first_day, t + rng.random() * 1.5), "file_access", host=foreign,
                          resource=f"{rng.randrange(10**8):08x}.{rng.choice(EXTENSIONS)}", **L)
            self.emit(user, self.at(first_day, t + 1.7), "logoff", activity="logoff", host=foreign, **L)
        elif name == "multi_stage_sequence":
            t = rng.uniform(21, 22.5)
            self.emit(user, self.at(first_day, t), "logon", activity="logon", auth_result="success", **L)
            for site in (JOB_DOMAIN, LEAK_DOMAIN, JOB_DOMAIN):
                self.emit(user, self.at(first_day, t + rng.random() * 0.3), "web_visit", destination=site, resource=site, **L)
            self.emit(user, self.at(first_day, t + 0.4), "device_connect", activity="connect", removable_media=True, **L)
            for _ in range(rng.randint(60, 150)):
                self.emit(user, self.at(first_day, t + 0.4 + rng.random() * 0.5), "file_copy_removable", removable_media=True,
                          resource=f"{rng.randrange(10**8):08x}.{rng.choice(EXTENSIONS)}", **L)
            self.emit(user, self.at(first_day, t + 1.0), "device_disconnect", activity="disconnect", removable_media=True, **L)
            self.emit(user, self.at(first_day, t + 1.1), "email_send", recipient_count=1, external_recipient_count=1,
                      destination=LEAK_DOMAIN, bytes=rng.uniform(5e6, 25e6), attachment_count=rng.randint(1, 4), **L)
            self.emit(user, self.at(first_day, t + 1.2), "logoff", activity="logoff", **L)

    def lookalike(self, name: str, user: dict, first_day: datetime) -> None:
        rng = self.rng
        M = dict(scenario=name)          # label stays 0: these are benign by construction
        if name == "legit_large_transfer":
            self.emit(user, self.at(first_day, rng.uniform(10, 16)), "email_send", recipient_count=2, external_recipient_count=2,
                      destination=PARTNER_DOMAINS[1], bytes=rng.uniform(20e6, 50e6), attachment_count=rng.randint(2, 5), **M)
        elif name == "routine_removable_media":
            for d in range(0, 20, 2):
                day = first_day + timedelta(days=d)
                if day.weekday() < 5:
                    t = rng.uniform(10, 15)
                    self.emit(user, self.at(day, t), "device_connect", activity="connect", removable_media=True, **M)
                    self.emit(user, self.at(day, t + 0.3), "device_disconnect", activity="disconnect", removable_media=True, **M)


def generate(out: str | Path, cfg: SyntheticConfig | None = None, *, profile_path: str | Path | None = None,
             random_seed: bool = False) -> dict:
    cfg = cfg or SyntheticConfig()
    if random_seed:
        cfg.seed = secrets.randbelow(2**31)
    rng = random.Random(cfg.seed)
    profile, profile_basis = DEFAULT_PROFILE, DEFAULT_PROFILE["basis"]
    if profile_path:
        profile = json.loads(Path(profile_path).read_text(encoding="utf-8"))
        profile_basis = f"{profile_path} ({profile.get('basis', 'CERT profile')})"
    builder = _Builder(cfg, profile, rng)

    users = []
    for i in range(cfg.n_users):
        user_id = f"SYN-U{i + 1:04d}"
        users.append({"user_id": user_id, "entity_id": "S" + hashlib.sha256(f"{SOURCE_SYNTHETIC}:{user_id}".encode()).hexdigest()[:12],
                      "host": f"SYNPC-{1000 + i}", "file_rate": rng.choice([0.6, 0.8, 1.0, 1.0, 1.3]),
                      "usb": rng.random() < 0.15, "usb_rate": rng.uniform(0.05, 0.25), "start_hour": None})
    order = list(range(len(users)))
    rng.shuffle(order)
    n_threat, n_look = round(cfg.threat_fraction * len(users)), round(cfg.lookalike_fraction * len(users))
    threat_names = [n for n, d in SCENARIOS.items() if d["kind"] == "threat"]
    look_names = [n for n, d in SCENARIOS.items() if d["kind"] == "benign_lookalike"]
    assignments: dict[int, str] = {}
    for k, idx in enumerate(order[:n_threat]):
        assignments[idx] = threat_names[k % len(threat_names)]
    for k, idx in enumerate(order[n_threat:n_threat + n_look]):
        assignments[idx] = look_names[k % len(look_names)]

    for idx, user in enumerate(users):
        scenario = assignments.get(idx, "")
        night = scenario == "approved_odd_hours"
        if night:
            user["start_hour"] = 21.5
        power = 4.0 if scenario == "frequent_authorised_access" else 0.0
        if scenario == "routine_removable_media":
            user["usb"], user["usb_rate"] = True, 0.0           # USB use is injected explicitly below
        for d in range(cfg.days):
            day = builder.start + timedelta(days=d)
            if day.weekday() < 5:
                builder.normal_day(user, day, extra_files=power * 10, night=night)
        if scenario in threat_names:
            first = builder.start + timedelta(days=rng.randint(int(cfg.days * 0.55), max(int(cfg.days * 0.55), cfg.days - 25)))
            builder.threat(scenario, user, first)
        elif scenario in look_names and scenario not in ("approved_odd_hours", "frequent_authorised_access"):
            builder.lookalike(scenario, user, builder.start + timedelta(days=rng.randint(int(cfg.days * 0.5), cfg.days - 5)))
        elif scenario:
            builder.meta.extend({"event_id": r["event_id"], "scenario": scenario, "insider_user": user["user_id"], "incident_file": "",
                                 "incident_start": "", "incident_end": ""} for r in builder.rows if r["entity_id"] == user["entity_id"])

    for row in builder.rows:
        builder._noisy(row)
    frame = pd.DataFrame(builder.rows).sort_values(["timestamp_utc", "event_id"]).reset_index(drop=True)[list(EVENT_COLUMNS)]

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    frame.to_csv(out / "events_synthetic_test.csv.gz", index=False, compression="gzip")
    labels = pd.DataFrame(builder.labels, columns=["event_id", "label", "label_basis"])
    labels.to_csv(out / "labels.csv", index=False)
    meta = pd.DataFrame(builder.meta, columns=["event_id", "scenario", "insider_user", "incident_file", "incident_start", "incident_end"])
    meta.to_csv(out / "eval_metadata.csv", index=False)
    pd.DataFrame({"entity_id": [u["entity_id"] for u in users], "user_id": [u["user_id"] for u in users]}).to_csv(
        out / "identity_map.csv", index=False)
    threat_entities = {users[i]["entity_id"] for i, name in assignments.items() if name in threat_names}
    split_users([u["entity_id"] for u in users], threat_entities, seed=cfg.seed).to_csv(out / "splits.csv", index=False)

    per_scenario = meta.groupby("scenario").agg(events=("event_id", "size"), users=("insider_user", "nunique")).to_dict("index")
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(), "source": SOURCE_SYNTHETIC, "notice": SYNTHETIC_NOTICE,
        "seed": cfg.seed, "seed_mode": "random (interactive demo)" if random_seed else "fixed (reproducible)",
        "config": asdict(cfg), "behaviour_profile": profile_basis, "event_count": int(len(frame)),
        "malicious_event_count": int(len(labels)), "users": len(users),
        "missing_value_rate_per_optional_field": cfg.missing_rate,
        "scenarios": {name: {**SCENARIOS[name], **per_scenario.get(name, {"events": 0, "users": 0})} for name in SCENARIOS},
        "policy": ("Tagged source=synthetic_test and is_synthetic=true. Stored apart from CERT records. Must never be added to "
                   "the held-out CERT test set; report synthetic scenario results separately from CERT results."),
        "naming": "No real names, credentials or destinations: users SYN-Uxxxx, hosts SYNPC-xxxx, domains *.example / *.invalid.",
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default="data/processed/synthetic_test")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--random-seed", action="store_true", help="draw a fresh seed (recorded in the manifest)")
    parser.add_argument("--users", type=int, default=60)
    parser.add_argument("--days", type=int, default=56)
    parser.add_argument("--profile", help="cert_profile.json written by ml.cert.prepare")
    args = parser.parse_args()
    manifest = generate(args.out, SyntheticConfig(seed=args.seed, n_users=args.users, days=args.days),
                        profile_path=args.profile, random_seed=args.random_seed)
    print(json.dumps({k: manifest[k] for k in ("seed", "seed_mode", "event_count", "malicious_event_count")}, indent=2))


if __name__ == "__main__":
    main()
