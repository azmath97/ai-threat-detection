"""Synthetic behavioural dataset: normal working patterns, benign oddities and labelled suspicious sessions.

Everything is generated from a seeded random generator; there are no real employees, credentials or
banking data. Suspicious windows exist for evaluation only: the model is trained on normal windows.
"""
import csv
import random
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

from backend.catalog import RESOURCES, is_self_service, sensitivity_of
from backend.config import get_settings
from ml.features import Baseline, EventRecord, build_baseline, extract_features

DEPARTMENTS = ["Finance", "HR", "IT", "Trading", "Customer Service", "Compliance", "Engineering", "Lending", "Marketing"]
CROSS_ACCESS = {  # a few legitimate read permissions outside the home department
    "Finance": ["customer-accounts"], "HR": ["payroll-records"], "IT": ["source-code-repo"], "Trading": ["financial-reports"],
    "Compliance": ["financial-reports", "customer-accounts"], "Lending": ["customer-accounts"],
}
ATTACK_KINDS = ["restricted_probe", "bulk_export", "brute_force", "privileged_account", "external_transfer", "full_chain"]
HARD_NORMAL_KINDS = ["after_hours_only", "unfamiliar_ip_only", "legit_admin_work", "heavy_but_plausible_download"]


@dataclass
class SyntheticEmployee:
    id: str
    department: str
    permissions: dict[str, str]
    known_ips: list[str]
    start_hour: float


@dataclass
class Window:
    window_id: str
    employee_id: str
    events: list[EventRecord]
    label: int            # 0 normal, 1 suspicious (evaluation only)
    scenario: str
    split: str            # train | test


@dataclass
class Dataset:
    employees: dict[str, SyntheticEmployee]
    baselines: dict[str, Baseline]
    windows: list[Window] = field(default_factory=list)


def _make_employee(rng: random.Random, index: int) -> SyntheticEmployee:
    dept = DEPARTMENTS[index % len(DEPARTMENTS)]
    perms = {rid: "write" for rid, meta in RESOURCES.items() if meta["department"] == dept and not is_self_service(rid)}
    perms["internal-wiki"] = rng.choice(["read", "write"])
    for rid in CROSS_ACCESS.get(dept, []):
        perms.setdefault(rid, "read")
    ips = [f"10.{40 + index % 20}.{index % 250}.{rng.randint(10, 240)}" for _ in range(rng.choice([1, 1, 2]))]
    return SyntheticEmployee(f"SYN-{index + 1:03d}", dept, perms, ips, rng.uniform(7.8, 9.4))


def _utc(day: datetime, hour: float) -> datetime:
    tz = get_settings().tz
    local = datetime.combine(day.date(), time(0), tzinfo=tz) + timedelta(hours=hour)
    return local.astimezone(timezone.utc)


def _outside_ip(rng: random.Random) -> str:
    return rng.choice(["198.51.100", "203.0.113", "192.0.2"]) + f".{rng.randint(2, 250)}"


class _Ids:
    def __init__(self):
        self.session = 0

    def next(self) -> int:
        self.session += 1
        return self.session


def _view(rng, emp, resource, when, ip, sid, *, download=False, records=None, outcome="success", account=None):
    n = records if records is not None else (rng.randint(1, 80) if download else rng.randint(1, 25))
    et = "file_download" if download else "resource_access"
    ok = outcome == "success"
    return EventRecord(when, et, ip, resource, outcome, n if ok else 0, n if ok and download else 0, sid, account or emp.id)


def normal_session(rng, emp, day, ids, *, force=None) -> list[EventRecord]:
    """One ordinary working session. `force` pins a benign oddity (used for held-out hard-normal windows)."""
    sid = ids.next()
    after_hours = force == "after_hours_only" or (force is None and rng.random() < 0.06)
    odd_ip = force == "unfamiliar_ip_only" or (force is None and rng.random() < 0.05)
    start = rng.uniform(19.2, 23.0) if after_hours else emp.start_hour + rng.uniform(-0.8, 1.0)
    ip = _outside_ip(rng) if odd_ip else rng.choice(emp.known_ips)
    t = _utc(day, start)
    events: list[EventRecord] = []
    if rng.random() < 0.06:
        for _ in range(rng.randint(1, 2)):
            events.append(EventRecord(t - timedelta(minutes=rng.randint(1, 3)), "login_failed", ip, None, "failure", 0, 0, None, emp.id))
    events.append(EventRecord(t, "login", ip, None, "success", 0, 0, sid, emp.id))
    resources = list(emp.permissions)
    for _ in range(rng.randint(3, 8)):
        t += timedelta(minutes=rng.randint(5, 40))
        if rng.random() < 0.2:  # self-service page (payslip, directory, profile)
            events.append(EventRecord(t, "resource_access", ip, rng.choice(["my-payslips", "employee-directory", "my-profile"]),
                                      "success", rng.randint(1, 6), 0, sid, emp.id))
            continue
        heavy = force == "heavy_but_plausible_download" or rng.random() < 0.02
        events.append(_view(rng, emp, rng.choice(resources), t, ip, sid, download=heavy or rng.random() < 0.2,
                            records=rng.randint(150, 420) if heavy else None))
    if rng.random() < 0.04:  # honest mistake: tries something its role does not allow
        t += timedelta(minutes=rng.randint(2, 10))
        events.append(_view(rng, emp, rng.choice([r for r in RESOURCES if r not in emp.permissions and not is_self_service(r)]),
                            t, ip, sid, outcome="denied"))
    if rng.random() < 0.03:  # small approved transfer to an auditor, regulator or vendor
        t += timedelta(minutes=rng.randint(2, 10))
        n = rng.randint(1, 60)
        events.append(EventRecord(t, "external_transfer", ip, rng.choice(list(emp.permissions)), "success", n, n, sid, emp.id,
                                  {"transfer_status": "confirmed", "destination": "approved-partner"}))
    if emp.department == "IT" and (force == "legit_admin_work" or rng.random() < 0.02):
        t += timedelta(minutes=rng.randint(2, 15))
        events.append(EventRecord(t, "administrative_action", ip, "it-admin-console", "success", 0, 0, sid, emp.id,
                                  {"action": "create_privileged_account"}))
    events.append(EventRecord(t + timedelta(minutes=rng.randint(5, 30)), "logout", ip, None, "success", 0, 0, sid, emp.id))
    return events


def attack_window(rng, emp, kind, day, ids) -> list[EventRecord]:
    sid = ids.next()
    ip = _outside_ip(rng)
    t = _utc(day, rng.uniform(1.0, 5.0) if rng.random() < 0.5 else emp.start_hour)
    ev: list[EventRecord] = []

    def at(minutes):
        nonlocal t
        t += timedelta(minutes=minutes)
        return t

    def failed(n):
        for i in range(n):
            ev.append(EventRecord(at(0.2), "login_failed", ip, rng.choice([None, "it-admin-console"]), "failure", 0, 0, None, emp.id))

    def login(account=None, session=None):
        ev.append(EventRecord(at(1), "login", ip, None, "success", 0, 0, session or sid, account or emp.id))

    def probe(n):
        outside = [r for r in RESOURCES if r not in emp.permissions and not is_self_service(r)]
        for r in rng.sample(outside, min(n, len(outside))):
            ev.append(_view(rng, emp, r, at(rng.uniform(0.5, 3)), ip, sid, outcome="denied"))

    def export(records):
        sensitive = [r for r in emp.permissions if sensitivity_of(r) >= 2] or list(emp.permissions)
        ev.append(_view(rng, emp, rng.choice(sensitive), at(2), ip, sid, download=True, records=records))

    def admin_create():
        ev.append(EventRecord(at(2), "administrative_action", ip, "it-admin-console",
                              "success" if emp.department == "IT" else "denied", 0, 0, sid, emp.id,
                              {"action": "create_privileged_account"}))
        if emp.department == "IT":
            new_sid = ids.next()
            login(f"{emp.id}-svc", new_sid)

    def transfer(records):
        ev.append(EventRecord(at(2), "external_transfer", ip, "customer-accounts", "success", records, records, sid, emp.id,
                              {"transfer_status": "confirmed"}))

    if kind == "restricted_probe":
        login(); probe(rng.randint(4, 7))
    elif kind == "bulk_export":
        login(); ev.append(_view(rng, emp, rng.choice(list(emp.permissions)), at(3), ip, sid)); export(rng.randint(3000, 40000))
    elif kind == "brute_force":
        failed(rng.randint(5, 12)); login(); ev.append(_view(rng, emp, rng.choice(list(emp.permissions)), at(3), ip, sid))
    elif kind == "privileged_account":
        login(); admin_create()
    elif kind == "external_transfer":
        login(); ev.append(_view(rng, emp, rng.choice(list(emp.permissions)), at(3), ip, sid)); transfer(rng.randint(2000, 50000))
    else:  # full_chain
        failed(rng.randint(3, 6)); login(); probe(rng.randint(3, 5)); export(rng.randint(5000, 40000))
        failed(5); admin_create(); transfer(rng.randint(5000, 40000))
    ev.append(EventRecord(at(2), "logout", ip, None, "success", 0, 0, sid, emp.id))
    return sorted(ev, key=lambda e: e.timestamp)


def generate_dataset(seed: int = 42, n_employees: int = 60, history_days: int = 28, window_days: int = 35) -> Dataset:
    rng = random.Random(seed)
    ids = _Ids()
    employees = {e.id: e for e in (_make_employee(rng, i) for i in range(n_employees))}
    start = datetime(2025, 1, 6, tzinfo=timezone.utc)
    data = Dataset(employees=employees, baselines={})

    for emp in employees.values():
        history: list[EventRecord] = []
        for d in range(history_days):
            day = start + timedelta(days=d)
            if day.weekday() < 5:
                history += normal_session(rng, emp, day, ids)
        data.baselines[emp.id] = build_baseline(history, home_department=emp.department, known_ips=emp.known_ips,
                                                permissions=emp.permissions)
        n = 0
        for d in range(history_days, history_days + window_days):
            day = start + timedelta(days=d)
            if day.weekday() >= 5:
                continue
            n += 1
            split = "test" if rng.random() < 0.2 else "train"
            data.windows.append(Window(f"{emp.id}-N{n:03d}", emp.id, normal_session(rng, emp, day, ids), 0, "normal", split))
        for i, kind in enumerate(HARD_NORMAL_KINDS):
            if kind == "legit_admin_work" and emp.department != "IT":
                continue
            day = start + timedelta(days=history_days + window_days + i)
            data.windows.append(Window(f"{emp.id}-H{i}", emp.id, normal_session(rng, emp, day, ids, force=kind), 0, kind, "test"))
        for i, kind in enumerate(ATTACK_KINDS):
            day = start + timedelta(days=history_days + window_days + 10 + i)
            data.windows.append(Window(f"{emp.id}-A{i}", emp.id, attack_window(rng, emp, kind, day, ids), 1, kind, "test"))
    return data


def window_features(data: Dataset, window: Window) -> dict[str, float]:
    return extract_features(window.events, data.baselines[window.employee_id])


def export_csv(data: Dataset, directory: Path) -> tuple[Path, Path]:
    """Write the event-level and window-level datasets for inspection."""
    directory.mkdir(parents=True, exist_ok=True)
    events_path, windows_path = directory / "synthetic_events.csv", directory / "synthetic_windows.csv"
    with events_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["window_id", "employee", "account", "timestamp_utc", "event_type", "resource", "outcome", "source_ip",
                    "records_accessed", "records_downloaded", "session_id", "label", "scenario", "split"])
        for win in data.windows:
            for e in win.events:
                w.writerow([win.window_id, win.employee_id, e.account, e.timestamp.isoformat(), e.event_type, e.resource or "",
                            e.outcome, e.source_ip, e.records_accessed, e.records_downloaded, e.session_id or "",
                            win.label, win.scenario, win.split])
    with windows_path.open("w", newline="", encoding="utf-8") as fh:
        first = window_features(data, data.windows[0])
        w = csv.writer(fh)
        w.writerow(["window_id", "employee", "label", "scenario", "split", *first.keys()])
        for win in data.windows:
            f = window_features(data, win)
            w.writerow([win.window_id, win.employee_id, win.label, win.scenario, win.split, *[round(v, 4) for v in f.values()]])
    return events_path, windows_path
