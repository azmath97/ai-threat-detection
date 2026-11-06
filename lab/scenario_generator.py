"""Seeded scenario generator for the simulation environment.

Pure and deterministic: (scenario, seed, target profile, peer profiles, volume) -> an ordered plan of actions. It touches no
database and no network; the runner (simulation_runs.py) submits each action through the backend's normal ingestion path.

Randomised within bounds: event timing, volumes, which resources are touched, the order of unconstrained actions, whether a
session is closed, and benign "noise" activity by other employees interleaved with the scenario. Ordering constraints
(sign in before acting, create an account before using it, collect before transferring) always hold. A plan describes what
the simulated actor *does*; whether that is detected, and how severely, is decided by the detection engine, never here.

Everything is synthetic: source addresses come from the RFC 5737 documentation ranges and destinations from the reserved
`.invalid` top-level domain, so nothing can resolve or route anywhere.
"""
import hashlib
import json
import random
import secrets
from dataclasses import dataclass

from backend.catalog import RESOURCES, SENSITIVITY_LABELS, is_self_service, sensitivity_of

PLAN_VERSION = 1
SELF_SERVICE = ["my-profile", "my-payslips", "employee-directory", "document-library"]
DOC_NETS = ["192.0.2", "198.51.100", "203.0.113"]                       # RFC 5737 documentation address blocks
DESTINATIONS = ["files.exfil-sim.example.invalid", "drop-sim.example.invalid", "transfer-sim.example.invalid",
                "paste-sim.example.invalid", "archive-sim.example.invalid"]
MAX_DEMO_SECONDS = 25.0
MAX_RECORDS = 1_000_000

SCENARIOS = [
    {"id": "benign_activity", "name": "Benign employee activity", "category": "benign", "uses_external_ip": False,
     "description": "A normal working session from a familiar address: a few views of permitted resources, perhaps a small download.",
     "intent": "Baseline traffic. Should stay Normal."},
    {"id": "benign_bulk_transfer", "name": "Benign high-volume file transfer", "category": "benign", "uses_external_ip": False,
     "description": "An employee legitimately exports or downloads a large file set from a resource they are entitled to, from a "
                    "familiar address. A benign lookalike for bulk export.",
     "intent": "Volume alone must not make this critical; it may still be flagged as an unusual size."},
    {"id": "gradual_collection_staging", "name": "Gradual collection followed by staging", "category": "malicious",
     "uses_external_ip": False,
     "description": "Over one session an insider downloads from several classified resources in growing amounts, then stages a "
                    "large consolidated export. No external transfer takes place.",
     "intent": "Collection and staging evidence that builds up; the detector decides whether it reaches a critical alert."},
    {"id": "bulk_export", "name": "Bulk export", "category": "malicious", "uses_external_ip": True,
     "description": "A compromised account signs in from an unfamiliar address, touches classified resources and performs one "
                    "very large export (sometimes from a familiar address, as an insider would).",
     "intent": "Sensitive access plus a bulk export; severity is decided by the engine."},
    {"id": "suspicious_external_transfer", "name": "Suspicious external transfer", "category": "malicious",
     "uses_external_ip": True,
     "description": "A collection step followed by an attempted or confirmed transfer of records to a synthetic external destination.",
     "intent": "External-transfer evidence, recorded separately from the collection."},
    {"id": "removable_media", "name": "Removable-media activity", "category": "malicious", "uses_external_ip": False,
     "description": "Records of a classified resource are copied to a (simulated) USB device; volume ranges from routine to large.",
     "intent": "Removable-media copy evidence; small volumes may be low-risk."},
    {"id": "correlated_low_signals", "name": "Multiple low-severity signals", "category": "malicious", "uses_external_ip": True,
     "description": "An unfamiliar address, a couple of failed logins, denied low-level requests and a modest download, each "
                    "minor on its own.",
     "intent": "Signals that are individually weak and only become suspicious when correlated."},
    {"id": "compromised_account_campaign", "name": "Compromised account campaign (full chain)", "category": "malicious",
     "uses_external_ip": True,
     "description": "Unfamiliar sign-in, restricted-resource probing, a bulk export, failed administrator logins, an attempt to "
                    "create a privileged account and an external transfer. Which stages occur, their order and sizes vary by seed; "
                    "the backend still denies anything the account is not entitled to.",
     "intent": "Multi-stage campaign. Stages the account is not permitted to perform are denied."},
]
SCENARIO_IDS = {s["id"] for s in SCENARIOS}


@dataclass(frozen=True)
class Profile:
    id: int
    code: str
    username: str
    department: str
    job_role: str
    known_ips: tuple[str, ...]
    permissions: tuple[tuple[str, str], ...]          # (resource, access level)

    @property
    def perms(self) -> dict[str, str]:
        return dict(self.permissions)

    def summary(self) -> dict:
        return {"id": self.id, "employee_id": self.code, "username": self.username, "department": self.department,
                "job_role": self.job_role}


class PlanError(ValueError):
    """The target cannot play the scenario (for example it has no access to any classified resource)."""


# ------------------------------------------------------------------------------------------------ resource helpers
def _managed(profile: Profile) -> list[str]:
    return sorted(r for r, _ in profile.permissions if r in RESOURCES and not is_self_service(r))


def _sensitive(profile: Profile, minimum: int = 2) -> list[str]:
    return [r for r in _managed(profile) if sensitivity_of(r) >= minimum]


def _writable(profile: Profile, resources: list[str]) -> list[str]:
    return [r for r in resources if profile.perms.get(r) == "write"]


def _transfer_action(profile: Profile, resource: str) -> str:
    return "export" if profile.perms.get(resource) == "write" else "download"


def eligible(scenario: str, profile: Profile) -> bool:
    if not profile.known_ips:
        return False
    if scenario == "benign_activity":
        return True
    if scenario in ("benign_bulk_transfer", "correlated_low_signals", "compromised_account_campaign"):
        return bool(_managed(profile))
    return bool(_sensitive(profile))


def external_ip(rng: random.Random, avoid: set[str]) -> str:
    while True:
        ip = f"{rng.choice(DOC_NETS)}.{rng.randint(2, 250)}"
        if ip not in avoid:
            return ip


def new_seed() -> int:
    return secrets.randbelow(2**31)


def choose_target(scenario: str, seed: int, candidates: list[Profile]) -> Profile:
    options = [c for c in sorted(candidates, key=lambda c: c.id) if eligible(scenario, c)]
    if not options:
        raise PlanError(f"no employee is eligible for the '{scenario}' scenario")
    return random.Random(f"target:{scenario}:{seed}").choice(options)


# --------------------------------------------------------------------------------------------------- action builders
def _login(actor: str, ip: str) -> dict:
    return {"kind": "login", "actor": actor, "ip": ip}


def _logout(actor: str = "target") -> dict:
    return {"kind": "logout", "actor": actor}


def _access(resource: str, action: str, records: int, actor: str = "target", **extra) -> dict:
    return {"kind": "access", "actor": actor, "resource": resource, "action": action, "records": int(records), **extra}


def _views(rng: random.Random, profile: Profile, count: int, pool: list[str] | None = None) -> list[dict]:
    pool = pool or [*SELF_SERVICE, *_managed(profile)]
    return [_access(rng.choice(pool), "view", rng.randint(1, 8)) for _ in range(count)]


def _scaled(rng: random.Random, records: int | None, low: int, high: int) -> int:
    value = records if records else rng.randint(low, high)
    return max(1, min(MAX_RECORDS, int(value)))


# ------------------------------------------------------------------------------------------------------- scenarios
def _benign_activity(rng, p, ctx):
    ip = rng.choice(p.known_ips)
    pool = [*SELF_SERVICE, *_managed(p)]
    acts = [_login("target", ip), *_views(rng, p, rng.randint(3, 7), pool)]
    if rng.random() < 0.5:
        acts.append(_access(rng.choice(SELF_SERVICE[2:]), "download", rng.randint(1, 20)))
    if rng.random() < 0.85:
        acts.append(_logout())
    return acts, {"from_known_ip": True}


def _benign_bulk(rng, p, ctx):
    ip = rng.choice(p.known_ips)
    managed = _managed(p)
    own = [r for r in managed if RESOURCES[r]["department"] in (p.department, "All")] or managed
    resource = rng.choice(_writable(p, own) or own)
    records = _scaled(rng, ctx["records"], 600, 3500)
    acts = [_login("target", ip), *_views(rng, p, rng.randint(1, 3), [resource, *SELF_SERVICE]),
            _access(resource, _transfer_action(p, resource), records, purpose="approved_work")]
    if rng.random() < 0.3:
        acts.append(_access(resource, "download", max(1, records // rng.randint(4, 9))))
    if rng.random() < 0.7:
        acts.append(_logout())
    return acts, {"from_known_ip": True, "resource": resource}


def _gradual(rng, p, ctx):
    ip = rng.choice(p.known_ips)
    pool = _sensitive(p) or _managed(p)
    chosen = rng.sample(pool, min(len(pool), rng.randint(2, 4)))
    rounds = rng.randint(4, 7)
    base = _scaled(rng, ctx["records"], 2500, 6000)
    factor = rng.uniform(1.3, 1.9)
    weights = [factor ** i for i in range(rounds)]
    volumes = [max(20, int(base * 0.6 * w / sum(weights))) for w in weights]
    acts = [_login("target", ip)]
    for i, volume in enumerate(volumes):
        resource = chosen[i % len(chosen)]
        acts += [_access(resource, "view", rng.randint(1, 6)), _access(resource, "download", volume, phase="collection")]
    staging = max(chosen, key=lambda r: (p.perms.get(r) == "write", sensitivity_of(r)))
    acts.append(_access(staging, _transfer_action(p, staging), max(50, int(sum(volumes) * rng.uniform(0.5, 1.0))), phase="staging"))
    if rng.random() < 0.7:
        acts.append(_logout())
    return acts, {"from_known_ip": True, "collection_rounds": rounds, "growth_factor": round(factor, 2), "staging_resource": staging}


def _bulk_export(rng, p, ctx):
    from_known = rng.random() < 0.25
    ip = rng.choice(p.known_ips) if from_known else ctx["source_ip"]
    sensitive = _sensitive(p)
    resource = max(_writable(p, sensitive) or sensitive, key=lambda r: (sensitivity_of(r), r))
    probes = rng.sample(sensitive, min(len(sensitive), rng.randint(1, 3)))
    acts = [_login("target", ip), *[_access(r, "view", rng.randint(5, 40)) for r in probes]]
    denied_pool = [r for r in RESOURCES if not is_self_service(r) and r not in p.perms and sensitivity_of(r) >= 3]
    if denied_pool and rng.random() < 0.5:
        acts.insert(rng.randint(1, len(acts)), _access(rng.choice(denied_pool), "view", 25))
    acts.append(_access(resource, _transfer_action(p, resource), _scaled(rng, ctx["records"], 3000, 15000), phase="bulk_export"))
    if rng.random() < 0.35:
        acts.append(_access(rng.choice(sensitive), "download", rng.randint(300, 2000), phase="bulk_export"))
    if rng.random() < 0.5:
        acts.append(_logout())
    return acts, {"from_known_ip": from_known, "export_resource": resource}


def _external(rng, p, ctx):
    from_known = rng.random() < 0.4
    ip = rng.choice(p.known_ips) if from_known else ctx["source_ip"]
    resource = rng.choice(_sensitive(p))
    collected = _scaled(rng, ctx["records"], 500, 5000)
    sent = max(1, int(collected * rng.uniform(0.5, 1.0)))
    destination = rng.choice(DESTINATIONS)
    status = "confirmed" if rng.random() < 0.65 else "attempted"
    acts = [_login("target", ip), *_views(rng, p, rng.randint(1, 2), [resource]),
            _access(resource, "download", collected, phase="collection"),
            {"kind": "external_transfer", "actor": "target", "resource": resource, "records": sent,
             "destination": destination, "status": status}]
    if rng.random() < 0.3:
        acts.append({"kind": "external_transfer", "actor": "target", "resource": resource, "records": max(1, sent // 3),
                     "destination": rng.choice(DESTINATIONS), "status": "attempted"})
    if rng.random() < 0.4:
        acts.append(_logout())
    return acts, {"from_known_ip": from_known, "transfer_status": status, "destination": destination}


def _removable(rng, p, ctx):
    ip = rng.choice(p.known_ips)
    resource = rng.choice(_sensitive(p))
    large = rng.random() < 0.6
    copies = rng.randint(1, 3)
    device = f"USB-SIM-{rng.randint(1000, 9999)}"
    acts = [_login("target", ip), _access(resource, "view", rng.randint(2, 20))]
    for _ in range(copies):
        records = _scaled(rng, ctx["records"], 1500, 9000) if large else rng.randint(30, 400)
        acts.append({"kind": "removable_media", "actor": "target", "resource": resource, "records": records, "device": device})
    if rng.random() < 0.8:
        acts.append(_logout())
    return acts, {"from_known_ip": True, "volume": "large" if large else "small", "device": device, "copies": copies}


def _low_signals(rng, p, ctx):
    ip = ctx["source_ip"]
    managed = _managed(p)
    readonly = [r for r in managed if p.perms.get(r) == "read"]
    unpermitted_low = [r for r in RESOURCES if not is_self_service(r) and r not in p.perms and sensitivity_of(r) <= 1]
    free = [_access(rng.choice(managed), "download", rng.randint(40, 300), phase="modest_download")]
    if readonly:
        free.append(_access(rng.choice(readonly), "export", 25, phase="insufficient_level"))
    elif unpermitted_low:
        free.append(_access(rng.choice(unpermitted_low), "view", 5, phase="not_permitted_low"))
    free.append(_access(rng.choice(managed), "view", rng.randint(2, 15)))
    rng.shuffle(free)
    failures = {"kind": "failed_login", "actor": "target", "ip": ip, "count": rng.randint(1, 2)}
    acts = [failures, _login("target", ip), *free]
    if rng.random() < 0.5:
        acts.append(_logout())
    return acts, {"from_known_ip": False, "failed_logins": failures["count"]}


def _campaign(rng, p, ctx):
    ip = ctx["source_ip"]
    middle = [s for s, prob in (("restricted_access", 0.85), ("large_export", 0.9), ("admin_login_failures", 0.7)) if rng.random() < prob]
    if rng.random() < 0.6:
        middle += ["create_privileged_account", "privileged_login"]
    if not {"restricted_access", "large_export"} & set(middle):
        middle.append("large_export")
    rng.shuffle(middle)
    if "create_privileged_account" in middle and middle.index("privileged_login") < middle.index("create_privileged_account"):
        a, b = middle.index("create_privileged_account"), middle.index("privileged_login")
        middle[a], middle[b] = middle[b], middle[a]
    steps = list(middle)
    if rng.random() < 0.8:      # exfiltration normally follows collection, but some campaigns never reach it
        low = steps.index("large_export") + 1 if "large_export" in steps else len(steps)
        steps.insert(rng.randint(low, len(steps)), "external_transfer")
    records = _scaled(rng, ctx["records"], 4000, 16000)
    probes = rng.sample(["hr-records", "payroll-records", "it-admin-console", "audit-reports", "loan-applications"], rng.randint(3, 5))
    failed = rng.randint(3, 8)
    acts = [_login("target", ip)]
    for step in steps:
        acts.append({"kind": "campaign_step", "actor": "target", "step": step, "records": records,
                     "failed_attempts": failed, "probe_resources": probes})
    return acts, {"from_known_ip": False, "stages": steps, "failed_attempts": failed}


_BUILDERS = {
    "benign_activity": _benign_activity, "benign_bulk_transfer": _benign_bulk, "gradual_collection_staging": _gradual,
    "bulk_export": _bulk_export, "suspicious_external_transfer": _external, "removable_media": _removable,
    "correlated_low_signals": _low_signals, "compromised_account_campaign": _campaign,
}


# ------------------------------------------------------------------------------------------------------------ noise
def _noise_chain(rng: random.Random, peer: Profile) -> list[dict]:
    actor = f"peer:{peer.id}"
    pool = [*SELF_SERVICE, *[r for r in _managed(peer) if sensitivity_of(r) <= 2]]
    chain = [_login(actor, rng.choice(peer.known_ips))]
    chain += [_access(rng.choice(pool), "view", rng.randint(1, 6), actor=actor) for _ in range(rng.randint(1, 4))]
    if rng.random() < 0.8:
        chain.append(_logout(actor))
    return chain


def _interleave(rng: random.Random, chains: list[list[dict]]) -> list[dict]:
    """Merge chains at random while keeping the order inside each chain (the first chain is the scenario itself)."""
    pending = [list(c) for c in chains]
    merged: list[dict] = []
    while any(pending):
        live = [c for c in pending if c]
        chain = rng.choices(live, weights=[len(c) for c in live])[0]
        merged.append(chain.pop(0))
    return merged


# --------------------------------------------------------------------------------------------------------- public
def generate(scenario: str, seed: int, target: Profile, peers: list[Profile], *, records: int | None = None,
             source_ip: str | None = None, noise: int | None = None) -> dict:
    """Build the plan. The same arguments always give the same plan."""
    if scenario not in _BUILDERS:
        raise PlanError(f"unknown scenario '{scenario}'")
    if not eligible(scenario, target):
        raise PlanError(f"{target.username} cannot play '{scenario}': it needs a known address and access to the relevant resources")
    rng = random.Random(f"plan:{scenario}:{seed}:{target.id}")
    others = [p for p in sorted(peers, key=lambda x: x.id) if p.id != target.id and p.known_ips]
    avoid = set(target.known_ips)
    for other in others:
        avoid |= set(other.known_ips)
    ctx = {"records": records, "source_ip": source_ip or external_ip(rng, avoid)}
    scenario_actions, variant = _BUILDERS[scenario](rng, target, ctx)

    count = rng.randint(1, 3) if noise is None else max(0, min(noise, 3))
    noise_peers = rng.sample(others, min(count, len(others)))
    chains = [scenario_actions, *[_noise_chain(rng, p) for p in noise_peers]]
    actions = _interleave(rng, chains)
    for n, action in enumerate(actions, start=1):
        action["n"] = n
        action["delay_ms"] = 0 if n == 1 else rng.randint(250, 2200)
    plan = {
        "version": PLAN_VERSION, "scenario": scenario, "seed": seed, "target_employee_id": target.id, "target": target.summary(),
        "source_ip": None if variant.get("from_known_ip") else ctx["source_ip"], "variant": variant, "records_override": records,
        "noise_employee_ids": [p.id for p in noise_peers], "actions": actions,
        "resource_sensitivity": {r: SENSITIVITY_LABELS[sensitivity_of(r)] for r in sorted({a["resource"] for a in actions if a.get("resource")})},
    }
    return plan


def plan_digest(plan: dict) -> str:
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def pacing(plan: dict, pace: str) -> list[float]:
    """Seconds to wait before each action. 'instant' skips waiting; 'demo' keeps the recorded gaps, capped in total."""
    delays = [a["delay_ms"] / 1000 for a in plan["actions"]]
    if pace == "instant":
        return [0.0] * len(delays)
    total = sum(delays)
    scale = min(1.0, MAX_DEMO_SECONDS / total) if total else 1.0
    return [d * scale for d in delays]
