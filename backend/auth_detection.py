"""Detection of authentication attacks from the stored sign-in attempts.

Every detector reads the `auth_attempts` table inside a time window, so the counts survive a restart and are the same on
every backend instance. Nothing here changes any state: it returns findings, and `auth_response` decides what to do.

Detectors (thresholds come from `auth_policy`):

* account_brute_force          many failures against one account in a short window
* credential_stuffing          one source address failing against many different accounts
* ip_failure_burst             many failures from one source address (against few accounts)
* distributed_account_attack   one account failing from several source addresses
* login_after_failures         a successful sign-in right after repeated failures (possible account takeover)

An unfamiliar address is never treated as malicious by itself; failures that all come from the account's own registered
addresses need a higher threshold before an account is locked, because that is usually the real employee mistyping.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.auth_policy import AuthPolicy
from backend.models import AuthAttempt, Employee

SAMPLE = 500            # at most this many rows are read to describe a pattern; the counts themselves are exact
MAX_IDS = 50
MAX_LISTED = 20


@dataclass
class Finding:
    kind: str
    severity: str                       # suspicious | high_risk | critical (a rule-based band, not a probability)
    dedup_key: str
    source_ip: str | None
    employee: Employee | None
    title: str
    explanation: str
    evidence: dict = field(default_factory=dict)
    attempts: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None


def _window(db: Session, attempt: AuthAttempt, minutes: int, *conditions) -> dict:
    """Exact count plus a bounded sample (ids, addresses, accounts, first and last time) of the matching attempts."""
    since = attempt.timestamp - timedelta(minutes=minutes)
    where = (AuthAttempt.timestamp >= since, AuthAttempt.timestamp <= attempt.timestamp, *conditions)
    count = db.scalar(select(func.count(AuthAttempt.id)).where(*where)) or 0
    rows = db.execute(select(AuthAttempt.id, AuthAttempt.source_ip, AuthAttempt.subject, AuthAttempt.timestamp)
                      .where(*where).order_by(AuthAttempt.id.desc()).limit(SAMPLE)).all()
    return {
        "count": count,
        "ids": sorted(r.id for r in rows)[-MAX_IDS:],
        "ips": sorted({r.source_ip for r in rows}),
        "subjects": sorted({r.subject for r in rows}),
        "first": min((r.timestamp for r in rows), default=attempt.timestamp),
        "last": max((r.timestamp for r in rows), default=attempt.timestamp),
    }


def _band(count: int, threshold: int) -> str:
    return "critical" if count >= 4 * threshold else "high_risk" if count >= 2 * threshold else "suspicious"


def _account_brute_force(db: Session, attempt: AuthAttempt, employee: Employee, policy: AuthPolicy) -> Finding | None:
    w = _window(db, attempt, policy.account_window_minutes,
                AuthAttempt.employee_id == employee.id, AuthAttempt.outcome == "failure")
    known = set(employee.known_ips or [])
    from_known_only = bool(w["ips"]) and set(w["ips"]) <= known
    threshold = policy.known_ip_fail_threshold if from_known_only else policy.account_fail_threshold
    if threshold <= 0 or w["count"] < threshold:
        return None
    code = employee.employee_code or employee.username
    return Finding(
        "account_brute_force", _band(w["count"], threshold), f"account_brute_force:{code}", attempt.source_ip, employee,
        f"Repeated failed sign-ins against {code} ({w['count']} in {policy.account_window_minutes} min)",
        f"{w['count']} failed sign-ins against {code} within {policy.account_window_minutes} minutes from "
        f"{len(w['ips'])} address(es). Policy threshold: {threshold}"
        + (" (higher, because every failure came from the account's own registered addresses)." if from_known_only else "."),
        {"rule": "failures on one account in a window", "window_minutes": policy.account_window_minutes, "threshold": threshold,
         "failures": w["count"], "source_ips": w["ips"][:MAX_LISTED], "all_from_known_ips": from_known_only,
         "attempt_ids": w["ids"]},
        w["count"], w["first"], w["last"])


def _distributed(db: Session, attempt: AuthAttempt, employee: Employee, policy: AuthPolicy) -> Finding | None:
    w = _window(db, attempt, policy.distributed_window_minutes,
                AuthAttempt.employee_id == employee.id, AuthAttempt.outcome == "failure")
    if policy.distributed_ips <= 0 or len(w["ips"]) < policy.distributed_ips or w["count"] < policy.distributed_failures:
        return None
    code = employee.employee_code or employee.username
    return Finding(
        "distributed_account_attack", "high_risk", f"distributed_account_attack:{code}", None, employee,
        f"{code} is being attacked from {len(w['ips'])} different addresses",
        f"{w['count']} failed sign-ins against {code} from {len(w['ips'])} different addresses within "
        f"{policy.distributed_window_minutes} minutes. Policy: at least {policy.distributed_ips} addresses and "
        f"{policy.distributed_failures} failures.",
        {"rule": "one account, many source addresses", "window_minutes": policy.distributed_window_minutes,
         "failures": w["count"], "source_ips": w["ips"][:MAX_LISTED], "attempt_ids": w["ids"]},
        w["count"], w["first"], w["last"])


def _from_one_address(db: Session, attempt: AuthAttempt, policy: AuthPolicy) -> Finding | None:
    ip = attempt.source_ip
    stuffing = _window(db, attempt, policy.stuffing_window_minutes, AuthAttempt.source_ip == ip, AuthAttempt.outcome == "failure")
    accounts = len(stuffing["subjects"])
    if 0 < policy.stuffing_accounts_alert <= accounts:
        critical = accounts >= policy.stuffing_accounts_critical > 0 or stuffing["count"] >= policy.ip_block_threshold > 0
        return Finding(
            "credential_stuffing", "critical" if critical else "high_risk", f"credential_stuffing:{ip}", ip, None,
            f"Credential stuffing from {ip}: {accounts} different accounts targeted",
            f"{stuffing['count']} failed sign-ins from {ip} against {accounts} different accounts within "
            f"{policy.stuffing_window_minutes} minutes (alert at {policy.stuffing_accounts_alert} accounts, critical at "
            f"{policy.stuffing_accounts_critical} accounts or {policy.ip_block_threshold} failures).",
            {"rule": "one source address, many accounts", "window_minutes": policy.stuffing_window_minutes,
             "threshold": policy.stuffing_accounts_alert, "critical_threshold": policy.stuffing_accounts_critical,
             "failures": stuffing["count"], "distinct_accounts": accounts, "accounts": stuffing["subjects"][:MAX_LISTED],
             "attempt_ids": stuffing["ids"]},
            stuffing["count"], stuffing["first"], stuffing["last"])
    burst = _window(db, attempt, policy.ip_alert_window_minutes, AuthAttempt.source_ip == ip, AuthAttempt.outcome == "failure")
    long = _window(db, attempt, policy.ip_block_window_minutes, AuthAttempt.source_ip == ip, AuthAttempt.outcome == "failure")
    if 0 < policy.ip_block_threshold <= long["count"]:
        use, severity, threshold, window = long, "critical", policy.ip_block_threshold, policy.ip_block_window_minutes
    elif 0 < policy.ip_alert_failures <= burst["count"]:
        use, severity, threshold, window = burst, "high_risk", policy.ip_alert_failures, policy.ip_alert_window_minutes
    else:
        return None
    return Finding(
        "ip_failure_burst", severity, f"ip_failure_burst:{ip}", ip, None,
        f"{use['count']} failed sign-ins from {ip} in {window} min",
        f"{use['count']} failed sign-ins from {ip} within {window} minutes against {len(use['subjects'])} account(s). "
        f"Policy threshold: {threshold}.",
        {"rule": "failures from one source address", "window_minutes": window, "threshold": threshold, "failures": use["count"],
         "accounts": use["subjects"][:MAX_LISTED], "attempt_ids": use["ids"]},
        use["count"], use["first"], use["last"])


def _login_after_failures(db: Session, attempt: AuthAttempt, employee: Employee, policy: AuthPolicy) -> Finding | None:
    w = _window(db, attempt, policy.success_window_minutes,
                AuthAttempt.employee_id == employee.id, AuthAttempt.outcome == "failure")
    if policy.success_after_failures <= 0 or w["count"] < policy.success_after_failures:
        return None
    known = set(employee.known_ips or [])
    failure_ips = set(w["ips"])
    if attempt.source_ip in known and attempt.source_ip not in failure_ips:
        # The owner signing in from their own registered address while the failures came from other addresses: the attack
        # failed (and is reported by the brute-force or stuffing findings). Treating this as a takeover would punish the victim.
        return None
    familiar = attempt.source_ip in known
    code = employee.employee_code or employee.username
    return Finding(
        "login_after_failures", "suspicious" if familiar else "critical", f"login_after_failures:{code}", attempt.source_ip, employee,
        f"Successful sign-in to {code} after {w['count']} failures" + (" (familiar address)" if familiar else ""),
        f"{code} signed in successfully from {attempt.source_ip} after {w['count']} failed attempts within "
        f"{policy.success_window_minutes} minutes from {len(w['ips'])} address(es). "
        + ("The sign-in came from an address registered to this account that also produced failures, which usually means the "
           "employee mistyped, so this is flagged for review only." if familiar else
           "The sign-in came from an address that is not registered to this account, after repeated failures: possible account "
           "takeover."),
        {"rule": "success after repeated failures", "window_minutes": policy.success_window_minutes, "failures_before": w["count"],
         "success_ip": attempt.source_ip, "failure_ips": w["ips"][:MAX_LISTED], "familiar": familiar,
         "attempt_ids": [*w["ids"][-MAX_IDS + 1:], attempt.id]},
        w["count"] + 1, w["first"], attempt.timestamp)


def evaluate(db: Session, attempt: AuthAttempt, employee: Employee | None, policy: AuthPolicy) -> list[Finding]:
    """Every pattern the new attempt completes or extends. Pure reads."""
    found: list[Finding | None] = []
    if attempt.outcome == "failure":
        if employee is not None:
            found += [_account_brute_force(db, attempt, employee, policy), _distributed(db, attempt, employee, policy)]
        found.append(_from_one_address(db, attempt, policy))
    elif attempt.outcome == "success" and employee is not None:
        found.append(_login_after_failures(db, attempt, employee, policy))
    return [f for f in found if f is not None]
