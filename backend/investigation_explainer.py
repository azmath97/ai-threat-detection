"""Deterministic, evidence-based explanation of an investigation.

The explainer receives only structured evidence taken from the database (events, rule flags, the live threat
assessment, the employee's baseline) and builds statements from those facts. Every statement that mentions an event
carries its real event ID and timestamp; nothing is generated from outside the evidence, so it needs no external
service. The structured input could be handed to an LLM later, but the application does not depend on one.
"""
from datetime import datetime

from backend import rules
from backend.catalog import RESOURCES, SEVERITY_LABELS, STAGE_LABELS, is_self_service, sensitivity_of
from backend.config import to_local
from backend.database import utcnow
from backend.models import Employee, SecurityEvent

ENGINE = "deterministic-evidence-v1"

ATTACK_TYPES = {
    "confirmed_external_transfer": ("Confirmed external data transfer", 6),
    "privilege_escalation": ("Privilege escalation", 5),
    "unauthorised_data_export": ("Unauthorised data export", 4),
    "compromised_credentials": ("Compromised employee credentials", 3),
    "automated_account_exploitation": ("Automated account exploitation", 2),
    "possible_insider_misuse": ("Possible insider misuse", 1),
}
ATTRIBUTION = ("The evidence shows what the account did, not who was operating it. The identity of the person behind the "
               "activity is not established and should not be assumed.")
CREDENTIAL_RULES = {"failed_login_burst", "admin_console_login_failed", "login_after_failures"}
MISUSE_RULES = {"unauthorised_department_access", "restricted_denied", "sensitive_access_novel", "large_export",
                "unusual_outbound_transfer", "rapid_enumeration"}
AUTOMATION_BURST = 5          # failed logins ...
AUTOMATION_SECONDS = 60       # ... within this many seconds


def _stamp(ts: datetime) -> str:
    return to_local(ts).strftime("%d %b %Y %H:%M:%S")


def _ref(e: SecurityEvent) -> dict:
    return {"event_id": e.id, "timestamp": e.timestamp.isoformat(), "local": _stamp(e.timestamp)}


def _tag(e: SecurityEvent) -> str:
    return f"event #{e.id} ({_stamp(e.timestamp)})"


def _tags(events: list[SecurityEvent], limit: int = 4) -> str:
    shown = ", ".join(f"#{e.id}" for e in events[:limit])
    return shown + (f" and {len(events) - limit} more" if len(events) > limit else "")


def _rules_of(e: SecurityEvent) -> list[str]:
    return [f["rule"] for f in (e.risk_flags or [])]


def _name(resource: str | None) -> str:
    return RESOURCES.get(resource or "", {}).get("name", resource or "-")


def describe(e: SecurityEvent) -> str:
    """One factual sentence built only from the event's stored fields."""
    who, ip = e.employee.employee_code or e.employee.username, e.source_ip
    records = e.records_downloaded or e.records_accessed
    n = f" ({records:,} records)" if records else ""
    if e.event_type == "login":
        return f"{who} logged in from {ip}"
    if e.event_type == "login_failed":
        target = " to the IT Admin Console" if e.resource == "it-admin-console" or (e.details or {}).get("auth_target") else ""
        return f"Failed login by {who}{target} from {ip}"
    if e.event_type == "logout":
        return f"{who} logged out"
    if e.event_type == "external_transfer":
        status = (e.details or {}).get("transfer_status", "attempted")
        return f"External transfer of {_name(e.resource)}{n} to {(e.details or {}).get('destination', 'an external destination')} ({status}, {e.outcome})"
    if e.event_type == "administrative_action":
        return f"Administrative action by {who} on {_name(e.resource)} ({e.outcome})"
    if e.event_type == "permission_change_attempt":
        return f"Permission change attempt by {who} ({e.outcome})"
    if e.event_type == "file_download" and (e.details or {}).get("channel") == "removable_media" and e.outcome != "denied":
        return f"{who} copied {_name(e.resource)}{n} to removable media ({(e.details or {}).get('device', 'device')})"
    verb = {"resource_access": "viewed", "file_download": "downloaded", "data_export": "exported"}.get(e.event_type, e.event_type)
    if e.outcome == "denied":
        return f"{who} was denied access to {_name(e.resource)} ({verb} attempt)"
    return f"{who} {verb} {_name(e.resource)}{n}"


def _burst(failures: list[SecurityEvent]) -> list[SecurityEvent]:
    """The largest group of failed logins inside AUTOMATION_SECONDS."""
    best: list[SecurityEvent] = []
    for i, first in enumerate(failures):
        group = [e for e in failures[i:] if (e.timestamp - first.timestamp).total_seconds() <= AUTOMATION_SECONDS]
        if len(group) > len(best):
            best = group
    return best


def classify(events: list[SecurityEvent], employee: Employee, exposure: dict, known_ips: set[str]) -> list[dict]:
    """Evaluate every attack category against the evidence. Each result lists the events that support it."""
    flagged = [e for e in events if e.risk_flags]
    with_rule = lambda *ids: [e for e in flagged if set(ids) & set(_rules_of(e))]

    transfers = [e for e in events if e.event_type == "external_transfer" and e.outcome == "success"
                 and (e.details or {}).get("transfer_status") == "confirmed"]
    exports = [e for e in with_rule("large_export") if e.outcome == "success"]
    privilege = with_rule("privileged_account_created", "permission_change_attempt")
    unfamiliar = [e for e in with_rule("unfamiliar_ip") if e.source_ip not in known_ips]
    credential = with_rule(*CREDENTIAL_RULES)
    bad_ips = {e.source_ip for e in unfamiliar}
    followers = [e for e in flagged if e not in unfamiliar and (e.source_ip in bad_ips or e in credential)
                 and any(s != "initial_access" for f in e.risk_flags for s in f.get("stages", []))]
    failures = sorted((e for e in events if e.event_type == "login_failed"), key=lambda e: (e.timestamp, e.id))
    burst = _burst(failures)
    enumeration = with_rule("rapid_enumeration")
    misuse = [e for e in with_rule(*MISUSE_RULES) if e.source_ip in known_ips]

    def entry(key, supported, basis, reason):
        return {"type": key, "label": ATTACK_TYPES[key][0], "supported": bool(supported), "reason": reason,
                "events": [_ref(e) for e in basis] if supported else []}

    out = [
        entry("confirmed_external_transfer", exposure.get("external_transfer_confirmed") and transfers, transfers,
              (f"A transfer was confirmed in {_tags(transfers)}." if transfers else
               "No external transfer is confirmed; an attempted or blocked transfer does not establish exfiltration.")),
        entry("privilege_escalation", privilege, privilege,
              (f"Privileged account creation or permission change in {_tags(privilege)}." if privilege else
               "No privileged account creation or permission-change attempt is recorded.")),
        entry("unauthorised_data_export", exports or exposure.get("status") in ("confirmed_export", "confirmed_external_transfer"),
              exports,
              (f"Export well above the employee's baseline in {_tags(exports)}; {exposure.get('records_exported', 0):,} records exported. "
               "Whether the export was business-approved is not verified." if exports else
               "No export above the employee's baseline is recorded.")),
        entry("compromised_credentials", unfamiliar and (followers or credential), [*unfamiliar, *credential, *followers],
              (f"Activity from address(es) outside the employee's known IPs ({', '.join(sorted(bad_ips))}) in {_tags(unfamiliar)}, "
               f"followed by credential misuse or sensitive activity in {_tags([*credential, *followers])}." if unfamiliar and (followers or credential)
               else "No unfamiliar source address combined with credential misuse or follow-on activity.")),
        entry("automated_account_exploitation", len(burst) >= AUTOMATION_BURST or enumeration, [*burst, *enumeration],
              (f"Failed logins in {_tags(burst)} ({len(burst)} within {AUTOMATION_SECONDS} seconds) or rapid enumeration of resources "
               f"in {_tags(enumeration)} is faster than typical manual use; this is indicative only."
               if len(burst) >= AUTOMATION_BURST or enumeration else
               "No burst of failed logins or rapid resource enumeration at machine pace.")),
        entry("possible_insider_misuse", misuse and not unfamiliar and not credential, misuse,
              (f"Out-of-baseline access or export from the employee's own known address in {_tags(misuse)}, with no unfamiliar address "
               "or credential misuse." if misuse and not unfamiliar and not credential else
               "Not indicated: either no out-of-baseline activity from a known address, or the activity involves unfamiliar "
               "addresses or credential misuse that point to account compromise.")),
    ]
    return out


def _activities(flagged: list[SecurityEvent]) -> list[dict]:
    groups: dict[str, list[SecurityEvent]] = {}
    known = rules.rules()
    for e in flagged:
        for rule_id in _rules_of(e):
            if rule_id in known and known[rule_id].severity >= rules.param("min_evidence_severity"):
                groups.setdefault(rule_id, []).append(e)
    result = []
    for rule_id, evs in groups.items():
        evs.sort(key=lambda e: (e.timestamp, e.id))
        result.append({
            "rule": rule_id, "description": known[rule_id].description, "count": len(evs),
            "events": [_ref(e) for e in evs], "first_seen": evs[0].timestamp.isoformat(), "last_seen": evs[-1].timestamp.isoformat(),
            "resources": sorted({e.resource for e in evs if e.resource}), "source_ips": sorted({e.source_ip for e in evs}),
            "stages": list(known[rule_id].stages),
        })
    return sorted(result, key=lambda a: a["first_seen"])


def _impact(events: list[SecurityEvent], exposure: dict, threat, accounts: list[str]) -> list[str]:
    impact = [exposure.get("statement", "")]
    sensitive: dict[str, int] = {}
    for e in events:
        if e.outcome == "success" and e.resource and not is_self_service(e.resource) and sensitivity_of(e.resource) >= 2 and e.risk_flags:
            sensitive[e.resource] = sensitive.get(e.resource, 0) + e.records_accessed
    for resource, records in sensitive.items():
        level = {2: "confidential", 3: "restricted"}[sensitivity_of(resource)]
        impact.append(f"{_name(resource)} ({level}) was accessed successfully in a flagged context"
                      + (f"; {records:,} records read." if records else "."))
    if accounts:
        impact.append(f"Privileged account(s) {', '.join(accounts)} created during the incident could give an attacker persistent access "
                      "until removed.")
    if exposure.get("external_transfer_confirmed"):
        impact.append("A confirmed external transfer may trigger data-breach assessment and notification obligations.")
    elif exposure.get("status") == "confirmed_export":
        impact.append("Exported records are in the account holder's hands; a further transfer could still follow, so it has not been "
                      "established that data left the organisation.")
    if len(impact) == 1 and exposure.get("status") == "none":
        impact.append("No data exposure is established from the evidence collected so far.")
    return [i for i in impact if i]


def _missing(events: list[SecurityEvent], employee: Employee, exposure: dict, threat, baseline, bad_ips: list[str]) -> list[str]:
    missing = ["No out-of-band verification is recorded (contact with the employee or their manager, MFA outcome), so it is unknown "
               "whether the legitimate account holder performed these actions."]
    missing += [f"No geolocation, hosting-provider or reputation data is available for {ip}; it is not known whether it is a VPN, "
                "proxy, home or hostile network." for ip in bad_ips]
    if exposure.get("records_exported", 0) and not exposure.get("external_transfer_confirmed"):
        missing.append("What happened to the exported files after download is unknown: no confirmed external transfer is recorded.")
    if any(e.event_type == "external_transfer" for e in events) and not exposure.get("external_transfer_confirmed"):
        missing.append("An external transfer was attempted but never confirmed; the destination's ownership and the data actually "
                       "delivered are unknown.")
    created = list(threat.related_accounts.values())
    used = {e.employee.username for e in events if e.event_type == "login" and e.outcome == "success"}
    for username in created:
        if username not in used:
            missing.append(f"No successful login by the created account {username} is recorded, so its intended use is unknown.")
    admin_failures = [e for e in events if e.event_type == "login_failed" and (e.resource == "it-admin-console" or (e.details or {}).get("auth_target"))]
    if admin_failures and not created:
        missing.append("No privileged account or successful administrator action follows the failed administrator logins, so their intent is unconfirmed.")
    if baseline is not None and baseline.login_count < 5:
        missing.append(f"Only {baseline.login_count} earlier login(s) exist for {employee.employee_code}; the behavioural baseline is thin.")
    missing.append("Only the device string recorded at login is available; no endpoint or network forensic data is collected.")
    return missing


def _alternatives(events: list[SecurityEvent], employee: Employee, baseline, bad_ips: list[str], created: list[str]) -> list[str]:
    alt: list[str] = []
    flagged = [e for e in events if e.risk_flags]
    unfamiliar = [e for e in flagged if "unfamiliar_ip" in _rules_of(e)]
    if unfamiliar:
        known = ", ".join(sorted(employee.known_ips or [])) or "none registered"
        alt.append(f"The employee may be working from a new network (travel, home, mobile hotspot or VPN): "
                   f"{_tags(unfamiliar)} came from an address outside their registered IPs ({known}). An unfamiliar address alone is not an attack.")
    exports = [e for e in flagged if "large_export" in _rules_of(e)]
    if exports:
        largest = max(exports, key=lambda e: e.records_downloaded)
        usual = getattr(baseline, "session_download_max", 0.0) or 0.0
        alt.append(f"The export in {_tag(largest)} ({largest.records_downloaded:,} records) could be an approved bulk task "
                   f"(the employee's largest earlier session download was {usual:,.0f} records). Confirm against a business request.")
    failures = [e for e in events if e.event_type == "login_failed"]
    if failures:
        alt.append(f"The failed logins ({_tags(failures)}) could be a forgotten password or a misconfigured script rather than guessing.")
    if created or any("privileged_account_created" in _rules_of(e) for e in flagged):
        ev = next(e for e in flagged if "privileged_account_created" in _rules_of(e)) if any("privileged_account_created" in _rules_of(e) for e in flagged) else None
        alt.append("Account creation by an administrator can be legitimate provisioning"
                   + (f" ({_tag(ev)})" if ev else "") + "; verify it against a change request.")
    cross = [e for e in flagged if {"unauthorised_department_access", "restricted_denied"} & set(_rules_of(e))]
    if cross:
        alt.append(f"Denied access to other departments' resources ({_tags(cross)}) can result from mis-navigation or cross-team work; "
                   "the denials show the permission model worked.")
    transfers = [e for e in events if e.event_type == "external_transfer"]
    if transfers:
        alt.append(f"The external transfer ({_tags(transfers)}) could be an approved data-sharing job; confirm who owns the destination.")
    if not alt:
        alt.append("The activity may be routine work for this role; the evidence collected so far does not rule that out.")
    return alt


def explain(*, employee: Employee, events: list[SecurityEvent], threat, baseline, exposure: dict, actions: list[dict],
            synthetic: bool, relations: dict[int, list[str]] | None = None) -> dict:
    """Build the explanation from structured evidence. `events` are the collected, preserved events."""
    events = sorted(events, key=lambda e: (e.timestamp, e.id))
    relations = relations or {}
    flagged = [e for e in events if e.risk_flags]
    known_ips = set(employee.known_ips or []) | set(getattr(baseline, "known_ips", set()) or set())
    classes = classify(events, employee, exposure, known_ips)
    supported = [c for c in classes if c["supported"]]
    primary = max(supported, key=lambda c: ATTACK_TYPES[c["type"]][1]) if supported else None
    by_type = {c["type"]: c for c in classes}

    if by_type["compromised_credentials"]["supported"]:
        vector, vector_text = "compromised_credentials", "consistent with the use of compromised credentials"
    elif by_type["possible_insider_misuse"]["supported"]:
        vector, vector_text = "possible_insider_misuse", "consistent with possible insider misuse"
    else:
        vector, vector_text = "undetermined", "access vector not determined from the evidence"
    if primary is None:
        attack = {"type": "none", "label": "No attack pattern established", "vector": vector,
                  "text": "The collected evidence does not support a specific attack category."}
    else:
        also = [c["label"] for c in supported if c["type"] not in (primary["type"], vector)]
        attack = {"type": primary["type"], "label": primary["label"], "vector": vector,
                  "text": f"{primary['label']}, {vector_text}." + (f" Also indicated: {', '.join(also)}." if also else ""),
                  "also": also}

    stage_hits = threat.correlation.stages if threat.correlation else []
    stage = {"key": threat.stage, "label": STAGE_LABELS[threat.stage],
             "observed": [{"stage": h.stage, "label": STAGE_LABELS[h.stage], "first_seen": h.first_seen.isoformat(),
                           "event_ids": h.event_ids} for h in stage_hits]}

    strongest = {e.id: max((f["severity"] if "severity" in f else f.get("points", 0) / 100 for f in e.risk_flags), default=0) for e in flagged}
    supporting = [{**_ref(e), "account": e.employee.employee_code or e.employee.username, "event_type": e.event_type,
                   "resource": e.resource, "source_ip": e.source_ip, "outcome": e.outcome, "statement": describe(e),
                   "rules": _rules_of(e), "links": relations.get(e.id, [])}
                  for e in flagged if strongest[e.id] >= rules.param("min_evidence_severity")][:60]

    created = list(threat.related_accounts.values())
    bad_ips = sorted({e.source_ip for e in flagged if "unfamiliar_ip" in _rules_of(e) and e.source_ip not in known_ips})
    comps = threat.components or {}
    risk = {
        "risk_score": threat.risk_score, "score": threat.score, "score_is_probability": False,
        "risk_band": threat.level, "risk_band_label": SEVERITY_LABELS[threat.level], "band_gated": bool(threat.band_gated),
        "impact_severity": threat.impact["level"], "impact_label": threat.impact["label"], "impact_reasons": threat.impact["reasons"],
        "evidence_strength": threat.strength["level"], "strength_label": threat.strength["label"],
        "strength_reasons": threat.strength["reasons"],
        "ml_anomaly_score": round(threat.ml.score, 3) if threat.ml else 0.0,
        "independent_stages": threat.counted_stages,
        "contributions": {k: comps[k]["contribution"] for k in ("rules", "ml") if k in comps},
        "breakdown": threat.breakdown,
        "statement": (f"Heuristic risk score {threat.risk_score:.1f}/100 (a hand-weighted evidence score, not a probability), risk band "
                      f"{SEVERITY_LABELS[threat.level]}, from {threat.counted_stages} independent attack stage(s). Impact severity "
                      f"({threat.impact['label']}) is judged from what the evidence shows was accessed or changed, separately from "
                      f"the score. Evidence strength is {threat.strength['label'].lower()}."),
    }

    return {
        "engine": ENGINE, "llm_used": False, "synthetic": synthetic, "generated_at": utcnow().isoformat(),
        "evidence_event_count": len(events),
        "attack_type": attack,
        "classifications": classes,
        "current_stage": stage,
        "suspicious_activities": _activities(flagged),
        "supporting_evidence": supporting,
        "risk_assessment": risk,
        "potential_impact": _impact(events, exposure, threat, created),
        "recommended_containment": [{"action": a["action"], "priority": a["priority"], "target": a.get("target"),
                                     "reason": a["reason"], "executable": a.get("executable", True)} for a in actions],
        "missing_evidence": _missing(events, employee, exposure, threat, baseline, bad_ips),
        "alternative_explanations": _alternatives(events, employee, baseline, bad_ips, created),
        "attribution": ATTRIBUTION,
        "simulation_notice": ("All events are synthetic and generated by the local simulation; containment affects only the simulated "
                              "environment, not a real banking network.") if synthetic else None,
    }
