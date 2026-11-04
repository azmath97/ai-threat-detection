"""Data exposure assessment, kept separate from the heuristic risk score.

It distinguishes suspicious access, a confirmed record export and a confirmed external transfer, and never
claims exfiltration unless an external transfer was actually confirmed.
"""
from backend.catalog import RESOURCE_EVENT_TYPES, is_self_service, sensitivity_of
from backend.models import SecurityEvent

STATUS_LABELS = {
    "none": "No suspicious data exposure",
    "suspicious_access": "Suspicious access",
    "confirmed_export": "Confirmed record export",
    "confirmed_external_transfer": "Confirmed external transfer",
}


def _sensitive(e: SecurityEvent) -> bool:
    return bool(e.resource) and not is_self_service(e.resource) and sensitivity_of(e.resource) >= 2


def assess(events: list[SecurityEvent], suspicious_context: bool) -> dict:
    """`suspicious_context`: the overall assessment is at least 'suspicious'. Individually flagged events always count."""
    def counts(e: SecurityEvent) -> bool:
        return suspicious_context or bool(e.risk_flags)

    ok = [e for e in events if e.outcome == "success"]
    accessed = [e for e in ok if e.event_type in RESOURCE_EVENT_TYPES and _sensitive(e)]
    exports = [e for e in ok if e.event_type in ("file_download", "data_export")]
    sensitive_exports = [e for e in exports if _sensitive(e)]

    # An attempted transfer followed by its confirmation is one transfer of the same records, not two.
    transfers_by_key: dict[tuple, list[SecurityEvent]] = {}
    for e in events:
        if e.event_type == "external_transfer" and e.outcome != "denied" \
                and (e.details or {}).get("transfer_status", "attempted") != "blocked":
            key = (e.resource, e.records_downloaded or e.records_accessed, (e.details or {}).get("destination"))
            transfers_by_key.setdefault(key, []).append(e)
    transfers = [group[-1] for group in transfers_by_key.values()]
    confirmed = [e for group in transfers_by_key.values() for e in group[-1:]
                 if any(x.outcome == "success" and (x.details or {}).get("transfer_status") == "confirmed" for x in group)]

    sensitive_accessed = sum(e.records_accessed for e in accessed)
    exported = sum(e.records_downloaded for e in exports)
    exported_sensitive = sum(e.records_downloaded for e in sensitive_exports)
    in_transfers = sum(e.records_downloaded or e.records_accessed for e in transfers)
    confirmed_records = sum(e.records_downloaded or e.records_accessed for e in confirmed)
    suspicious_export = sum(e.records_downloaded for e in sensitive_exports if counts(e))
    suspicious_access = sum(e.records_accessed for e in accessed if counts(e))

    # Exported and transferred records are normally the same records, so exposure is the larger of the two.
    exposed = max(suspicious_export, in_transfers) if (suspicious_export or in_transfers) else 0
    if confirmed:
        status = "confirmed_external_transfer"
    elif suspicious_export > 0:
        status = "confirmed_export"
    elif suspicious_access > 0:
        status = "suspicious_access"
    else:
        status = "none"

    if status == "confirmed_external_transfer":
        statement = (f"{confirmed_records:,} records were confirmed transferred to an external destination. "
                     "Treat this as a confirmed data exfiltration.")
    elif transfers:
        statement = (f"An external transfer of {in_transfers:,} records was attempted but is not confirmed. "
                     "Exfiltration is not established.")
    elif status == "confirmed_export":
        statement = (f"{suspicious_export:,} sensitive records were exported (confirmed export). No external transfer has "
                     "been confirmed, so exfiltration is not established.")
    elif status == "suspicious_access":
        statement = f"{suspicious_access:,} sensitive records were accessed in a suspicious context; no export confirmed."
    else:
        statement = STATUS_LABELS["none"] + "."

    return {
        "status": status,
        "status_label": STATUS_LABELS[status],
        "sensitive_records_accessed": sensitive_accessed,
        "records_exported": exported,
        "records_exported_sensitive": exported_sensitive,
        "records_potentially_exposed": exposed,
        "records_in_external_transfers": in_transfers,
        "records_confirmed_external": confirmed_records,
        "external_transfer_confirmed": bool(confirmed),
        "exfiltration_established": bool(confirmed),
        "resources": sorted({e.resource for e in [*accessed, *sensitive_exports, *transfers] if e.resource}),
        "statement": statement,
    }
