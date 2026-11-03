"""Canonical event schema, source-file expectations and field mapping for the CERT insider-threat release.

CERT Insider Threat Test Dataset (Carnegie Mellon University SEI CERT Division with ExactData, LLC; DARPA I2O):
https://sei.cmu.edu/library/insider-threat-test-dataset/  -  DOI 10.1184/R1/12841247.v1  -  licence CC BY 4.0.
It is SYNTHETIC: synthetic background users plus synthetic malicious actors. It is not real banking data.
"""
from dataclasses import dataclass

RELEASE = "r4.2"
SOURCE_CERT = f"cert_{RELEASE}"
SOURCE_SYNTHETIC = "synthetic_test"
SYNTHETIC_NOTICE = ("The CERT Insider Threat Test Dataset is synthetic (generated background activity plus synthetic malicious "
                    "actors). It is not real banking data and no figure derived from it describes a real organisation.")

# Event types used by the prepared dataset. They are dataset-level types; only logon/logoff have an
# equivalent in the application's event catalogue (login/logout) - see docs/cert-dataset.md.
EVENT_TYPES = ("logon", "logoff", "device_connect", "device_disconnect", "web_visit", "email_send", "file_access",
               "file_copy_removable")

# ---------------------------------------------------------------------------------------------- canonical columns
# Columns a detector may use as model input (event level). Everything else is identity, label or evaluation metadata.
MODEL_INPUT_COLUMNS = (
    "timestamp_utc", "host", "event_type", "activity", "auth_result", "destination", "resource", "bytes",
    "attachment_count", "recipient_count", "external_recipient_count", "removable_media",
)
# Needed to group events per person, never a model input (pseudonymous; the real user id lives in identity_map.csv).
GROUPING_COLUMNS = ("entity_id",)
# Provenance columns: kept for storage/UI, forbidden as model input (a model could learn "synthetic" or the source).
PROVENANCE_COLUMNS = ("event_id", "source", "is_synthetic")
EVENT_COLUMNS = ("event_id", "source", "timestamp_utc", "entity_id", *MODEL_INPUT_COLUMNS[1:], "is_synthetic")
LABEL_COLUMNS = ("event_id", "label", "label_basis")
EVAL_METADATA_COLUMNS = ("event_id", "scenario", "insider_user", "incident_file", "incident_start", "incident_end")
# Never allowed in a feature set: ground truth, answer-key fields, identity, split assignment, provenance.
FORBIDDEN_FEATURE_COLUMNS = frozenset({
    "label", "label_basis", "scenario", "insider_user", "incident_file", "incident_start", "incident_end", "answer_key",
    "user", "user_id", "entity_id", "split", "is_insider", "event_id", "source", "is_synthetic",
})

LABEL_MALICIOUS = "answer_key_event"                  # event id listed in the answer key, performed by the insider's own account
LABEL_AMBIGUOUS = "answer_key_other_account"          # listed in the answer key but recorded under a different account
LABEL_BENIGN = "no_answer_key_entry"                  # absent from the answer key (stored implicitly; see labels.py)

TIMESTAMP_FORMAT = "%m/%d/%Y %H:%M:%S"
TIMEZONE_ASSUMPTION = ("CERT timestamps carry no UTC offset. They are the organisation's local clock; they are stored "
                       "unchanged and labelled UTC, so 'hour of day' means organisation-local hour.")


@dataclass(frozen=True)
class SourceSpec:
    kind: str                      # canonical source name
    filename: str
    required: tuple[str, ...]      # columns that must be present
    use: tuple[str, ...]           # columns read (large free-text 'content' is never read)
    optional_file: bool = True     # False: the release cannot be prepared without it


# Column layout of release r4.2 (verified against the extracted release, see docs/cert-dataset.md).
SOURCES: dict[str, SourceSpec] = {
    "logon": SourceSpec("logon", "logon.csv", ("id", "date", "user", "pc", "activity"), ("id", "date", "user", "pc", "activity"),
                        optional_file=False),
    "device": SourceSpec("device", "device.csv", ("id", "date", "user", "pc", "activity"), ("id", "date", "user", "pc", "activity")),
    "http": SourceSpec("http", "http.csv", ("id", "date", "user", "pc", "url"), ("id", "date", "user", "pc", "url")),
    "email": SourceSpec("email", "email.csv", ("id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments"),
                        ("id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments")),
    "file": SourceSpec("file", "file.csv", ("id", "date", "user", "pc", "filename"), ("id", "date", "user", "pc", "filename")),
}

LOGON_ACTIVITY = {"logon": "logon", "logoff": "logoff"}
DEVICE_ACTIVITY = {"connect": "device_connect", "disconnect": "device_disconnect"}

# source field -> canonical field (documented in docs/cert-dataset.md)
FIELD_MAP = {
    "id": "event_id", "date": "timestamp_utc (parsed, format %m/%d/%Y %H:%M:%S)", "user": "entity_id (pseudonymised)",
    "pc": "host", "activity": "activity / event_type", "url": "destination (host name only) + resource (host name)",
    "filename": "resource (file.csv rows are file COPIES TO REMOVABLE MEDIA: event_type file_copy_removable, removable_media=true)",
    "size": "bytes", "attachments": "attachment_count",
    "to,cc,bcc": "recipient_count, external_recipient_count, destination (recipient domains)",
}

# Optional LDAP snapshot (LDAP/YYYY-MM.csv): only organisational context is kept. Names, e-mail addresses, supervisors and
# psychometric scores are deliberately NOT carried over.
LDAP_CONTEXT_COLUMNS = ("role", "business_unit", "functional_unit", "department", "team")


class DatasetError(Exception):
    """A user-facing problem with the dataset files (missing, malformed, wrong release)."""
