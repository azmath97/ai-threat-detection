"""Synthetic resource catalogue and shared vocabulary used by the whole backend."""

SENSITIVITY_LABELS = {1: "internal", 2: "confidential", 3: "restricted"}

RESOURCES: dict[str, dict] = {
    "internal-wiki": {"name": "Internal Wiki", "sensitivity": 1, "department": "All"},
    "marketing-assets": {"name": "Marketing Assets", "sensitivity": 1, "department": "Marketing"},
    "financial-reports": {"name": "Financial Reports", "sensitivity": 2, "department": "Finance"},
    "customer-accounts": {"name": "Customer Accounts", "sensitivity": 2, "department": "Customer Service"},
    "trading-reports": {"name": "Trading Reports", "sensitivity": 2, "department": "Trading"},
    "loan-applications": {"name": "Loan Applications", "sensitivity": 2, "department": "Lending"},
    "audit-reports": {"name": "Audit Reports", "sensitivity": 2, "department": "Compliance"},
    "source-code-repo": {"name": "Source Code Repository", "sensitivity": 2, "department": "Engineering"},
    "payroll-records": {"name": "Payroll Records", "sensitivity": 3, "department": "Finance"},
    "hr-records": {"name": "HR Records", "sensitivity": 3, "department": "HR"},
    "it-admin-console": {"name": "IT Admin Console", "sensitivity": 3, "department": "IT"},
    # Self-service resources: available to every authenticated employee (read only), still logged.
    "my-profile": {"name": "My Profile", "sensitivity": 1, "department": "All", "self_service": True},
    "my-payslips": {"name": "My Payslips", "sensitivity": 1, "department": "All", "self_service": True},
    "employee-directory": {"name": "Employee Directory", "sensitivity": 1, "department": "All", "self_service": True},
    "document-library": {"name": "Document Library", "sensitivity": 1, "department": "All", "self_service": True},
}

EVENT_TYPES = (
    "login",
    "login_failed",
    "logout",
    "resource_access",
    "file_download",
    "data_export",
    "directory_search",
    "administrative_action",
    "external_transfer",
    "permission_change_attempt",
)
RESOURCE_EVENT_TYPES = ("resource_access", "file_download", "data_export")
# Event types whose outcome is decided by the backend permission check
CLIENT_EVENT_TYPES = RESOURCE_EVENT_TYPES + ("external_transfer", "permission_change_attempt")

EVENT_TO_ACTION = {"resource_access": "view", "file_download": "download", "data_export": "export"}
ACTION_TO_EVENT = {v: k for k, v in EVENT_TO_ACTION.items()}
ACTION_REQUIRED_LEVEL = {"view": "read", "download": "read", "export": "write"}
ACCESS_LEVEL_RANK = {"read": 1, "write": 2}

# Risk band: a band of the heuristic risk score (0-100), limited by how many independent attack stages the evidence shows.
# It decides triage order and whether an alert is raised. It says nothing about impact and is not a probability.
# (The identifiers keep their earlier names because they are stored in the database; only the labels changed.)
SEVERITY_LEVELS = ("normal", "suspicious", "high_risk", "critical")
SEVERITY_RANK = {level: rank for rank, level in enumerate(SEVERITY_LEVELS)}
SEVERITY_LABELS = {"normal": "Normal", "suspicious": "Watch", "high_risk": "Elevated", "critical": "Alert"}

# Impact severity: how much harm the evidence shows has happened or is under way. Derived from what was accessed,
# exported or changed, never from the risk score or the anomaly model, so a high-impact event can be reported while the
# detector is still uncertain.
IMPACT_LEVELS = ("none", "low", "medium", "high", "critical")
IMPACT_RANK = {level: rank for rank, level in enumerate(IMPACT_LEVELS)}
IMPACT_LABELS = {"none": "None", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}

# Evidence strength: a qualitative reading of how well independent evidence corroborates the finding. It is not a probability.
STRENGTH_LEVELS = ("none", "weak", "moderate", "strong")
STRENGTH_LABELS = {"none": "No evidence", "weak": "Weak", "moderate": "Moderate", "strong": "Strong"}

# Attack stages in progression order. Evidence decides which are present; no fixed sequence is required.
STAGES = (
    "initial_access",
    "credential_misuse",
    "sensitive_resource_access",
    "collection",
    "privilege_escalation",
    "persistence",
    "lateral_movement",
    "exfiltration",
)
STAGE_LABELS = {
    "none": "None",
    "initial_access": "Initial Access",
    "credential_misuse": "Credential Misuse",
    "sensitive_resource_access": "Sensitive Resource Access",
    "collection": "Collection",
    "privilege_escalation": "Privilege Escalation",
    "persistence": "Persistence",
    "lateral_movement": "Lateral Movement",
    "exfiltration": "Exfiltration",
}


def sensitivity_of(resource: str | None) -> int:
    if resource and resource in RESOURCES:
        return RESOURCES[resource]["sensitivity"]
    return 0


def is_self_service(resource: str | None) -> bool:
    return bool(resource and RESOURCES.get(resource, {}).get("self_service"))


def managed_resources() -> list[str]:
    """Resources that require an explicit permission grant."""
    return [rid for rid in RESOURCES if not is_self_service(rid)]
