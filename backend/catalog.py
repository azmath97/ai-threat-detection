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
}

EVENT_TYPES = (
    "login",
    "login_failed",
    "logout",
    "resource_access",
    "file_download",
    "data_export",
    "external_transfer",
    "permission_change_attempt",
)
AUTH_EVENT_TYPES = ("login", "login_failed", "logout")
RESOURCE_EVENT_TYPES = ("resource_access", "file_download", "data_export")

EVENT_TO_ACTION = {"resource_access": "view", "file_download": "download", "data_export": "export"}
ACTION_TO_EVENT = {v: k for k, v in EVENT_TO_ACTION.items()}
ACTION_REQUIRED_LEVEL = {"view": "read", "download": "read", "export": "write"}
ACCESS_LEVEL_RANK = {"read": 1, "write": 2}

LEVELS = ("low", "medium", "high", "critical")


def sensitivity_of(resource: str | None) -> int:
    if resource and resource in RESOURCES:
        return RESOURCES[resource]["sensitivity"]
    return 0
