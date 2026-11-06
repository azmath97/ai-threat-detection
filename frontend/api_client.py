"""Thin HTTP client for the FastAPI backend. The backend is the only source of identity and permissions."""
import os

import requests


def _timeout() -> float:
    try:
        return float(os.getenv("API_TIMEOUT_SECONDS", "20"))
    except ValueError:
        return 20.0


def env_seconds(name: str, default: float, minimum: float) -> float:
    """Read a refresh interval from the environment; invalid values fall back to the default, small ones to the minimum.

    The minimum stops a misconfigured dashboard from polling the backend aggressively."""
    try:
        value = float(os.getenv(name, default))
    except ValueError:
        value = default
    return max(minimum, value)


def _api_base_url() -> str:
    """Where the backend is. Production never falls back to a localhost default: a missing value stops the app with a clear message."""
    value = os.getenv("API_BASE_URL", "").strip()
    if not value and os.getenv("APP_ENV", "").strip().lower() == "production":
        raise RuntimeError("API_BASE_URL must be set when APP_ENV=production (the address of the deployed backend)")
    return (value or "http://127.0.0.1:8000").rstrip("/")


API_BASE_URL = _api_base_url()
TIMEOUT = _timeout()          # raise it on free hosts whose API sleeps when idle
FRONTEND_KEY = os.getenv("TRUSTED_FRONTEND_KEY", "")
CLIENT_IP_HEADER = "X-Westbridge-Client-IP"      # set by the gateway from what the hosting platform observed; never by the browser


def _browser_ip() -> str | None:
    """The end user's address for this Streamlit session, as the gateway measured it (None locally, where there is no gateway)."""
    try:
        import streamlit as st

        return st.context.headers.get(CLIENT_IP_HEADER) or None
    except Exception:  # noqa: BLE001 - outside a Streamlit run there is simply no browser to ask
        return None


class ApiError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class ApiClient:
    def __init__(self, token: str | None = None, device: str | None = None, idempotency_key: str | None = None):
        self.token = token
        self.device = device
        self.idempotency_key = idempotency_key        # lets the backend drop a repeat of the same action (retry, double click)

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.device:
            headers["X-Device-Info"] = self.device
        if FRONTEND_KEY:
            headers["X-Frontend-Key"] = FRONTEND_KEY
            client_ip = _browser_ip()
            if client_ip:
                headers["X-Client-IP"] = client_ip       # the backend believes this only because the key above proves who is asking
        if self.idempotency_key:
            headers["Idempotency-Key"] = self.idempotency_key
        try:
            response = requests.request(method, f"{API_BASE_URL}{path}", headers=headers, timeout=TIMEOUT, **kwargs)
        except requests.RequestException as exc:
            raise ApiError(0, "The service is currently unavailable. Please try again shortly.") from exc
        if response.status_code >= 400:
            raise ApiError(response.status_code, _detail(response))
        return response

    def _json(self, method: str, path: str, **kwargs):
        return self._request(method, path, **kwargs).json()

    # authentication
    def login(self, employee_id: str, password: str) -> dict:
        return self._json("POST", "/api/auth/login", json={"employee_id": employee_id, "password": password})

    def logout(self) -> None:
        self._request("POST", "/api/auth/logout")

    # employee
    def me(self) -> dict:
        return self._json("GET", "/api/employees/me")

    def resources(self) -> list[dict]:
        return self._json("GET", "/api/resources")

    def my_activity(self, limit: int = 10) -> list[dict]:
        return self._json("GET", "/api/events/me", params={"limit": limit})

    def profile_detail(self) -> dict:
        return self._json("GET", "/api/portal/profile")

    # payroll
    def payslips(self) -> list[dict]:
        return self._json("GET", "/api/portal/payslips")

    def payslip(self, period: str) -> dict:
        return self._json("GET", f"/api/portal/payslips/{period}")

    def payroll_register(self) -> list[dict]:
        return self._json("GET", "/api/portal/payroll/register")

    def payroll_export(self) -> dict:
        return self._json("POST", "/api/portal/payroll/export")

    # HR records
    def hr_records(self, query: str = "") -> list[dict]:
        return self._json("GET", "/api/portal/hr/records", params={"q": query})

    def hr_record(self, employee_id: str) -> dict:
        return self._json("GET", f"/api/portal/hr/records/{employee_id}")

    # documents
    def documents(self) -> list[dict]:
        return self._json("GET", "/api/portal/documents")

    def download_document(self, doc_id: str) -> tuple[bytes, str, str]:
        response = self._request("GET", f"/api/portal/documents/{doc_id}/download")
        disposition = response.headers.get("content-disposition", "")
        filename = disposition.split('filename="')[-1].rstrip('"') if "filename=" in disposition else f"{doc_id}.txt"
        return response.content, filename, response.headers.get("content-type", "application/octet-stream")

    # directory
    def directory(self, query: str = "", department: str = "") -> list[dict]:
        return self._json("GET", "/api/portal/directory", params={"q": query, "department": department})

    def departments(self) -> list[str]:
        return self._json("GET", "/api/portal/directory/departments")

    def synthetic_events(self, limit: int = 20) -> list[dict]:
        return self._json("GET", "/api/events", params={"synthetic": "true", "limit": limit})["items"]

    # generic helpers used by the SOC dashboard
    def get(self, path: str, **params):
        return self._json("GET", path, params={k: v for k, v in params.items() if v not in (None, "")})

    def post(self, path: str, body: dict | None = None):
        return self._json("POST", path, json=body or {})

    def patch(self, path: str, body: dict):
        return self._json("PATCH", path, json=body)

    def download(self, path: str, **params) -> tuple[bytes, str, str]:
        response = self._request("GET", path, params=params)
        disposition = response.headers.get("content-disposition", "")
        filename = disposition.split('filename="')[-1].rstrip('"') if "filename=" in disposition else "report"
        return response.content, filename, response.headers.get("content-type", "application/octet-stream")


def _detail(response: requests.Response) -> str:
    try:
        detail = response.json().get("detail")
    except ValueError:
        detail = None
    if isinstance(detail, list):  # validation errors
        return "; ".join(str(item.get("msg", item)) for item in detail)
    return str(detail or f"Request failed ({response.status_code})")
