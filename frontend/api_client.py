"""Thin HTTP client for the FastAPI backend. The backend is the only source of identity and permissions."""
import os

import requests

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT = 20


class ApiError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class ApiClient:
    def __init__(self, token: str | None = None, device: str | None = None):
        self.token = token
        self.device = device

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.device:
            headers["X-Device-Info"] = self.device
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

    # simulation (security administrators only)
    def sim_scenarios(self) -> dict:
        return self._json("GET", "/api/simulation/scenarios")

    def sim_status(self) -> dict:
        return self._json("GET", "/api/simulation/status")

    def sim_step(self, target_employee_id: int, step: str, source_ip: str, scenario: str) -> dict:
        return self._json("POST", "/api/simulation/steps", json={
            "target_employee_id": target_employee_id, "step": step, "source_ip": source_ip, "scenario": scenario})

    def sim_run(self, target_employee_id: int, source_ip: str, scenario: str) -> dict:
        return self._json("POST", "/api/simulation/run", json={
            "target_employee_id": target_employee_id, "source_ip": source_ip, "scenario": scenario})

    def sim_reset(self) -> dict:
        return self._json("POST", "/api/simulation/reset")

    def synthetic_events(self, limit: int = 20) -> list[dict]:
        return self._json("GET", "/api/events", params={"synthetic": "true", "limit": limit})["items"]

    # generic helpers used by the SOC dashboard
    def get(self, path: str, **params):
        return self._json("GET", path, params={k: v for k, v in params.items() if v not in (None, "")})

    def post(self, path: str, body: dict | None = None):
        return self._json("POST", path, json=body or {})

    def patch(self, path: str, body: dict):
        return self._json("PATCH", path, json=body)


def _detail(response: requests.Response) -> str:
    try:
        detail = response.json().get("detail")
    except ValueError:
        detail = None
    if isinstance(detail, list):  # validation errors
        return "; ".join(str(item.get("msg", item)) for item in detail)
    return str(detail or f"Request failed ({response.status_code})")
