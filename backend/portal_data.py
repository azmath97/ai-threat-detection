"""Deterministic synthetic content for the employee portal (no real personal or banking data)."""
import csv
import io
import random
from datetime import date, datetime, timezone

from backend.models import Employee

ORG_NAME = "Arden Bank"
LOCATIONS = ["Head Office - London", "Operations Centre - Manchester", "Branch Support - Edinburgh"]
RATINGS = ["Exceeds expectations", "Meets expectations", "Meets expectations", "Developing"]
MANAGERS = ["Priya Raman", "Thomas Becker", "Naomi Clarke", "Luis Ortega"]

DOCUMENTS = [
    {"id": "DOC-001", "title": "Code of Conduct", "resource": "internal-wiki", "category": "Policy", "format": "txt"},
    {"id": "DOC-002", "title": "Information Security Policy", "resource": "internal-wiki", "category": "Policy", "format": "txt"},
    {"id": "DOC-003", "title": "Public Holiday Calendar 2026", "resource": "internal-wiki", "category": "General", "format": "csv"},
    {"id": "DOC-010", "title": "Brand Guidelines", "resource": "marketing-assets", "category": "Marketing", "format": "txt"},
    {"id": "DOC-020", "title": "Management Accounts Q3 2026", "resource": "financial-reports", "category": "Finance", "format": "csv"},
    {"id": "DOC-021", "title": "Budget Variance Summary - September", "resource": "financial-reports", "category": "Finance", "format": "csv"},
    {"id": "DOC-030", "title": "Customer Account Review Procedure", "resource": "customer-accounts", "category": "Procedure", "format": "txt"},
    {"id": "DOC-040", "title": "Daily Risk Position Report", "resource": "trading-reports", "category": "Trading", "format": "csv"},
    {"id": "DOC-050", "title": "Credit Policy Manual", "resource": "loan-applications", "category": "Lending", "format": "txt"},
    {"id": "DOC-060", "title": "Internal Audit Report FY26 Q2", "resource": "audit-reports", "category": "Compliance", "format": "txt"},
    {"id": "DOC-070", "title": "Platform Architecture Overview", "resource": "source-code-repo", "category": "Engineering", "format": "txt"},
    {"id": "DOC-080", "title": "Payroll Processing Calendar", "resource": "payroll-records", "category": "Payroll", "format": "csv"},
    {"id": "DOC-090", "title": "HR Policy Handbook", "resource": "hr-records", "category": "HR", "format": "txt"},
    {"id": "DOC-100", "title": "Privileged Access Runbook", "resource": "it-admin-console", "category": "IT", "format": "txt"},
]

_PARAGRAPHS = [
    "This document sets out the standards that apply to all staff and contractors of the organisation.",
    "Owners are responsible for reviewing the content annually and recording any exceptions in the register.",
    "Questions about the contents should be raised with the relevant department head or the service desk.",
    "Unauthorised distribution outside the organisation is prohibited and monitored under the acceptable use policy.",
]


def _rng(*parts) -> random.Random:
    return random.Random("|".join(str(p) for p in parts))


def hr_profile(employee: Employee) -> dict:
    rng = _rng("hr", employee.id)
    hired = date(2016 + rng.randint(0, 8), rng.randint(1, 12), rng.randint(1, 28))
    return {
        "hire_date": hired.isoformat(),
        "manager": rng.choice(MANAGERS),
        "location": LOCATIONS[employee.id % len(LOCATIONS)],
        "employment_type": "Permanent" if rng.random() > 0.15 else "Fixed term",
        "work_phone": f"ext. {2000 + employee.id * 7}",
        "leave_balance_days": rng.randint(4, 24),
        "performance_rating": rng.choice(RATINGS),
        "emergency_contact": f"{rng.choice(['A.', 'B.', 'C.', 'D.'])} {employee.full_name.split()[-1]} (synthetic contact)",
    }


def directory_entry(employee: Employee) -> dict:
    profile = hr_profile(employee)
    return {
        "employee_id": employee.employee_code,
        "name": employee.full_name,
        "department": employee.department,
        "job_role": employee.job_role,
        "email": employee.email,
        "phone": profile["work_phone"],
        "location": profile["location"],
    }


def recent_periods(count: int) -> list[str]:
    today = datetime.now(timezone.utc).date()
    year, month = today.year, today.month
    periods = []
    for _ in range(count):
        month -= 1
        if month == 0:
            year, month = year - 1, 12
        periods.append(f"{year}-{month:02d}")
    return periods


def payslip(employee: Employee, period: str) -> dict:
    rng = _rng("pay", employee.id, period)
    base = 2800 + (employee.id * 331) % 2600
    allowance = 150 + rng.randint(0, 120)
    bonus = rng.choice([0, 0, 0, 250])
    gross = base + allowance + bonus
    tax = round(gross * 0.20, 2)
    pension = round(base * 0.05, 2)
    insurance = 42.50
    return {
        "period": period,
        "employee_id": employee.employee_code,
        "name": employee.full_name,
        "currency": "USD",
        "earnings": {"Basic salary": base, "Allowances": allowance, "Bonus": bonus},
        "deductions": {"Income tax": tax, "Pension contribution": pension, "Health insurance": insurance},
        "gross": float(gross),
        "total_deductions": round(tax + pension + insurance, 2),
        "net": round(gross - tax - pension - insurance, 2),
    }


def payslips(employee: Employee, count: int = 6) -> list[dict]:
    return [payslip(employee, p) for p in recent_periods(count)]


def payroll_register(employees: list[Employee]) -> list[dict]:
    period = recent_periods(1)[0]
    rows = []
    for e in employees:
        slip = payslip(e, period)
        rows.append({
            "employee_id": e.employee_code, "name": e.full_name, "department": e.department, "period": period,
            "gross": slip["gross"], "deductions": slip["total_deductions"], "net": slip["net"],
        })
    return rows


def rows_to_csv(rows: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=list(rows[0].keys()) if rows else ["empty"])
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def find_document(doc_id: str) -> dict | None:
    return next((d for d in DOCUMENTS if d["id"] == doc_id), None)


def document_content(doc: dict) -> tuple[str, str, str]:
    """Returns (filename, media_type, text)."""
    rng = _rng("doc", doc["id"])
    banner = f"SYNTHETIC DOCUMENT - {ORG_NAME} - generated for demonstration only\n"
    slug = doc["title"].lower().replace(" ", "_").replace("-", "").replace("__", "_")
    if doc["format"] == "csv":
        rows = [{"line": i, "item": f"{doc['category']} item {i}", "value": round(rng.uniform(1000, 90000), 2)} for i in range(1, 9)]
        return f"{slug}.csv", "text/csv", banner.replace("\n", "") + "\n" + rows_to_csv(rows)
    body = "\n\n".join(f"{i}. {rng.choice(_PARAGRAPHS)}" for i in range(1, 6))
    return f"{slug}.txt", "text/plain", f"{banner}\n{doc['title']}\nCategory: {doc['category']}\n\n{body}\n"
