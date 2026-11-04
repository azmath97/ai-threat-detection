"""Synthetic demo data: 10 employees + 1 security administrator and ~2 weeks of normal activity.

Run standalone to (re)create the database:  python -m data.seed_data --reset
"""
import argparse
import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend import migrations
from backend.config import get_settings
from backend.database import SessionLocal, engine, init_db, utcnow
from backend.event_service import record_event, write_audit
from backend.models import AccessPermission, Employee, EmployeeSession, employee_code_for
from backend.security import hash_password, hash_token
from data.demo_accounts import DEMO_USERNAMES, load_passwords

HISTORY_DAYS = 14

# username, full name, department, job role, role, known IPs, {resource: level}
EMPLOYEES = [
    ("alice.morgan", "Alice Morgan", "Finance", "Financial Analyst", "employee", ["10.20.1.11", "10.20.1.12"],
     {"financial-reports": "write", "customer-accounts": "read", "internal-wiki": "read"}),
    ("bob.chen", "Bob Chen", "Finance", "Payroll Specialist", "employee", ["10.20.1.21"],
     {"payroll-records": "write", "financial-reports": "read", "internal-wiki": "read"}),
    ("carol.diaz", "Carol Diaz", "HR", "HR Manager", "employee", ["10.20.2.31", "10.20.2.32"],
     {"hr-records": "write", "payroll-records": "read", "internal-wiki": "read"}),
    ("david.kumar", "David Kumar", "IT", "Systems Administrator", "employee", ["10.20.3.41"],
     {"it-admin-console": "write", "source-code-repo": "read", "internal-wiki": "write"}),
    ("emma.wilson", "Emma Wilson", "Trading", "Risk Analyst", "employee", ["10.20.4.51"],
     {"trading-reports": "write", "financial-reports": "read", "internal-wiki": "read"}),
    ("frank.osei", "Frank Osei", "Customer Service", "Account Manager", "employee", ["10.20.5.61", "10.20.5.62"],
     {"customer-accounts": "write", "internal-wiki": "read"}),
    ("grace.lee", "Grace Lee", "Compliance", "Compliance Officer", "employee", ["10.20.6.71"],
     {"audit-reports": "write", "financial-reports": "read", "customer-accounts": "read", "internal-wiki": "read"}),
    ("henry.novak", "Henry Novak", "Engineering", "Software Engineer", "employee", ["10.20.7.81"],
     {"source-code-repo": "write", "internal-wiki": "write"}),
    ("isla.murphy", "Isla Murphy", "Lending", "Loan Officer", "employee", ["10.20.8.91"],
     {"loan-applications": "write", "customer-accounts": "read", "internal-wiki": "read"}),
    ("jack.silva", "Jack Silva", "Marketing", "Marketing Coordinator", "employee", ["10.20.9.101"],
     {"marketing-assets": "write", "internal-wiki": "read"}),
    ("soc.admin", "Sam Okafor", "Security", "SOC Analyst", "security_admin", ["10.20.10.5", "127.0.0.1", "::1"],
     {"audit-reports": "read", "internal-wiki": "read"}),
]

# A few employees occasionally work from home / travel: (username -> unfamiliar IP)
TRAVEL_IPS = {"bob.chen": "82.45.113.20", "emma.wilson": "92.118.30.7", "isla.murphy": "203.0.113.58"}
DEVICES = [
    "Windows 11 / Edge 130 (corporate laptop)",
    "Windows 10 / Chrome 129 (corporate desktop)",
    "macOS 14 / Safari 17 (corporate laptop)",
]


def _local_to_utc(day: datetime, hour: float) -> datetime:
    tz = get_settings().tz
    local = day.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=tz) + timedelta(hours=hour)
    return local.astimezone(timezone.utc)


def _seed_history(db: Session, employee: Employee, perms: dict[str, str], rng: random.Random) -> None:
    today = utcnow().astimezone(get_settings().tz)
    device = DEVICES[employee.id % len(DEVICES)]
    resources = list(perms)
    travel_day = rng.randint(2, HISTORY_DAYS - 1) if employee.username in TRAVEL_IPS else None
    typo_day = rng.randint(2, HISTORY_DAYS - 1) if employee.role == "employee" else None

    for days_ago in range(HISTORY_DAYS, 0, -1):
        day = today - timedelta(days=days_ago)
        if day.weekday() >= 5:
            continue
        ip = TRAVEL_IPS[employee.username] if days_ago == travel_day else rng.choice(employee.known_ips)
        start = 8.5 + rng.uniform(-0.6, 0.6)
        login_at = _local_to_utc(day, start)
        logout_at = _local_to_utc(day, 17.0 + rng.uniform(-0.6, 0.8))

        if days_ago == typo_day:
            record_event(db, employee, "login_failed", source_ip=ip, outcome="failure", details={"reason": "bad_password"},
                         device_info=device, occurred_at=login_at - timedelta(minutes=1), evaluate_alerts=False, commit=False)

        session = EmployeeSession(
            employee_id=employee.id, token_hash=hash_token(f"seed-{employee.id}-{days_ago}-{rng.random()}"),
            ip_address=ip, device_info=device, created_at=login_at, expires_at=logout_at, revoked_at=logout_at,
        )
        db.add(session)
        db.flush()
        record_event(db, employee, "login", source_ip=ip, session=session, occurred_at=login_at,
                     evaluate_alerts=False, commit=False)

        moment = login_at
        for _ in range(rng.randint(3, 6) if days_ago != travel_day else 1):
            moment += timedelta(minutes=rng.randint(20, 90))
            if moment >= logout_at:
                break
            resource = rng.choice(resources)
            action = rng.choices(["view", "download"], weights=[8, 2])[0]
            event_type = "resource_access" if action == "view" else "file_download"
            count = rng.randint(1, 60) if action == "download" else rng.randint(1, 20)
            record_event(
                db, employee, event_type, source_ip=ip, resource=resource, session=session, occurred_at=moment,
                details={"action": action}, device_info=device, records_accessed=count,
                records_downloaded=count if action == "download" else 0,
                evaluate_alerts=False, commit=False,
            )
        record_event(db, employee, "logout", source_ip=ip, session=session, occurred_at=logout_at,
                     evaluate_alerts=False, commit=False)


def seed_database(db: Session, reset: bool = False) -> bool:
    """Create the synthetic dataset. Returns False if data already exists (and reset is False).

    Safe when two backend processes start together: the second one's inserts violate the unique usernames, it rolls back
    and reports that the data already exists."""
    if reset:
        migrations.drop_everything(engine)
        init_db()
    if db.scalar(select(Employee.id).limit(1)) is not None:
        return False
    try:
        return _seed(db)
    except IntegrityError:
        db.rollback()
        return False


def _seed(db: Session) -> bool:
    rng = random.Random(20260101)
    passwords = load_passwords()

    created: list[tuple[Employee, dict[str, str]]] = []
    for username, full_name, department, job_role, role, ips, perms in EMPLOYEES:
        employee = Employee(
            username=username, full_name=full_name, email=f"{username}@westbridgebank.test",
            department=department, job_role=job_role, role=role, status="active",
            password_hash=hash_password(passwords[username]),
            known_ips=ips, created_at=utcnow() - timedelta(days=HISTORY_DAYS + 30),
        )
        employee.permissions = [AccessPermission(resource=r, access_level=lvl) for r, lvl in perms.items()]
        db.add(employee)
        created.append((employee, perms))
    db.flush()
    for employee, _ in created:
        employee.employee_code = employee_code_for(employee.id, employee.role)
    db.flush()

    for employee, perms in created:
        _seed_history(db, employee, perms, rng)
    write_audit(db, "database_seeded", details={"employees": len(created), "history_days": HISTORY_DAYS})
    db.commit()
    return True


def sync_demo_passwords(db: Session) -> int:
    """Make the stored hashes of the demo accounts match the current credential source.

    This rotates away any password an earlier version of the project published (an existing database keeps its old hashes
    until now) and applies a password changed in the secret manager. Only usernames in DEMO_USERNAMES are touched, and only
    hashes that no longer verify. Plaintext is never logged; the audit entry records the count only."""
    from backend.security import verify_password

    passwords, changed = load_passwords(), 0
    for employee in db.scalars(select(Employee).where(Employee.username.in_(DEMO_USERNAMES), Employee.is_synthetic.is_(False))):
        if not verify_password(passwords[employee.username], employee.password_hash):
            employee.password_hash = hash_password(passwords[employee.username])
            changed += 1
    if changed:
        write_audit(db, "demo_credentials_synced", details={"accounts_updated": changed})
        db.commit()
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the synthetic insider-threat database")
    parser.add_argument("--reset", action="store_true", help="drop all tables and re-seed")
    args = parser.parse_args()
    init_db()
    with SessionLocal() as db:
        done = seed_database(db, reset=args.reset)
    print("Database seeded." if done else "Database already contains data (use --reset to rebuild).")


if __name__ == "__main__":
    main()
