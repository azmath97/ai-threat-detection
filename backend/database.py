from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, create_engine, event, inspect
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.types import TypeDecorator

from backend.config import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Stores naive UTC in SQLite and always returns timezone-aware UTC datetimes."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        return None if value is None else value.replace(tzinfo=timezone.utc)


class Base(DeclarativeBase):
    pass


_url = make_url(get_settings().database_url)
_is_sqlite = _url.drivername.startswith("sqlite")
if _is_sqlite and _url.database and _url.database != ":memory:":
    Path(_url.database).parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(_url, connect_args={"check_same_thread": False} if _is_sqlite else {})


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_connection, _record):
    if _is_sqlite:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=True, expire_on_commit=False)


def init_db() -> None:
    from backend import models  # noqa: F401  (register tables)

    Base.metadata.create_all(bind=engine)
    _add_missing_columns()
    _backfill_employee_codes()


def _add_missing_columns() -> None:
    """Lightweight in-place upgrade so databases created by earlier versions keep working."""
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            existing = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                ddl = f"ALTER TABLE {table.name} ADD COLUMN {column.name} {column.type.compile(engine.dialect)}"
                if column.server_default is not None:
                    ddl += f" DEFAULT {column.server_default.arg}"
                conn.exec_driver_sql(ddl)


def _backfill_employee_codes() -> None:
    from backend.models import Employee, employee_code_for

    with SessionLocal() as db:
        missing = db.query(Employee).filter(Employee.employee_code.is_(None)).all()
        for employee in missing:
            employee.employee_code = employee_code_for(employee.id, employee.role)
        if missing:
            db.commit()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
