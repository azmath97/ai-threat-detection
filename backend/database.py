"""Database engine, sessions and connection settings.

One configured store (`DATABASE_URL`) is shared by every part of the system. The Streamlit dashboards never open it: they
call the backend, and the backend is the only process that reads or writes the database.

* SQLite (local development): file database in WAL mode with a busy timeout, so one writer and many readers can work at
  the same time. It is a single-host, single-writer store. See the README for its limits.
* PostgreSQL (shared / deployed): pooled connections with `pool_pre_ping`, so a database restart is survived. Use it for
  anything that must persist across redeploys or run more than one backend process.
"""
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import DateTime, create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.types import TypeDecorator

from backend.config import get_settings, redact_url


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """Stores naive UTC in the database and always returns timezone-aware UTC datetimes."""

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


_settings = get_settings()
_url = make_url(_settings.database_url)
IS_SQLITE = _url.drivername.startswith("sqlite")
IS_POSTGRES = _url.drivername.startswith("postgresql")
if IS_SQLITE and _url.database and _url.database != ":memory:":
    Path(_url.database).parent.mkdir(parents=True, exist_ok=True)


def _engine_options() -> dict:
    s = get_settings()
    options: dict = {"pool_pre_ping": True, "pool_recycle": s.db_pool_recycle_seconds}
    if IS_SQLITE:
        options["connect_args"] = {"check_same_thread": False, "timeout": s.db_busy_timeout_seconds}
    else:
        options.update(pool_size=s.db_pool_size, max_overflow=s.db_max_overflow, pool_timeout=s.db_pool_timeout_seconds)
        if IS_POSTGRES:
            options["connect_args"] = {"connect_timeout": 10, "application_name": "westbridge-api",
                                       "options": "-c statement_timeout=60000"}
    return options


engine = create_engine(_url, **_engine_options())


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_connection, _record):
    """WAL lets readers and the single writer overlap; the busy timeout makes writers queue instead of failing."""
    if IS_SQLITE:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")          # safe with WAL against application crashes; see README
        cursor.execute(f"PRAGMA busy_timeout={int(get_settings().db_busy_timeout_seconds) * 1000}")
        cursor.execute("PRAGMA wal_autocheckpoint=1000")
        cursor.execute("PRAGMA journal_size_limit=67108864")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=True, expire_on_commit=False)


def init_db() -> None:
    """Create or upgrade the schema to the current version (see backend/migrations.py)."""
    from backend import migrations

    migrations.upgrade(engine)
    _backfill_employee_codes()


def _add_missing_columns(conn) -> None:
    """Add columns that databases created by earlier versions do not have yet (the version-1 baseline)."""
    from sqlalchemy import inspect

    inspector = inspect(conn)
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            ddl = f"ALTER TABLE {table.name} ADD COLUMN {column.name} {column.type.compile(conn.dialect)}"
            if column.server_default is not None:
                ddl += f" DEFAULT '{column.server_default.arg}'"
            conn.exec_driver_sql(ddl)


def _backfill_employee_codes() -> None:
    from backend.models import Employee, employee_code_for

    with SessionLocal() as db:
        missing = db.query(Employee).filter(Employee.employee_code.is_(None)).all()
        for employee in missing:
            employee.employee_code = employee_code_for(employee.id, employee.role)
        if missing:
            db.commit()


def check_database() -> bool:
    """True when the database answers a trivial query (used by the health check)."""
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True


def database_info() -> dict:
    """What the backend is connected to, safe to show to an administrator (no password, no file path)."""
    info = {"dialect": engine.dialect.name, "driver": engine.dialect.driver,
            "url": redact_url(_url.render_as_string(hide_password=False)), "persistent_shared_store": not IS_SQLITE}
    if IS_SQLITE:
        info["url"] = f"sqlite:///{Path(_url.database).name}" if _url.database else "sqlite://"
        info["note"] = "Single-host, single-writer file database for local development; not a production-scale store."
        with engine.connect() as conn:
            info["journal_mode"] = conn.execute(text("PRAGMA journal_mode")).scalar()
            info["busy_timeout_ms"] = conn.execute(text("PRAGMA busy_timeout")).scalar()
    else:
        info["pool_size"] = getattr(engine.pool, "size", lambda: None)()
    return info


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
