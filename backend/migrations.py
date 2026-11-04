"""Versioned schema migrations for SQLite and PostgreSQL.

`upgrade(engine)` brings any database to the current schema version and records what it applied in `schema_migrations`.

* A new, empty database is created straight from the models (the head schema) and stamped with every version.
* A database created by an earlier version (no `schema_migrations` table) is treated as version 1, then upgraded.
* A versioned database applies only the migrations it is missing. A database newer than this code is refused.

The whole upgrade runs in one transaction under a lock (`BEGIN IMMEDIATE` on SQLite, an advisory lock on PostgreSQL), so
two processes starting at the same moment cannot both migrate, and a failure leaves the database unchanged.

Migration 2 adds the indexes, the event de-duplication key and the CHECK / uniqueness constraints that the models declare.
SQLite cannot add constraints to an existing table, so affected tables are rebuilt (create new, copy rows, drop old,
rename); PostgreSQL uses ALTER TABLE. Rows that would break a new constraint are repaired first and the repair is written
to the audit log; values that cannot be repaired stop the migration with a message naming the table and constraint.
"""
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, inspect, insert, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.schema import AddConstraint, CheckConstraint, CreateTable, ForeignKeyConstraint

from backend import database
from backend.database import Base

log = logging.getLogger("insider_threat.migrations")

_meta = MetaData()
schema_migrations = Table(
    "schema_migrations", _meta,
    Column("version", Integer, primary_key=True, autoincrement=False),
    Column("name", String(160), nullable=False),
    Column("applied_at", DateTime, nullable=False),
)
ADVISORY_LOCK_KEY = 7_342_001


class MigrationError(RuntimeError):
    """A migration could not be applied; the database was left unchanged."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[Connection], None]


# ----------------------------------------------------------------------------------------------------- helpers
def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _app_tables(conn: Connection) -> set[str]:
    return set(inspect(conn).get_table_names()) & {t.name for t in Base.metadata.sorted_tables}


def _index_names(conn: Connection, table: str) -> set[str]:
    insp = inspect(conn)
    names = {i["name"] for i in insp.get_indexes(table)}
    names |= {u["name"] for u in insp.get_unique_constraints(table) if u.get("name")}
    return names


def _create_missing_indexes(conn: Connection) -> list[str]:
    created = []
    for table in Base.metadata.sorted_tables:
        if not inspect(conn).has_table(table.name):
            continue
        present = _index_names(conn, table.name)
        for index in table.indexes:
            if index.name not in present:
                index.create(conn)
                created.append(index.name)
    return created


def _count(conn: Connection, sql: str, **params) -> int:
    return conn.execute(text(sql), params).rowcount or 0


# ------------------------------------------------------------------------------------------- migration 1: baseline
def _v1_baseline(conn: Connection) -> None:
    """Tables and columns as they existed before versioning (also repairs a database missing newer tables)."""
    _rename_legacy_columns(conn)
    Base.metadata.create_all(conn, checkfirst=True)
    database._add_missing_columns(conn)


# Columns whose old names called a heuristic score a "confidence". (table, old name, new name, multiplier for old values)
RENAMED_COLUMNS = (
    ("security_alerts", "attack_confidence", "peak_risk_score", 1.0),
    ("attack_investigations", "confidence", "risk_score_exact", 100.0),     # was stored as a 0-1 fraction
)


def _rename_legacy_columns(conn: Connection) -> list[str]:
    """Rename the old score columns (idempotent). Run first in every step that could meet an old database, so a table
    rebuilt or extended later never leaves the old values behind."""
    done = []
    insp = inspect(conn)
    for table, old, new, factor in RENAMED_COLUMNS:
        if not insp.has_table(table):
            continue
        columns = {c["name"] for c in insp.get_columns(table)}
        if old in columns and new not in columns:
            conn.exec_driver_sql(f"ALTER TABLE {table} RENAME COLUMN {old} TO {new}")
            if factor != 1.0:
                conn.exec_driver_sql(f"UPDATE {table} SET {new} = {new} * {factor}")
            done.append(f"{table}.{old}->{new}")
    return done


# ---------------------------------------------------------------------- migration 2: indexes, dedupe key, constraints
def _v2_repair_rows(conn: Connection) -> dict[str, int]:
    """Make existing rows satisfy the new uniqueness rules. Nothing is deleted; each repair is reported."""
    now, yes, no = _now(), True, False
    repaired = {
        "duplicate_request_ids_cleared": _count(conn, (
            "UPDATE security_events SET request_id = NULL WHERE request_id IS NOT NULL AND id NOT IN "
            "(SELECT MIN(id) FROM security_events WHERE request_id IS NOT NULL GROUP BY employee_id, request_id)")),
        "extra_open_alerts_resolved": _count(conn, (
            "UPDATE security_alerts SET status = 'resolved', updated_at = :now WHERE status IN ('open', 'investigating') AND id NOT IN "
            "(SELECT MAX(id) FROM security_alerts WHERE status IN ('open', 'investigating') GROUP BY employee_id)"), now=now),
        "extra_active_investigations_resolved": _count(conn, (
            "UPDATE attack_investigations SET status = 'resolved', closed_at = :now, updated_at = :now "
            "WHERE status IN ('open', 'contained') AND id NOT IN "
            "(SELECT MAX(id) FROM attack_investigations WHERE status IN ('open', 'contained') GROUP BY employee_id)"), now=now),
        "extra_active_controls_released": _count(conn, (
            "UPDATE response_controls SET active = :no, released_at = :now WHERE active = :yes AND id NOT IN "
            "(SELECT MAX(id) FROM response_controls WHERE active = :yes GROUP BY kind, value)"), now=now, yes=yes, no=no),
        "duplicate_containment_keys_cleared": _count(conn, (
            "UPDATE containment_actions SET idempotency_key = NULL WHERE idempotency_key IS NOT NULL AND id NOT IN "
            "(SELECT MIN(id) FROM containment_actions WHERE idempotency_key IS NOT NULL GROUP BY idempotency_key)")),
    }
    repaired = {k: v for k, v in repaired.items() if v}
    if repaired:
        audit = Base.metadata.tables["audit_logs"]
        conn.execute(insert(audit).values(action="schema_migration_repair", target_type="database", details=repaired, timestamp=now))
        log.warning("Migration 2 repaired existing rows: %s", repaired)
    return repaired


def _v2_check_existing_rows(conn: Connection) -> None:
    """Refuse, before changing anything, if existing rows break a CHECK constraint (a CHECK with NULL passes)."""
    problems = []
    for table in Base.metadata.sorted_tables:
        if not inspect(conn).has_table(table.name):
            continue
        for constraint in table.constraints:
            if isinstance(constraint, CheckConstraint):
                sql = str(constraint.sqltext)
                bad = conn.execute(text(f"SELECT COUNT(*) FROM {table.name} WHERE NOT ({sql})")).scalar() or 0
                if bad:
                    problems.append(f"{table.name}: {bad} row(s) violate {constraint.name} ({sql})")
    if problems:
        raise MigrationError("Existing data breaks the new constraints; fix these rows and retry: " + "; ".join(problems))


_SQLITE_CK = re.compile(r"CONSTRAINT\s+(\w+)\s+CHECK", re.IGNORECASE)


def _sqlite_needs_rebuild(conn: Connection, table: Table) -> bool:
    sql = conn.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:n"), {"n": table.name}).scalar() or ""
    have_checks = set(_SQLITE_CK.findall(sql))
    want_checks = {c.name for c in table.constraints if isinstance(c, CheckConstraint)}
    if want_checks - have_checks:
        return True
    existing_fks = {(tuple(f["constrained_columns"]), f["referred_table"]) for f in inspect(conn).get_foreign_keys(table.name)}
    wanted_fks = {(tuple(c.name for c in fk.columns), fk.referred_table.name)
                  for fk in table.constraints if isinstance(fk, ForeignKeyConstraint)}
    return wanted_fks != existing_fks


def _sqlite_rebuild(conn: Connection, table: Table) -> None:
    """Create the table from the model under a temporary name, copy the rows, drop the old table, rename, re-index."""
    temp = f"_new_{table.name}"
    ddl = str(CreateTable(table).compile(dialect=conn.dialect))
    ddl, n = re.subn(rf"CREATE TABLE {re.escape(table.name)}\s*\(", f"CREATE TABLE {temp} (", ddl, count=1)
    if n != 1:
        raise MigrationError(f"could not prepare the rebuild of {table.name}")
    conn.exec_driver_sql(ddl)
    old_columns = {c["name"] for c in inspect(conn).get_columns(table.name)}
    columns = ", ".join(c.name for c in table.columns if c.name in old_columns)
    conn.exec_driver_sql(f"INSERT INTO {temp} ({columns}) SELECT {columns} FROM {table.name}")
    conn.exec_driver_sql(f"DROP TABLE {table.name}")
    conn.exec_driver_sql(f"ALTER TABLE {temp} RENAME TO {table.name}")
    for index in table.indexes:
        index.create(conn)


def _v2_sqlite(conn: Connection) -> None:
    rebuilt = []
    for table in Base.metadata.sorted_tables:
        if inspect(conn).has_table(table.name) and _sqlite_needs_rebuild(conn, table):
            _sqlite_rebuild(conn, table)
            rebuilt.append(table.name)
    violations = conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise MigrationError(f"foreign key violations after the rebuild: {violations[:3]}")
    if rebuilt:
        log.info("Migration 2 rebuilt tables: %s", ", ".join(rebuilt))


def _v2_alter(conn: Connection) -> None:
    """PostgreSQL (and other databases that support ALTER TABLE ... ADD CONSTRAINT)."""
    for table in Base.metadata.sorted_tables:
        insp = inspect(conn)
        if not insp.has_table(table.name):
            continue
        have_checks = {c["name"] for c in insp.get_check_constraints(table.name)}
        for constraint in table.constraints:
            if isinstance(constraint, CheckConstraint) and constraint.name not in have_checks:
                conn.execute(AddConstraint(constraint))
        have_fks = {(tuple(f["constrained_columns"]), f["referred_table"]) for f in insp.get_foreign_keys(table.name)}
        for fk in table.constraints:
            if isinstance(fk, ForeignKeyConstraint) and (tuple(c.name for c in fk.columns), fk.referred_table.name) not in have_fks:
                conn.execute(AddConstraint(fk))


OBSOLETE_INDEXES = ("ix_security_events_request_id", "ix_security_alerts_employee_id", "ix_attack_investigations_employee_id",
                    "ix_containment_actions_employee_id")


def _v2_indexes_and_constraints(conn: Connection) -> None:
    _rename_legacy_columns(conn)
    _v2_repair_rows(conn)
    _v2_check_existing_rows(conn)
    if conn.dialect.name == "sqlite":
        _v2_sqlite(conn)
    else:
        _v2_alter(conn)
    _create_missing_indexes(conn)
    for name in OBSOLETE_INDEXES:                      # superseded by composite or partial-unique indexes
        conn.exec_driver_sql(f"DROP INDEX IF EXISTS {name}")


def _v3_score_columns(conn: Connection) -> None:
    """Score terminology: rename the old "confidence" columns and add impact severity, evidence strength and the
    stored score basis. Existing rows keep their scores; the new columns are empty (shown as "not assessed")."""
    renamed = _rename_legacy_columns(conn)
    database._add_missing_columns(conn)
    if renamed:
        log.info("Migration 3 renamed score columns: %s", ", ".join(renamed))


MIGRATIONS = [
    Migration(1, "baseline tables and columns", _v1_baseline),
    Migration(2, "indexes, event de-duplication key, check and uniqueness constraints", _v2_indexes_and_constraints),
    Migration(3, "heuristic risk score columns, impact severity and evidence strength", _v3_score_columns),
]
CURRENT_VERSION = MIGRATIONS[-1].version


# ------------------------------------------------------------------------------------------------------- runner
def _lock(conn: Connection) -> None:
    if conn.dialect.name == "sqlite":
        conn.exec_driver_sql("BEGIN IMMEDIATE")
    elif conn.dialect.name == "postgresql":
        conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": ADVISORY_LOCK_KEY})


def applied_versions(conn: Connection) -> set[int]:
    if not inspect(conn).has_table(schema_migrations.name):
        return set()
    return {row[0] for row in conn.execute(select(schema_migrations.c.version))}


def _stamp(conn: Connection, migration: Migration) -> None:
    conn.execute(insert(schema_migrations).values(version=migration.version, name=migration.name, applied_at=_now()))


def upgrade(engine: Engine) -> list[int]:
    """Bring the database to CURRENT_VERSION. Returns the versions applied by this call (empty if already current)."""
    from backend import models  # noqa: F401  (registers every table on Base.metadata)

    sqlite = engine.dialect.name == "sqlite"
    conn = engine.connect()
    done: list[int] = []
    try:
        if sqlite:
            conn.exec_driver_sql("PRAGMA foreign_keys=OFF")      # required while tables are rebuilt; a no-op inside a transaction
        _lock(conn)
        versions = applied_versions(conn)
        if versions and max(versions) > CURRENT_VERSION:
            raise MigrationError(f"the database is at schema version {max(versions)}, newer than this application "
                                 f"({CURRENT_VERSION}); upgrade the application instead of running it against this database")
        if not versions:
            if not _app_tables(conn):                              # new database: build the head schema directly
                Base.metadata.create_all(conn)
                _meta.create_all(conn)
                for migration in MIGRATIONS:
                    _stamp(conn, migration)
                done = [m.version for m in MIGRATIONS]
                conn.commit()
                log.info("Created a new database at schema version %s", CURRENT_VERSION)
                return done
            _meta.create_all(conn)                                 # unversioned database from an earlier release
        else:
            Base.metadata.create_all(conn, checkfirst=True)        # heal a missing table without touching the rest
        for migration in MIGRATIONS:
            if migration.version in versions:
                continue
            log.info("Applying migration %s: %s", migration.version, migration.name)
            migration.apply(conn)
            _stamp(conn, migration)
            done.append(migration.version)
        conn.commit()
        return done
    except BaseException:
        conn.rollback()
        raise
    finally:
        if sqlite:
            conn.exec_driver_sql("PRAGMA foreign_keys=ON")
        conn.close()


def current_version(engine: Engine) -> int:
    with engine.connect() as conn:
        versions = applied_versions(conn)
    return max(versions) if versions else 0


def drop_everything(engine: Engine) -> None:
    """Remove every table, including the version table (used by `python -m data.seed_data --reset`)."""
    with engine.begin() as conn:
        Base.metadata.drop_all(conn)
        _meta.drop_all(conn)
