"""Database maintenance: upgrade a database to the current schema, inspect it, or copy it into another database.

The usual use is moving the local SQLite demo data into a managed PostgreSQL database:

    python -m backend.db_tools copy --source sqlite:///./data/insider_threat.db --target postgresql://USER:PASSWORD@HOST/DBNAME

URLs may also come from SOURCE_DATABASE_URL / TARGET_DATABASE_URL, which keeps the password out of your shell history.

The copy never writes to the source. It refuses to run unless the source is at the current schema version (run `upgrade`
on a copy of an old file first), refuses a target that already holds rows, and writes the whole target in one transaction,
so a failure leaves the target empty rather than half-filled. Afterwards it resets PostgreSQL id sequences and compares row
counts table by table.
"""
import argparse
import os
import sys
from dataclasses import dataclass

from sqlalchemy import create_engine, event, func, select, text, update
from sqlalchemy.engine import Engine

from backend import migrations
from backend.config import normalize_database_url, redact_url
from backend.database import Base


class CopyError(RuntimeError):
    pass


@dataclass
class CopyReport:
    rows: dict[str, int]
    source_version: int
    target_version: int


def make_engine(url: str) -> Engine:
    engine = create_engine(normalize_database_url(url), pool_pre_ping=True)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()
    return engine


def count_rows(engine: Engine) -> dict[str, int]:
    with engine.connect() as conn:
        return {t.name: conn.scalar(select(func.count()).select_from(t)) or 0 for t in Base.metadata.sorted_tables}


def _self_references(table) -> list[str]:
    return [c.name for c in table.columns if any(fk.column.table is table for fk in c.foreign_keys)]


def _reset_sequences(conn) -> None:
    for table in Base.metadata.sorted_tables:
        pk = [c.name for c in table.primary_key.columns]
        if pk != ["id"]:
            continue
        conn.execute(text(
            f"SELECT setval(pg_get_serial_sequence('{table.name}', 'id'), COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) "
            f"FROM {table.name}"))


def copy_database(source_url: str, target_url: str, batch: int = 1000) -> CopyReport:
    source, target = make_engine(source_url), make_engine(target_url)
    try:
        if source.url == target.url:
            raise CopyError("source and target are the same database")
        source_version = migrations.current_version(source)
        if source_version != migrations.CURRENT_VERSION:
            raise CopyError(
                f"the source is at schema version {source_version}, this application expects {migrations.CURRENT_VERSION}. "
                "Upgrade a copy of it first: python -m backend.db_tools upgrade --url <copy of the source>")
        migrations.upgrade(target)
        non_empty = {name: n for name, n in count_rows(target).items() if n}
        if non_empty:
            raise CopyError(f"the target already holds rows ({', '.join(f'{k}={v}' for k, v in non_empty.items())}); "
                            "copy into an empty database so existing data is never overwritten")
        expected = count_rows(source)

        with source.connect() as src, target.begin() as dst:
            for table in Base.metadata.sorted_tables:
                self_refs = _self_references(table)
                pk = list(table.primary_key.columns)
                last = None
                deferred: list[dict] = []
                while True:
                    query = select(table).order_by(*pk).limit(batch)
                    if last is not None:
                        query = query.where(pk[0] > last)
                    rows = [dict(r._mapping) for r in src.execute(query)]
                    if not rows:
                        break
                    last = rows[-1][pk[0].name]
                    if self_refs:       # insert without the self-references, then set them once every row exists
                        for row in rows:
                            deferred.append({"_pk": row[pk[0].name], **{c: row[c] for c in self_refs}})
                            for c in self_refs:
                                row[c] = None
                    dst.execute(table.insert(), rows)
                for item in deferred:
                    values = {c: item[c] for c in self_refs if item[c] is not None}
                    if values:
                        dst.execute(update(table).where(pk[0] == item["_pk"]).values(**values))
            if target.dialect.name == "postgresql":
                _reset_sequences(dst)

        copied = count_rows(target)
        mismatch = {t: (expected[t], copied[t]) for t in expected if expected[t] != copied[t]}
        if mismatch:
            raise CopyError(f"row counts differ after the copy (source, target): {mismatch}")
        return CopyReport(rows=copied, source_version=source_version, target_version=migrations.current_version(target))
    finally:
        source.dispose()
        target.dispose()


def _url_arg(value: str | None, env_name: str, label: str) -> str:
    url = value or os.getenv(env_name, "")
    if not url:
        raise SystemExit(f"{label} database URL required: pass it as an option or set {env_name}")
    return url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend.db_tools", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    cp = sub.add_parser("copy", help="copy every table from one database into an empty one")
    cp.add_argument("--source")
    cp.add_argument("--target")
    cp.add_argument("--batch", type=int, default=1000, help="rows per insert (default 1000)")
    up = sub.add_parser("upgrade", help="apply pending schema migrations to a database")
    up.add_argument("--url")
    info = sub.add_parser("info", help="show schema version and row counts")
    info.add_argument("--url")
    args = parser.parse_args(argv)

    try:
        if args.command == "copy":
            source = _url_arg(args.source, "SOURCE_DATABASE_URL", "source")
            target = _url_arg(args.target, "TARGET_DATABASE_URL", "target")
            report = copy_database(source, target, max(1, args.batch))
            print(f"Copied {redact_url(source)} -> {redact_url(target)} (schema version {report.target_version})")
            for name, n in report.rows.items():
                print(f"  {name}: {n}")
        else:
            url = _url_arg(args.url, "DATABASE_URL", "")
            engine = make_engine(url)
            try:
                if args.command == "upgrade":
                    applied = migrations.upgrade(engine)
                    print(f"{redact_url(url)}: applied migrations {applied or 'none (already current)'}")
                else:
                    print(f"{redact_url(url)}: schema version {migrations.current_version(engine)} "
                          f"(application expects {migrations.CURRENT_VERSION})")
                    for name, n in count_rows(engine).items():
                        print(f"  {name}: {n}")
            finally:
                engine.dispose()
    except (CopyError, migrations.MigrationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
