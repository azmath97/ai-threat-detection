"""Validation of a user-provided CERT release directory and answer key, with actionable error messages.

    python -m ml.cert.validate --source data/external/cert/r4.2 [--answers data/external/cert/answers]
Nothing is modified: files are only read.
"""
import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from ml.cert.schema import RELEASE, SOURCES, TIMESTAMP_FORMAT, DatasetError

SAMPLE_ROWS = 2000
ANSWER_COLUMNS = ("dataset", "scenario", "details", "user", "start", "end")


@dataclass
class ValidationReport:
    root: Path
    sources_present: list[str] = field(default_factory=list)
    sources_missing: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sampled: dict[str, dict] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def raise_if_failed(self) -> "ValidationReport":
        if self.errors:
            raise DatasetError("Dataset validation failed:\n  - " + "\n  - ".join(self.errors))
        return self

    def as_dict(self) -> dict:
        return {"root": str(self.root), "ok": self.ok, "sources_present": self.sources_present,
                "sources_missing": self.sources_missing, "errors": self.errors, "warnings": self.warnings,
                "sampled": self.sampled}


def locate_release(path: str | Path) -> Path:
    """Accept either the directory holding logon.csv etc. or its parent (for example the extraction folder)."""
    root = Path(path)
    if not root.exists():
        raise DatasetError(f"Dataset path does not exist: {root}. See docs/cert-dataset.md for download instructions.")
    if not root.is_dir():
        raise DatasetError(f"Dataset path is not a directory: {root}. Extract the .tar.bz2 archive first "
                           f"(python -m ml.cert.prepare --extract <archive>).")
    if (root / "logon.csv").exists():
        return root
    for candidate in (root / RELEASE, *sorted(p for p in root.glob("*") if p.is_dir())):
        if (candidate / "logon.csv").exists():
            return candidate
    return root


def _header(path: Path) -> list[str]:
    try:
        return [str(c).strip() for c in pd.read_csv(path, nrows=0).columns]
    except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise DatasetError(f"{path.name} cannot be read as CSV: {exc}") from exc


def validate_release(path: str | Path, sample_rows: int = SAMPLE_ROWS) -> ValidationReport:
    root = locate_release(path)
    report = ValidationReport(root=root)
    for kind, spec in SOURCES.items():
        file = root / spec.filename
        if not file.exists():
            report.sources_missing.append(kind)
            message = f"{spec.filename} not found in {root}"
            (report.warnings if spec.optional_file else report.errors).append(
                message + ("" if not spec.optional_file else " - that event source will be skipped"))
            continue
        try:
            columns = _header(file)
        except DatasetError as exc:
            report.errors.append(str(exc))
            continue
        missing = [c for c in spec.required if c not in columns]
        if missing:
            report.errors.append(f"{spec.filename} is missing column(s) {missing}; found {columns}. "
                                 f"Is this release {RELEASE}? Other releases use different layouts.")
            continue
        try:
            sample = pd.read_csv(file, nrows=sample_rows, usecols=list(spec.use), dtype=str)
        except (pd.errors.ParserError, ValueError, UnicodeDecodeError) as exc:
            report.errors.append(f"{spec.filename} is malformed: {exc}")
            continue
        if sample.empty:
            report.errors.append(f"{spec.filename} has a header but no rows")
            continue
        parsed = pd.to_datetime(sample["date"], format=TIMESTAMP_FORMAT, errors="coerce")
        bad = float(parsed.isna().mean())
        if bad > 0.5:
            report.errors.append(f"{spec.filename}: {bad:.0%} of sampled timestamps do not match {TIMESTAMP_FORMAT!r} "
                                 f"(example: {sample['date'].iloc[0]!r})")
        elif bad > 0:
            report.warnings.append(f"{spec.filename}: {bad:.1%} of sampled timestamps are unparseable and will be rejected")
        duplicates = int(sample["id"].duplicated().sum())
        if duplicates:
            report.warnings.append(f"{spec.filename}: {duplicates} duplicate event id(s) in the first {len(sample)} rows; "
                                   f"duplicates are dropped during preparation")
        missing_ids = int(sample["id"].isna().sum())
        if missing_ids:
            report.warnings.append(f"{spec.filename}: {missing_ids} row(s) without an event id are rejected")
        report.sources_present.append(kind)
        report.sampled[kind] = {"columns": columns, "sample_rows": len(sample), "unparseable_timestamp_fraction": round(bad, 4)}
    return report


def validate_answers(path: str | Path) -> Path:
    """Return the directory holding insiders.csv; raise a helpful DatasetError if the answer key is unusable."""
    root = Path(path)
    if not root.exists():
        raise DatasetError(f"Answer key path does not exist: {root}. Download answers.tar.bz2 from the official release "
                           f"(see docs/cert-dataset.md) and extract it.")
    directory = root if (root / "insiders.csv").exists() else next(
        (p for p in root.glob("*") if p.is_dir() and (p / "insiders.csv").exists()), None)
    if directory is None:
        raise DatasetError(f"insiders.csv not found under {root}; extract answers.tar.bz2 and pass the extracted directory")
    columns = _header(directory / "insiders.csv")
    missing = [c for c in ANSWER_COLUMNS if c not in columns]
    if missing:
        raise DatasetError(f"insiders.csv is missing column(s) {missing}; found {columns}")
    rows = pd.read_csv(directory / "insiders.csv", dtype=str)
    if rows[rows["dataset"] == RELEASE.lstrip("r")].empty:
        raise DatasetError(f"insiders.csv has no entries for release {RELEASE}; this answer key does not cover the dataset")
    if not (directory / f"{RELEASE}-1").is_dir() and not any(directory.glob(f"{RELEASE}-*")):
        raise DatasetError(f"No per-incident observables directories ({RELEASE}-1, ...) in {directory}")
    return directory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, help="directory with logon.csv, device.csv, ...")
    parser.add_argument("--answers", help="directory with insiders.csv (extracted answers.tar.bz2)")
    args = parser.parse_args()
    try:
        report = validate_release(args.source)
        if args.answers:
            validate_answers(args.answers)
    except DatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    for line in report.warnings:
        print(f"warning: {line}")
    for line in report.errors:
        print(f"ERROR: {line}", file=sys.stderr)
    print(f"sources present: {report.sources_present or 'none'}; missing: {report.sources_missing or 'none'}")
    return 0 if report.ok else 2


if __name__ == "__main__":
    sys.exit(main())
