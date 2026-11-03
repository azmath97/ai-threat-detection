"""A per-machine signing secret for local development.

Production never uses this: it must be given SECRET_KEY by the environment or the platform's secret manager. For a local
run without SECRET_KEY, a random key is created once and stored in a git-ignored file, so sessions survive a restart and no
fixed default exists in the source.
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def local_secret_file() -> Path:
    return Path(os.getenv("LOCAL_SECRET_FILE") or BASE_DIR / "data" / ".local_secret")


def local_secret_key() -> str:
    path = local_secret_file()
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if len(value) >= 32:
            return value
    value = secrets.token_urlsafe(48)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return value
