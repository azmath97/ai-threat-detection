"""Sign-in credentials for the seeded synthetic demo accounts.

No password is stored in source control. Passwords are random values created on this machine (or supplied by the
hosting platform's secret manager) and read from, in order:

1. the `DEMO_PASSWORDS_JSON` environment variable: a JSON object `{"alice.morgan": "...", ...}` (use a secret manager);
2. the JSON file named by `DEMO_CREDENTIALS_FILE` (default `data/demo_credentials.local.json`, git-ignored).

Outside production, if neither exists the file is generated on first use. In production nothing is generated: a
missing credential source is an error, so the application never starts with guessable accounts. The database stores only
Argon2id hashes; this module is the one place the plaintext exists, so the simulation ("stolen credentials") and the
tests can sign in as the demo accounts.
"""
import json
import os
import secrets
from pathlib import Path

from backend.models import employee_code_for

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_FILE = BASE_DIR / "data" / "demo_credentials.local.json"

# Usernames in the same order as data.seed_data.EMPLOYEES (so IDs are EMP-1001 ... EMP-1010, SEC-9011). Not secret.
DEMO_USERNAMES = ("alice.morgan", "bob.chen", "carol.diaz", "david.kumar", "emma.wilson", "frank.osei", "grace.lee",
                  "henry.novak", "isla.murphy", "jack.silva", "soc.admin")
MIN_PASSWORD_LENGTH = 12
_ROLE_OF = {name: ("security_admin" if name == "soc.admin" else "employee") for name in DEMO_USERNAMES}
_BY_CODE = {employee_code_for(i, _ROLE_OF[name]): name for i, name in enumerate(DEMO_USERNAMES, start=1)}
_cache: dict[str, str] | None = None


class CredentialsMissing(RuntimeError):
    """No demo credential source is configured and one may not be generated (production)."""


def credentials_file() -> Path:
    return Path(os.getenv("DEMO_CREDENTIALS_FILE") or DEFAULT_FILE)


def _is_production() -> bool:
    return os.getenv("APP_ENV", "development").strip().lower() == "production"


def _validate(data: object, source: str) -> dict[str, str]:
    if not isinstance(data, dict):
        raise CredentialsMissing(f"{source} must be a JSON object mapping username to password")
    missing = [u for u in DEMO_USERNAMES if u not in data]
    weak = [u for u in DEMO_USERNAMES if u in data and (not isinstance(data[u], str) or len(data[u]) < MIN_PASSWORD_LENGTH)]
    if missing or weak:
        raise CredentialsMissing(f"{source} must give every demo account a password of at least {MIN_PASSWORD_LENGTH} "
                                 f"characters (missing: {', '.join(missing) or 'none'}; too short: {', '.join(weak) or 'none'})")
    if len({data[u] for u in DEMO_USERNAMES}) != len(DEMO_USERNAMES):
        raise CredentialsMissing(f"{source}: every demo account needs its own password")
    return {u: data[u] for u in DEMO_USERNAMES}


def generate_passwords() -> dict[str, str]:
    return {u: secrets.token_urlsafe(15) for u in DEMO_USERNAMES}


def write_credentials(passwords: dict[str, str], path: Path | None = None) -> Path:
    """Write the local credentials file, readable by the current user only where the platform supports it."""
    path = path or credentials_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(passwords, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def credentials_source_available() -> bool:
    return bool(os.getenv("DEMO_PASSWORDS_JSON")) or credentials_file().exists()


def load_passwords(*, create: bool | None = None) -> dict[str, str]:
    """username -> password. `create` defaults to True outside production."""
    global _cache
    if _cache is not None:
        return _cache
    create = (not _is_production()) if create is None else create
    raw = os.getenv("DEMO_PASSWORDS_JSON")
    if raw:
        try:
            _cache = _validate(json.loads(raw), "DEMO_PASSWORDS_JSON")
        except json.JSONDecodeError as exc:
            raise CredentialsMissing("DEMO_PASSWORDS_JSON is not valid JSON") from exc
        return _cache
    path = credentials_file()
    if path.exists():
        try:
            _cache = _validate(json.loads(path.read_text(encoding="utf-8")), path.name)
        except json.JSONDecodeError as exc:
            raise CredentialsMissing(f"{path.name} is not valid JSON") from exc
        return _cache
    if not create:
        raise CredentialsMissing("No demo credentials: set DEMO_PASSWORDS_JSON (or DEMO_CREDENTIALS_FILE) from your secret "
                                 "manager, or set AUTO_SEED=false to run without the demo accounts")
    _cache = generate_passwords()
    write_credentials(_cache, path)
    return _cache


def reset_cache() -> None:
    global _cache
    _cache = None


def demo_password(identifier: str, default: str | None = None) -> str:
    """Password for an employee ID (EMP-1001) or username (alice.morgan)."""
    username = _BY_CODE.get(identifier.upper(), identifier)
    passwords = load_passwords()
    if default is not None:
        return passwords.get(username, default)
    return passwords[username]
