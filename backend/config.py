import base64
import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _str(name: str, default: str) -> str:
    return os.getenv(name, default)


def _int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str
    secret_key: str
    session_ttl_minutes: int
    display_timezone: str
    cors_origins: list[str]
    auto_seed: bool
    simulation_enabled: bool
    map_loopback_to_workstation: bool
    trusted_frontend_key: str
    app_env: str
    login_max_failures: int
    login_lockout_seconds: int
    containment_max_per_minute: int
    simulation_privileged_password: str
    argon2_time_cost: int
    argon2_memory_kib: int
    argon2_parallelism: int
    require_https: bool
    trust_forwarded_proto: bool
    max_request_bytes: int
    enable_api_docs: bool
    login_ip_max_failures: int
    login_ip_window_seconds: int
    rate_limits_enabled: bool
    rate_limit_sensitive_per_minute: int
    rate_limit_heavy_per_minute: int
    rate_limit_employee_per_minute: int
    db_busy_timeout_seconds: int
    db_pool_size: int
    db_max_overflow: int
    db_pool_timeout_seconds: int
    db_pool_recycle_seconds: int
    allow_sqlite_in_production: bool
    dashboard_window_days: int
    max_page_size: int
    correlation_window_minutes: int
    investigation_window_hours: int
    threat_suspicious_threshold: int
    threat_high_threshold: int
    threat_critical_threshold: int
    alert_min_severity: str
    baseline_days: int
    detection_rules_path: str
    ml_model_path: str
    ml_auto_train: bool
    bulk_record_threshold: int
    business_hours_start: int
    business_hours_end: int

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.display_timezone)


def normalize_database_url(url: str) -> str:
    """Accept the URL forms hosts hand out. `postgres://` and `postgresql://` become `postgresql+psycopg://` (psycopg 3)."""
    url = url.strip()
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


def redact_url(url: str) -> str:
    """The URL with any password replaced, safe to log or return."""
    return re.sub(r"(://[^:/@\s]+):[^@\s]*@", r"\1:***@", url)


@lru_cache
def get_settings() -> Settings:
    default_db = f"sqlite:///{(BASE_DIR / 'data' / 'insider_threat.db').as_posix()}"
    db_url = normalize_database_url(_str("DATABASE_URL", default_db))
    if db_url.startswith("sqlite:///./"):
        db_url = f"sqlite:///{(BASE_DIR / db_url[len('sqlite:///./'):]).as_posix()}"
    app_env = _str("APP_ENV", "development").strip().lower()
    secret = _str("SECRET_KEY", "").strip()
    if not secret and app_env != "production":
        from backend.local_secrets import local_secret_key

        secret = local_secret_key()                      # per-machine random value; production never gets one
    privileged = os.getenv("SIMULATION_PRIVILEGED_PASSWORD") or (
        base64.urlsafe_b64encode(hmac.new(secret.encode() or b"unset", b"simulation-privileged-account", hashlib.sha256).digest())
        [:24].decode() if secret else "")                # derived from the secret, so there is no fixed default
    return Settings(
        database_url=db_url,
        secret_key=secret,
        session_ttl_minutes=_int("SESSION_TTL_MINUTES", 480),
        display_timezone=_str("DISPLAY_TIMEZONE", "Asia/Kolkata"),
        cors_origins=[o.strip().rstrip("/") for o in _str("CORS_ORIGINS", "http://localhost:8501,http://127.0.0.1:8501,http://localhost:8503,http://127.0.0.1:8503").split(",") if o.strip()],
        auto_seed=_bool("AUTO_SEED", True),
        simulation_enabled=_bool("SIMULATION_ENABLED", True),
        map_loopback_to_workstation=_bool("MAP_LOOPBACK_TO_WORKSTATION", True),
        trusted_frontend_key=_str("TRUSTED_FRONTEND_KEY", ""),
        app_env=app_env,
        login_max_failures=_int("LOGIN_MAX_FAILURES", 5),
        login_lockout_seconds=_int("LOGIN_LOCKOUT_SECONDS", 300),
        containment_max_per_minute=_int("CONTAINMENT_MAX_PER_MINUTE", 30),
        simulation_privileged_password=privileged,
        argon2_time_cost=_int("ARGON2_TIME_COST", 3),
        argon2_memory_kib=_int("ARGON2_MEMORY_KIB", 65_536),
        argon2_parallelism=_int("ARGON2_PARALLELISM", 2),
        require_https=_bool("REQUIRE_HTTPS", app_env == "production"),
        trust_forwarded_proto=_bool("TRUST_FORWARDED_PROTO", False),
        max_request_bytes=_int("MAX_REQUEST_BYTES", 1_000_000),
        enable_api_docs=_bool("ENABLE_API_DOCS", app_env != "production"),
        login_ip_max_failures=_int("LOGIN_IP_MAX_FAILURES", 20),
        login_ip_window_seconds=_int("LOGIN_IP_WINDOW_SECONDS", 300),
        rate_limits_enabled=_bool("RATE_LIMITS_ENABLED", True),
        rate_limit_sensitive_per_minute=_int("RATE_LIMIT_SENSITIVE_PER_MINUTE", 30),
        rate_limit_heavy_per_minute=_int("RATE_LIMIT_HEAVY_PER_MINUTE", 6),
        rate_limit_employee_per_minute=_int("RATE_LIMIT_EMPLOYEE_PER_MINUTE", 60),
        db_busy_timeout_seconds=max(1, _int("DB_BUSY_TIMEOUT_SECONDS", 30)),
        db_pool_size=max(1, _int("DB_POOL_SIZE", 10)),
        db_max_overflow=max(0, _int("DB_MAX_OVERFLOW", 10)),
        db_pool_timeout_seconds=max(1, _int("DB_POOL_TIMEOUT_SECONDS", 30)),
        db_pool_recycle_seconds=max(30, _int("DB_POOL_RECYCLE_SECONDS", 1800)),
        allow_sqlite_in_production=_bool("ALLOW_SQLITE_IN_PRODUCTION", False),
        dashboard_window_days=max(1, _int("DASHBOARD_WINDOW_DAYS", 30)),
        max_page_size=max(10, _int("MAX_PAGE_SIZE", 500)),
        correlation_window_minutes=_int("CORRELATION_WINDOW_MINUTES", 240),
        investigation_window_hours=_int("INVESTIGATION_WINDOW_HOURS", 24),
        threat_suspicious_threshold=_int("THREAT_SUSPICIOUS_THRESHOLD", 25),
        threat_high_threshold=_int("THREAT_HIGH_THRESHOLD", 50),
        threat_critical_threshold=_int("THREAT_CRITICAL_THRESHOLD", 80),
        alert_min_severity=_str("ALERT_MIN_SEVERITY", "critical"),
        baseline_days=_int("BASELINE_DAYS", 30),
        detection_rules_path=_str("DETECTION_RULES_PATH", str(BASE_DIR / "backend" / "detection_rules.json")),
        ml_model_path=_str("ML_MODEL_PATH", str(BASE_DIR / "ml" / "artifacts" / "isolation_forest.joblib")),
        ml_auto_train=_bool("ML_AUTO_TRAIN", True),
        bulk_record_threshold=_int("BULK_RECORD_THRESHOLD", 500),
        business_hours_start=_int("BUSINESS_HOURS_START", 7),
        business_hours_end=_int("BUSINESS_HOURS_END", 19),
    )


PLACEHOLDER_SECRETS = ("change-me", "changeme", "dev-only", "secret", "test-secret", "password")


def _origin_problems(origins: list[str]) -> list[str]:
    problems = []
    for origin in origins:
        if origin in ("*", "null") or "*" in origin:
            problems.append(f"'{origin}' (wildcards and 'null' are not allowed)")
        elif not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?", origin):
            problems.append(f"'{origin}' (must look like https://host or http://host:port)")
    return problems


def validate_for_environment(settings: Settings | None = None) -> None:
    """Fail at start-up, with a clear message, rather than run unsafely.

    Always: CORS origins must be explicit. Production additionally needs a strong SECRET_KEY from the environment (there is
    no default), a long TRUSTED_FRONTEND_KEY if one is set, and a demo-credential source when demo data is seeded.
    """
    s = settings or get_settings()
    problems = _origin_problems(s.cors_origins)
    if problems:
        raise RuntimeError("CORS_ORIGINS must list explicit origins; invalid: " + ", ".join(problems))
    if s.app_env != "production":
        return
    lowered = s.secret_key.lower()
    if not s.secret_key or len(s.secret_key) < 32 or any(lowered.startswith(p) for p in PLACEHOLDER_SECRETS):
        raise RuntimeError("APP_ENV=production requires SECRET_KEY, set by the environment or your secret manager, to be a "
                           "random value of at least 32 characters; there is no default")
    if s.trusted_frontend_key and len(s.trusted_frontend_key) < 24:
        raise RuntimeError("TRUSTED_FRONTEND_KEY must be at least 24 characters")
    if s.database_url.startswith("sqlite") and not s.allow_sqlite_in_production:
        raise RuntimeError(
            "APP_ENV=production needs a persistent shared database: set DATABASE_URL to a managed PostgreSQL URL "
            "(for example postgresql://user:password@host/dbname). SQLite is a single-file, single-host development "
            "database and its file is lost on an ephemeral filesystem; set ALLOW_SQLITE_IN_PRODUCTION=true only if the "
            "file lives on a persistent volume and you accept a single-process deployment")
    if s.auto_seed:
        from data.demo_accounts import CredentialsMissing, load_passwords

        try:
            load_passwords(create=False)
        except CredentialsMissing as exc:
            raise RuntimeError(f"APP_ENV=production with AUTO_SEED=true needs demo credentials from the environment: {exc}") from exc


def to_local(dt: datetime) -> datetime:
    """Convert a UTC (or aware) datetime to the configured display timezone."""
    return dt.astimezone(get_settings().tz)
