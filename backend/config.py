import os
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
    simulation_privileged_password: str
    password_hash_iterations: int
    demo_employee_password: str
    demo_admin_password: str
    risk_window_minutes: int
    correlation_window_minutes: int
    investigation_window_hours: int
    risk_medium_threshold: int
    risk_high_threshold: int
    risk_critical_threshold: int
    bulk_record_threshold: int
    business_hours_start: int
    business_hours_end: int

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.display_timezone)


@lru_cache
def get_settings() -> Settings:
    default_db = f"sqlite:///{(BASE_DIR / 'data' / 'insider_threat.db').as_posix()}"
    db_url = _str("DATABASE_URL", default_db)
    if db_url.startswith("sqlite:///./"):
        db_url = f"sqlite:///{(BASE_DIR / db_url[len('sqlite:///./'):]).as_posix()}"
    return Settings(
        database_url=db_url,
        secret_key=_str("SECRET_KEY", "dev-only-secret-change-me"),
        session_ttl_minutes=_int("SESSION_TTL_MINUTES", 480),
        display_timezone=_str("DISPLAY_TIMEZONE", "Asia/Kolkata"),
        cors_origins=[o.strip() for o in _str("CORS_ORIGINS", "http://localhost:8501,http://127.0.0.1:8501").split(",") if o.strip()],
        auto_seed=_bool("AUTO_SEED", True),
        simulation_enabled=_bool("SIMULATION_ENABLED", True),
        map_loopback_to_workstation=_bool("MAP_LOOPBACK_TO_WORKSTATION", True),
        simulation_privileged_password=_str("SIMULATION_PRIVILEGED_PASSWORD", "Synthetic#Priv2026"),
        password_hash_iterations=_int("PASSWORD_HASH_ITERATIONS", 260_000),
        demo_employee_password=_str("DEMO_EMPLOYEE_PASSWORD", "Employee#Demo2026"),
        demo_admin_password=_str("DEMO_ADMIN_PASSWORD", "SocAdmin#Demo2026"),
        risk_window_minutes=_int("RISK_WINDOW_MINUTES", 120),
        correlation_window_minutes=_int("CORRELATION_WINDOW_MINUTES", 240),
        investigation_window_hours=_int("INVESTIGATION_WINDOW_HOURS", 24),
        risk_medium_threshold=_int("RISK_MEDIUM_THRESHOLD", 25),
        risk_high_threshold=_int("RISK_HIGH_THRESHOLD", 50),
        risk_critical_threshold=_int("RISK_CRITICAL_THRESHOLD", 75),
        bulk_record_threshold=_int("BULK_RECORD_THRESHOLD", 500),
        business_hours_start=_int("BUSINESS_HOURS_START", 7),
        business_hours_end=_int("BUSINESS_HOURS_END", 19),
    )


def to_local(dt: datetime) -> datetime:
    """Convert a UTC (or aware) datetime to the configured display timezone."""
    return dt.astimezone(get_settings().tz)
