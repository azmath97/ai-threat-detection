"""Policy for authentication defence: detection thresholds and response limits, all configurable from the environment.

The defaults are a starting policy, not universal truth: they should be calibrated against the organisation's real
sign-in traffic. Read on every use (not cached) so tests and operators can change them without a restart.
"""
import ipaddress
import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _networks(raw: str) -> tuple:
    found = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            try:
                found.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                continue
    return tuple(found)


@dataclass(frozen=True)
class AuthPolicy:
    enabled: bool                       # AUTH_DEFENSE_ENABLED: record attempts and detect attacks
    auto_response: bool                 # AUTH_AUTO_RESPONSE: apply the response policy (false = alert only)
    # one account
    account_fail_threshold: int         # ACCOUNT_LOCKOUT_THRESHOLD: failures on one account ...
    account_window_minutes: int         # ... within this many minutes
    known_ip_fail_threshold: int        # the higher threshold when every failure came from the account's own known addresses
    account_lock_minutes: int           # how long an automatic lock lasts
    # one source address
    ip_alert_failures: int              # failures from one address within ip_alert_window_minutes: high risk
    ip_alert_window_minutes: int
    ip_block_threshold: int             # IP_BLOCK_THRESHOLD: failures from one address within ip_block_window_minutes: critical
    ip_block_window_minutes: int
    stuffing_accounts_alert: int        # distinct accounts failed from one address: credential stuffing (high risk)
    stuffing_accounts_critical: int     # ... and critical
    stuffing_window_minutes: int
    ip_block_minutes: int               # how long an automatic application-level block lasts
    # one account, many addresses
    distributed_ips: int
    distributed_failures: int
    distributed_window_minutes: int
    # success after failures
    success_after_failures: int
    success_window_minutes: int
    # safeguards
    max_auto_locks_per_hour: int
    max_auto_blocks_per_hour: int
    protected_networks: tuple           # PROTECTED_IPS: addresses and CIDR ranges that are never blocked
    attempt_retention_days: int


def get_policy() -> AuthPolicy:
    return AuthPolicy(
        enabled=_flag("AUTH_DEFENSE_ENABLED", True),
        auto_response=_flag("AUTH_AUTO_RESPONSE", True),
        account_fail_threshold=_int("ACCOUNT_LOCKOUT_THRESHOLD", 5),
        account_window_minutes=_int("ACCOUNT_FAILURE_WINDOW_MINUTES", 5),
        known_ip_fail_threshold=_int("KNOWN_IP_LOCKOUT_THRESHOLD", 10),
        account_lock_minutes=_int("ACCOUNT_LOCK_MINUTES", 15),
        ip_alert_failures=_int("IP_ALERT_FAILURES", 10),
        ip_alert_window_minutes=_int("IP_ALERT_WINDOW_MINUTES", 5),
        ip_block_threshold=_int("IP_BLOCK_THRESHOLD", 20),
        ip_block_window_minutes=_int("IP_BLOCK_WINDOW_MINUTES", 10),
        stuffing_accounts_alert=_int("STUFFING_ACCOUNTS_ALERT", 5),
        stuffing_accounts_critical=_int("STUFFING_ACCOUNTS_CRITICAL", 10),
        stuffing_window_minutes=_int("STUFFING_WINDOW_MINUTES", 10),
        ip_block_minutes=_int("IP_BLOCK_MINUTES", 60),
        distributed_ips=_int("DISTRIBUTED_IPS", 3),
        distributed_failures=_int("DISTRIBUTED_FAILURES", 6),
        distributed_window_minutes=_int("DISTRIBUTED_WINDOW_MINUTES", 10),
        success_after_failures=_int("SUCCESS_AFTER_FAILURES", 3),
        success_window_minutes=_int("SUCCESS_AFTER_FAILURES_WINDOW_MINUTES", 10),
        max_auto_locks_per_hour=_int("MAX_AUTO_LOCKS_PER_HOUR", 10),
        max_auto_blocks_per_hour=_int("MAX_AUTO_BLOCKS_PER_HOUR", 10),
        protected_networks=_networks(os.getenv("PROTECTED_IPS", "")),
        attempt_retention_days=_int("AUTH_ATTEMPT_RETENTION_DAYS", 30),
    )


# Addresses a block must never cover: this host, private and shared address space (an office, a VPN or a proxy would take
# every user with it) and link-local ranges. The documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) stay
# blockable because they are what tests and examples use as "an outside address".
NEVER_BLOCK = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"))


def unblockable_reason(ip: str, policy: AuthPolicy, known_ips: set[str] = frozenset()) -> str | None:
    """Why this address must not be blocked, or None if it may be."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "not a valid IP address"
    if any(addr in net for net in NEVER_BLOCK if net.version == addr.version):
        return "private, loopback or shared address space: blocking it could lock out legitimate users (or the platform itself)"
    if any(addr in net for net in policy.protected_networks if net.version == addr.version):
        return "listed in PROTECTED_IPS"
    if ip in known_ips:
        return "registered as an employee's known address"
    return None
