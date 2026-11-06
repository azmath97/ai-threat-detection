"""Attack drill: a command-line client that sends real requests to a running Westbridge backend, the way an attacker's tooling
(or a misbehaving employee) would, so the detection and response can be watched live in the SOC dashboard.

    python -m deploy.attack_drill brute-force            five wrong passwords against one account, from an outside address
    python -m deploy.attack_drill credential-stuffing    one password tried against every account, from one outside address
    python -m deploy.attack_drill idor                   an employee reads other employees' records one by one
    python -m deploy.attack_drill bulk-export            an employee asks for 15,000 records at once (held for approval)
    python -m deploy.attack_drill compromised-account    stolen password used from an unfamiliar address: probing, then a large export
    python -m deploy.attack_drill recover                unlock accounts and unblock addresses afterwards (as the SOC administrator)

Nothing here bypasses the product: every call is an ordinary HTTP request to the real endpoints, and every result you see is the
backend's own answer. Outside addresses are RFC 5737 documentation addresses; no packet leaves the machine except the requests to
the backend. The backend believes a client address only together with the shared TRUSTED_FRONTEND_KEY (read from the environment
or .env), exactly as it does for the dashboards. The employee passwords come from the local demo credentials file, which stands in
for "stolen" credentials. Point it only at your own demo backend.
"""
import argparse
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
sys.path.insert(0, str(ROOT))

ATTACKER = {"brute-force": "203.0.113.50", "credential-stuffing": "198.51.100.77", "compromised-account": "203.0.113.45"}
ACCOUNTS = [f"EMP-10{n:02d}" for n in range(1, 11)] + ["SEC-9011"]
PROBES = ["hr-records", "payroll-records", "it-admin-console", "audit-reports", "loan-applications"]


class Drill:
    def __init__(self, api: str, key: str):
        self.api, self.key = api.rstrip("/"), key
        self.http = requests.Session()

    def headers(self, ip: str | None, token: str | None = None) -> dict:
        out = {}
        if ip:
            out.update({"X-Frontend-Key": self.key, "X-Client-IP": ip})
        if token:
            out["Authorization"] = f"Bearer {token}"
        return out

    def login(self, who: str, password: str, ip: str | None):
        return self.http.post(f"{self.api}/api/auth/login", json={"employee_id": who, "password": password},
                              headers=self.headers(ip), timeout=30)

    def token(self, who: str, ip: str | None) -> str:
        from data.demo_accounts import demo_password

        response = self.login(who, demo_password(who), ip)
        if response.status_code != 200:
            sys.exit(f"Could not sign in as {who}: HTTP {response.status_code} {response.json().get('detail', '')}")
        return response.json()["access_token"]

    def call(self, method: str, path: str, token: str | None, ip: str | None = None, **kwargs):
        return self.http.request(method, f"{self.api}{path}", headers=self.headers(ip, token), timeout=60, **kwargs)


def say(text: str = "") -> None:
    print(text, flush=True)


def brute_force(d: Drill, target: str) -> None:
    ip = ATTACKER["brute-force"]
    say(f"Brute force on {target} from {ip}: five wrong passwords")
    for n in range(1, 6):
        r = d.login(target, f"guess-{n}-not-the-password", ip)
        say(f"  attempt {n}: HTTP {r.status_code}  {r.json().get('detail', '')}")
    r = d.login(target, "one-more-guess", ip)
    say(f"  attempt 6 (after the lock): HTTP {r.status_code}  {r.json().get('detail', '')}")
    say("Look at: SOC dashboard > Authentication Defence. The account is locked and the sessions revoked automatically.")


def credential_stuffing(d: Drill) -> None:
    ip = ATTACKER["credential-stuffing"]
    say(f"Credential stuffing from {ip}: one common password against {len(ACCOUNTS)} accounts")
    for who in ACCOUNTS:
        r = d.login(who, "Summer2024!", ip)
        say(f"  {who}: HTTP {r.status_code}  {r.json().get('detail', '')}")
    r = d.login("EMP-1001", "Summer2024!", ip)
    say(f"  EMP-1001 again, from the same address: HTTP {r.status_code}  {r.json().get('detail', '')}")
    say("Look at: Authentication Defence. The address is blocked inside the application (not a firewall rule) once ten accounts have failed.")


def idor(d: Drill, who: str) -> None:
    token = d.token(who, None)
    own = d.call("GET", "/api/employees/me", token).json()
    others = [e["id"] for e in d.call("GET", "/api/employees", d.token("SEC-9011", None)).json() if e["id"] != own["id"]]
    say(f"{who} reads other employees' records one by one")
    for pk in others[:10]:
        r = d.call("GET", f"/api/employees/{pk}", token)
        say(f"  /api/employees/{pk}: HTTP {r.status_code}")
    r = d.call("GET", "/api/employees/me", token)
    say(f"  the account's own session afterwards: HTTP {r.status_code}")
    say("Look at: Authentication Defence. Probing is an incident; no record was ever returned; the account was locked at the Alert level.")


def bulk_export(d: Drill, who: str) -> None:
    token = d.token(who, None)
    say(f"{who} asks to export 15,000 records at once")
    r = d.call("POST", "/api/resources/financial-reports/access", token, json={"action": "export", "record_count": 15_000})
    say(f"  HTTP {r.status_code}  {r.json().get('detail', '')}")
    say("Look at: Authentication Defence > Export approvals. A security administrator approves or denies it; nothing was processed.")


def compromised_account(d: Drill, who: str) -> None:
    ip = ATTACKER["compromised-account"]
    say(f"Stolen password for {who} used from {ip}, an address the account has never used")
    token = d.token(who, ip)
    say("  signed in with the valid password")
    for resource in PROBES:
        r = d.call("POST", f"/api/resources/{resource}/access", token, ip, json={"action": "view"})
        say(f"  probe {resource}: HTTP {r.status_code}")
    for n in range(2):
        r = d.call("POST", "/api/resources/financial-reports/access", token, ip, json={"action": "export", "record_count": 9_000})
        say(f"  export {n + 1} (9,000 records): HTTP {r.status_code}  {r.json().get('detail', '')[:90]}")
    say("Look at: Live Event Feed, Attack Investigations and the Employee Risk Monitor. The detector decides whether to raise an alert.")


def recover(d: Drill) -> None:
    admin = d.token("SEC-9011", None)
    overview = d.call("GET", "/api/soc/auth/overview", admin).json()
    for row in overview["locked_accounts"]:
        r = d.call("POST", "/api/soc/auth/actions", admin, json={"action": "unlock_account", "target": row["employee_id"],
                                                                 "reason": "Attack drill clean-up", "confirm": True})
        say(f"unlock {row['employee_id']}: HTTP {r.status_code}")
    for row in overview["blocked_addresses"]:
        r = d.call("POST", "/api/soc/auth/actions", admin, json={"action": "unblock_ip", "target": row["ip"],
                                                                 "reason": "Attack drill clean-up", "confirm": True})
        say(f"unblock {row['ip']}: HTTP {r.status_code}")
    if not (overview["locked_accounts"] or overview["blocked_addresses"]):
        say("Nothing to recover: no locked accounts and no blocked addresses.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m deploy.attack_drill", description=__doc__.split("\n\n")[0])
    parser.add_argument("scenario", choices=["brute-force", "credential-stuffing", "idor", "bulk-export", "compromised-account", "recover"])
    parser.add_argument("--api", default=os.getenv("API_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--key", default=os.getenv("TRUSTED_FRONTEND_KEY", ""), help="the backend's TRUSTED_FRONTEND_KEY")
    parser.add_argument("--account", help="the account the scenario uses (default depends on the scenario)")
    args = parser.parse_args(argv)
    if args.scenario in ("brute-force", "credential-stuffing", "compromised-account") and not args.key:
        parser.error("this scenario needs the backend's TRUSTED_FRONTEND_KEY (set it in .env or pass --key): without it the backend "
                     "cannot tell the attacker's address from the machine you are on")
    d = Drill(args.api, args.key)
    {"brute-force": lambda: brute_force(d, args.account or "EMP-1010"),
     "credential-stuffing": lambda: credential_stuffing(d),
     "idor": lambda: idor(d, args.account or "EMP-1003"),
     "bulk-export": lambda: bulk_export(d, args.account or "EMP-1001"),
     "compromised-account": lambda: compromised_account(d, args.account or "EMP-1001"),
     "recover": lambda: recover(d)}[args.scenario]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
