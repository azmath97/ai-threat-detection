"""Generate the secrets a deployment needs, for you to paste into the host's environment settings.

    python -m deploy.make_secrets

Prints to your terminal only (nothing is written to disk, nothing is committed). Paste each value into the host's secret store, for
example Render's Environment tab. Run it again to rotate everything. The demo accounts are synthetic; their passwords are random.
"""
import json
import secrets
import string

from data.demo_accounts import DEMO_USERNAMES

ALPHABET = string.ascii_letters + string.digits


def password(length: int = 20) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def make() -> dict[str, str]:
    return {
        "SECRET_KEY": secrets.token_urlsafe(48),
        "DEMO_PASSWORDS_JSON": json.dumps({name: password(20) for name in sorted(DEMO_USERNAMES)}),
        "ADMIN_UI_USER": "gate-" + secrets.token_hex(3),
        "ADMIN_UI_PASSWORD": password(24),
    }


if __name__ == "__main__":
    print("# Paste these into your host's environment settings. They are shown once and stored nowhere else.\n")
    for key, value in make().items():
        print(f"{key}={value}")
    print("\n# Also set PUBLIC_URL (the https address) unless the host supplies it, and DATABASE_URL for persistent mode.")
    print("# Employee and administrator sign-in IDs and the matching passwords are listed in the DEMO_PASSWORDS_JSON value above.")
