"""Demo sign-in credentials for the seeded synthetic accounts (local demonstration only).

Each account has its own password. They are stored in the database only as salted PBKDF2 hashes; this module is the
one place the plaintext demo values exist, so the README, the simulation ("stolen credentials") and the tests agree.
"""
from backend.models import employee_code_for

# username -> password, in the same order as data.seed_data.EMPLOYEES (so IDs are EMP-1001 ... EMP-1010, SEC-9011)
DEMO_PASSWORDS = {
    "alice.morgan": "Cedar#Harbor47",
    "bob.chen": "Quill&Meadow82",
    "carol.diaz": "Birch!Lantern26",
    "david.kumar": "Falcon$Ridge63",
    "emma.wilson": "Willow#Summit19",
    "frank.osei": "Amber%Compass74",
    "grace.lee": "Juniper!Atlas58",
    "henry.novak": "Granite#Voyage31",
    "isla.murphy": "Coral&Beacon95",
    "jack.silva": "Cobalt!Meadow68",
    "soc.admin": "Sentinel#Vault2026",
}
_ROLE_OF = {name: ("security_admin" if name == "soc.admin" else "employee") for name in DEMO_PASSWORDS}
_BY_CODE = {employee_code_for(i, _ROLE_OF[name]): name for i, name in enumerate(DEMO_PASSWORDS, start=1)}


def demo_password(identifier: str, default: str | None = None) -> str:
    """Password for an employee ID (EMP-1001) or username (alice.morgan)."""
    username = _BY_CODE.get(identifier.upper(), identifier)
    if default is not None:
        return DEMO_PASSWORDS.get(username, default)
    return DEMO_PASSWORDS[username]
