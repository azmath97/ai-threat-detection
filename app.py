"""Launcher.

    python app.py setup      first-time local setup: .env with a random SECRET_KEY and random demo credentials
    python app.py credentials  show the local demo sign-in credentials (never printed by the servers)
    python app.py            backend API only            (http://127.0.0.1:8000)
    python app.py portal     Employee Workspace Portal   (http://127.0.0.1:8501)
    python app.py simulation Simulation Console (admin)  (http://127.0.0.1:8502)
    python app.py soc        SOC Dashboard (admin)       (http://127.0.0.1:8503)
    python app.py all        backend + portal + simulation console + SOC dashboard
"""
import os
import secrets
import subprocess
import sys
from pathlib import Path

import uvicorn
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")      # so API_HOST / API_PORT / API_BASE_URL can live in .env too
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "8000"))
FRONTENDS = {
    "portal": ("frontend/employee_portal.py", 8501),
    "simulation": ("frontend/simulation_console.py", 8502),
    "soc": ("frontend/soc_dashboard.py", 8503),
}


def streamlit_command(script: str, port: int) -> list[str]:
    return [sys.executable, "-m", "streamlit", "run", script, "--server.port", str(port)]


def setup() -> None:
    """Create .env (random SECRET_KEY) and the demo credentials file. Safe to re-run: existing files are kept."""
    env_file, example = ROOT / ".env", ROOT / ".env.example"
    if env_file.exists():
        print(f"{env_file.name} already exists; left unchanged.")
    else:
        lines = example.read_text(encoding="utf-8").splitlines()
        lines = [f"SECRET_KEY={secrets.token_urlsafe(48)}" if line.startswith("SECRET_KEY=") else line for line in lines]
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            env_file.chmod(0o600)
        except OSError:
            pass
        print(f"Created {env_file.name} with a random SECRET_KEY (git-ignored).")
    from data.demo_accounts import credentials_file, load_passwords

    existed = credentials_file().exists()
    load_passwords(create=True)
    print(f"{'Using existing' if existed else 'Generated'} demo credentials in {credentials_file().relative_to(ROOT)} (git-ignored).")
    print("Show them with:  python app.py credentials")
    print("Start everything with:  python app.py all")


def show_credentials() -> None:
    from data.demo_accounts import _BY_CODE, load_passwords

    passwords = load_passwords(create=True)
    print("Local demo credentials (synthetic accounts, this machine only; do not commit or share this output)\n")
    print(f"{'Employee ID':<12} {'Username':<14} Password")
    for code, username in _BY_CODE.items():
        print(f"{code:<12} {username:<14} {passwords[username]}")


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "backend"
    env = {**os.environ, "API_BASE_URL": os.getenv("API_BASE_URL", f"http://{API_HOST}:{API_PORT}")}
    if mode == "setup":
        setup()
    elif mode == "credentials":
        show_credentials()
    elif mode == "backend":
        uvicorn.run("backend.main:app", host=API_HOST, port=API_PORT,
                    reload=os.getenv("API_RELOAD", "false").lower() == "true")
    elif mode in FRONTENDS:
        subprocess.run(streamlit_command(*FRONTENDS[mode]), env=env, check=False)
    elif mode == "all":
        children = [subprocess.Popen(streamlit_command(*spec), env=env) for spec in FRONTENDS.values()]
        try:
            uvicorn.run("backend.main:app", host=API_HOST, port=API_PORT)
        finally:
            for child in children:
                child.terminate()
    else:
        sys.exit(f"Unknown mode '{mode}'. Use: setup | credentials | backend | portal | simulation | soc | all")


if __name__ == "__main__":
    main()
