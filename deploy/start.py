"""Container entry point: checks the configuration, starts the backend and the three Streamlit apps on loopback, then the public
gateway, and supervises them. If any process dies the others are stopped and the container exits non-zero so the host restarts it.

    python -m deploy.start

Nothing here prints a secret. Configuration problems are reported by setting name only.
"""
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from deploy import preflight

ROOT = Path(__file__).resolve().parent.parent
log = logging.getLogger("supervisor")
STREAMLIT_FLAGS = ["--server.headless=true", "--server.address=127.0.0.1", "--browser.gatherUsageStats=false",
                   "--server.enableCORS=true", "--server.enableXsrfProtection=true", "--client.toolbarMode=minimal"]


def apps(env: dict[str, str]) -> list[tuple[str, list[str], str]]:
    """(name, command, health URL) for the backend and each Streamlit app."""
    py = sys.executable
    api, portal, console, soc = (int(env[k]) for k in ("API_PORT", "PORTAL_PORT", "CONSOLE_PORT", "SOC_PORT"))

    def streamlit(script: str, port: int, base: str = "") -> list[str]:
        command = [py, "-m", "streamlit", "run", script, f"--server.port={port}", *STREAMLIT_FLAGS]
        return command + ([f"--server.baseUrlPath={base}"] if base else [])

    return [
        ("backend", [py, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", str(api), "--workers", "1",
                     "--log-level", env.get("LOG_LEVEL", "info").lower()], f"http://127.0.0.1:{api}/api/health"),
        ("portal", streamlit("frontend/employee_portal.py", portal), f"http://127.0.0.1:{portal}/_stcore/health"),
        ("console", streamlit("frontend/simulation_console.py", console, "console"), f"http://127.0.0.1:{console}/console/_stcore/health"),
        ("soc", streamlit("frontend/soc_dashboard.py", soc, "soc"), f"http://127.0.0.1:{soc}/soc/_stcore/health"),
    ]


def gateway_command(env: dict[str, str]) -> list[str]:
    return [sys.executable, "-m", "uvicorn", "deploy.gateway:create_app", "--factory", "--host", env.get("HOST", "0.0.0.0"),  # noqa: S104
            "--port", env.get("PORT", "8080"), "--log-level", env.get("LOG_LEVEL", "info").lower(), "--no-access-log",
            "--timeout-graceful-shutdown", "10"]


def wait_healthy(name: str, url: str, process: subprocess.Popen, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{name} exited with code {process.returncode} before it became healthy")
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    log.info("%s is healthy", name)
                    return
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    raise RuntimeError(f"{name} did not become healthy within {timeout:.0f}s")


def stop_all(processes: dict[str, subprocess.Popen], grace: float = 15.0) -> None:
    for name, process in reversed(list(processes.items())):
        if process.poll() is None:
            log.info("stopping %s", name)
            process.terminate()
    deadline = time.time() + grace
    for name, process in processes.items():
        try:
            process.wait(timeout=max(0.1, deadline - time.time()))
        except subprocess.TimeoutExpired:
            log.warning("%s did not stop in time; killing it", name)
            process.kill()


def prepare_demo_database(env: dict[str, str]) -> None:
    """Demo mode starts from nothing every time: the old demo database is removed so the synthetic data is re-seeded."""
    url = env["DATABASE_URL"]
    path = Path(url.removeprefix("sqlite:///"))
    if path.parent.exists():
        shutil.rmtree(path.parent, ignore_errors=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    log.info("demo mode: using a fresh throw-away database (nothing here is kept across restarts)")


def main() -> int:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    sys.path.insert(0, str(ROOT))
    found = preflight.problems(os.environ)
    if found:
        log.error("The deployment is not configured correctly. Fix these and restart:")
        for item in found:
            log.error("  - %s", item)
        return 2
    env = preflight.child_environment(os.environ)
    log.info("starting in %s mode; public address %s", env["DEPLOY_MODE"], env["PUBLIC_URL"])
    if env["DEPLOY_MODE"] == "demo":
        prepare_demo_database(env)

    processes: dict[str, subprocess.Popen] = {}
    stopping = False

    def on_signal(signum, _frame):
        nonlocal stopping
        stopping = True
        log.info("received signal %s; shutting down", signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, on_signal)

    try:
        for name, command, health in apps(env):
            log.info("starting %s", name)
            processes[name] = subprocess.Popen(command, cwd=ROOT, env=env)
            wait_healthy(name, health, processes[name], timeout=float(env.get("STARTUP_TIMEOUT_SECONDS", "240")))
            if stopping:
                break
        if not stopping:
            processes["gateway"] = subprocess.Popen(gateway_command(env), cwd=ROOT, env=env)
            wait_healthy("gateway", f"http://127.0.0.1:{env.get('PORT', '8080')}/healthz", processes["gateway"], timeout=60)
            log.info("ready: every process is healthy and the gateway is serving on port %s", env.get("PORT", "8080"))
        while not stopping:
            for name, process in processes.items():
                code = process.poll()
                if code is not None:
                    log.error("%s exited with code %s; stopping everything so the host can restart the service", name, code)
                    return 1
            time.sleep(1)
        return 0
    except RuntimeError as exc:
        log.error("%s", exc)
        return 1
    finally:
        stop_all(processes)


if __name__ == "__main__":
    sys.exit(main())
