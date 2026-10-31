"""Launcher.

    python app.py            backend API only            (http://127.0.0.1:8000)
    python app.py portal     Employee Workspace Portal   (http://127.0.0.1:8501)
    python app.py simulation Simulation Console (admin)  (http://127.0.0.1:8502)
    python app.py all        backend + portal + simulation console
"""
import os
import subprocess
import sys

import uvicorn

API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "8000"))


def streamlit_command(script: str, port: int) -> list[str]:
    return [sys.executable, "-m", "streamlit", "run", script, "--server.port", str(port)]


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "backend"
    env = {**os.environ, "API_BASE_URL": os.getenv("API_BASE_URL", f"http://{API_HOST}:{API_PORT}")}
    if mode == "backend":
        uvicorn.run("backend.main:app", host=API_HOST, port=API_PORT,
                    reload=os.getenv("API_RELOAD", "false").lower() == "true")
    elif mode == "portal":
        subprocess.run(streamlit_command("frontend/employee_portal.py", 8501), env=env, check=False)
    elif mode == "simulation":
        subprocess.run(streamlit_command("frontend/simulation_console.py", 8502), env=env, check=False)
    elif mode == "all":
        children = [
            subprocess.Popen(streamlit_command("frontend/employee_portal.py", 8501), env=env),
            subprocess.Popen(streamlit_command("frontend/simulation_console.py", 8502), env=env),
        ]
        try:
            uvicorn.run("backend.main:app", host=API_HOST, port=API_PORT)
        finally:
            for child in children:
                child.terminate()
    else:
        sys.exit(f"Unknown mode '{mode}'. Use: backend | portal | simulation | all")


if __name__ == "__main__":
    main()
