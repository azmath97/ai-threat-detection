"""Launcher. Starts the FastAPI backend (the dashboards are added in the next phase)."""
import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=os.getenv("API_HOST", "127.0.0.1"),
        port=int(os.getenv("API_PORT", "8000")),
        reload=os.getenv("API_RELOAD", "false").lower() == "true",
    )
