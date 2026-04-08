from dotenv import load_dotenv
load_dotenv()

import logging
import os
import subprocess
import sys
logging.basicConfig(level=logging.INFO, format="%(message)s")

from core.ssh.ssh_server import start_server
from core.database.init_db import init_db
from core.chaos.watcher import start_chaos_watcher


def start_api_server():
    """
    Starts the FastAPI backend used by the dashboard as a child process.
    Using a child process is more reliable on Windows than running uvicorn
    inside a background thread.
    """
    host = os.getenv("API_HOST", "127.0.0.1")
    port = int(os.getenv("API_PORT", "8000"))
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "core.api.server:app",
        "--host",
        host,
        "--port",
        str(port),
        "--log-level",
        "warning",
    ]
    try:
        proc = subprocess.Popen(cmd)
        logging.info(f"[API] Dashboard API starting on http://{host}:{port} (pid={proc.pid})")
        return proc
    except Exception as exc:
        logging.warning(f"[API] Failed to start dashboard API on {host}:{port}: {exc}")
        return None


if __name__ == "__main__":
    init_db()
    start_chaos_watcher()
    start_api_server()
    start_server()
