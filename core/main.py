import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)

from core.ssh.ssh_server import start_server
from core.database.init_db import init_db

if __name__ == "__main__":
    init_db()
    start_server()