from dotenv import load_dotenv
load_dotenv()

import logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

from core.ssh.ssh_server import start_server
from core.database.init_db import init_db
from core.chaos.watcher import start_chaos_watcher

if __name__ == "__main__":
    init_db()
    start_chaos_watcher()
    start_server()