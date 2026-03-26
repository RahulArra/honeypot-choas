
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(BASE_DIR, "database", "honeypot.db")

SSH_HOST = "127.0.0.1"
SSH_PORT = 2222

SESSION_TIMEOUT_SECONDS = 300
MAX_COMMAND_LENGTH = 512

SENSOR_ID = "local-node-1"