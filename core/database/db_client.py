import time
import logging
import sqlite3

from core.config import DATABASE_PATH

logger = logging.getLogger(__name__)

BUSY_TIMEOUT_MS = 5000
MAX_RETRIES = 4
BASE_RETRY_DELAY = 0.1


def get_connection():
    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=5,
        check_same_thread=False
    )

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS};")

    return conn


def safe_execute(query, params=(), fetch=False):
    for attempt in range(MAX_RETRIES):
        conn = None
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(query, params)

            result = None
            if fetch:
                result = cursor.fetchall()

            conn.commit()
            return result
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower():
                delay = BASE_RETRY_DELAY * (2 ** attempt)
                logger.warning(
                    "db_retry",
                    extra={
                        "event": "db_retry",
                        "attempt": attempt + 1,
                        "max_retries": MAX_RETRIES,
                        "delay_secs": round(delay, 3),
                        "error": str(e),
                    },
                )
                time.sleep(delay)
            else:
                raise
        finally:
            if conn is not None:
                conn.close()

    raise RuntimeError("Database locked repeatedly after retries")
