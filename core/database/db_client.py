import sqlite3
from core.config import DATABASE_PATH
import time


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

    return conn



def safe_execute(query, params=(), fetch=False):
    max_retries = 3
    retry_delay = 0.1

    for attempt in range(max_retries):
        try:
            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute(query, params)

            result = None
            if fetch:
                result = cursor.fetchall()

            conn.commit()
            conn.close()

            return result

        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower():
                time.sleep(retry_delay)
            else:
                raise

    raise Exception("Database locked repeatedly after retries")