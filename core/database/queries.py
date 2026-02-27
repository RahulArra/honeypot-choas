from core.database.db_client import safe_execute
from core.config import SENSOR_ID


def insert_session(session_id, source_ip):
    query = """
        INSERT INTO sessions (session_id, sensor_id, source_ip)
        VALUES (?, ?, ?)
    """
    safe_execute(query, (session_id, SENSOR_ID, source_ip))


def close_session(session_id, status="closed"):
    query = """
        UPDATE sessions
        SET end_time = CURRENT_TIMESTAMP,
            duration_secs = CAST(
                (julianday(CURRENT_TIMESTAMP) - julianday(start_time)) * 86400
                AS INTEGER
            ),
            status = ?
        WHERE session_id = ?
    """
    safe_execute(query, (status, session_id))


def increment_command_count(session_id):
    query = """
        UPDATE sessions
        SET total_commands = total_commands + 1
        WHERE session_id = ?
    """
    safe_execute(query, (session_id,))