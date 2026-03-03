from core.database.db_client import safe_execute
from core.config import SENSOR_ID

from core.database.db_client import get_connection

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

def insert_command(session_id, raw_input, parsed_command, response_type, response_text):
    """Logs the command and returns the unique command_id."""
    query = """
        INSERT INTO commands 
        (session_id, raw_input, parsed_command, response_type, response_text)
        VALUES (?, ?, ?, ?, ?)
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (session_id, raw_input, parsed_command, response_type, response_text))
        command_id = cursor.lastrowid
        conn.commit()
        return command_id
    finally:
        conn.close()

def insert_threat(session_id, command_id, threat_type, severity, confidence, source):
    query = """
        INSERT INTO threats
        (session_id, command_id, threat_type, severity, confidence, source)
        VALUES (?, ?, ?, ?, ?, ?)
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(query, (session_id, command_id, threat_type, severity, confidence, source))

    conn.commit()
    conn.close()