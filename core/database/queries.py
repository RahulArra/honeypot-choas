from core.database.db_client import get_connection, safe_execute
from core.config import SENSOR_ID

MAX_INTENSITY = 6.0


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


def update_command_response_type(command_id, response_type, response_text):
    query = """
        UPDATE commands
        SET response_type = ?, response_text = ?
        WHERE command_id = ?
    """
    safe_execute(query, (response_type, response_text, command_id))


def insert_threat(session_id, command_id, threat_type, severity, confidence, source, experiment=None):
    if experiment is None:
        experiment = {"type": "cpu_stress", "intensity": 1, "duration": 10}

    query = """
        INSERT INTO threats
        (session_id, command_id, threat_type, severity, confidence, source, experiment_type, experiment_intensity, experiment_duration)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            query,
            (
                session_id,
                command_id,
                threat_type,
                severity,
                confidence,
                source,
                experiment.get("type", "cpu_stress"),
                experiment.get("intensity", 1),
                experiment.get("duration", 10),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def upsert_global_threat_stats(threat_type, is_failure, intensity):
    """
    Atomically update cross-session learning with capped intensity averaging.
    """
    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO global_threat_stats (
                    threat_type,
                    total_runs,
                    total_failures,
                    avg_intensity,
                    last_seen
                )
                VALUES (?, 1, ?, MIN(?, ?), CURRENT_TIMESTAMP)
                ON CONFLICT(threat_type) DO UPDATE SET
                    total_runs = COALESCE(global_threat_stats.total_runs, 0) + 1,
                    total_failures = COALESCE(global_threat_stats.total_failures, 0) + excluded.total_failures,
                    avg_intensity = MIN(
                        (
                            (COALESCE(global_threat_stats.avg_intensity, 0.0) * COALESCE(global_threat_stats.total_runs, 0))
                            + excluded.avg_intensity
                        ) / (COALESCE(global_threat_stats.total_runs, 0) + 1),
                        ?
                    ),
                    last_seen = CURRENT_TIMESTAMP
                """,
                (
                    threat_type,
                    1 if is_failure else 0,
                    float(intensity),
                    MAX_INTENSITY,
                    MAX_INTENSITY,
                ),
            )
    finally:
        conn.close()


def get_threat_prediction(threat_type):
    """Fetch prediction from the analytics view."""
    query = """
        SELECT total_runs, total_failures, failure_rate, risk_score
        FROM v_vulnerability_metrics
        WHERE threat_type = ?
    """
    rows = safe_execute(query, (threat_type,), fetch=True)
    if rows:
        row = rows[0]
        return {
            "total_runs": int(row[0] or 0),
            "total_failures": int(row[1] or 0),
            "failure_rate": round(float(row[2] or 0.0), 2),
            "risk_score": round(float(row[3] or 0.0), 2),
        }
    return {"total_runs": 0, "total_failures": 0, "failure_rate": 0.0, "risk_score": 0.0}
