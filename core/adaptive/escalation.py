from datetime import datetime, timedelta, timezone

from core.database.db_client import get_connection, safe_execute

SCALING_WINDOW = timedelta(minutes=5)
SCALING_COOLDOWN = timedelta(minutes=2)
DEBOUNCE_WINDOW_SECS = 2

_last_scale_attempts = {}


def _utc_now():
    return datetime.now(timezone.utc)


def _iso_utc_now():
    return _utc_now().isoformat()


def _parse_utc(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def update_adaptive_score(session_id, threat_type):
    """
    Escalates severity and intensity on every fifth occurrence while preserving
    accumulated run and scaling metadata.
    """
    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT occurrence_count, current_severity, chaos_intensity_level
                FROM adaptive_scores
                WHERE session_id = ? AND threat_type = ?
                """,
                (session_id, threat_type),
            )
            row = cursor.fetchone()

            now = _iso_utc_now()
            count = int(row["occurrence_count"] or 0) + 1 if row else 1
            severity = row["current_severity"] if row else "Low"
            intensity = int(row["chaos_intensity_level"] or 1) if row else 1
            escalation_triggered = 0

            if count > 0 and count % 5 == 0:
                escalation_triggered = 1
                if severity == "Low":
                    severity = "Medium"
                    intensity = min(intensity + 1, 3)
                elif severity == "Medium":
                    severity = "High"
                    intensity = min(intensity + 1, 3)

            cursor.execute(
                """
                INSERT INTO adaptive_scores (
                    session_id,
                    threat_type,
                    occurrence_count,
                    current_severity,
                    chaos_intensity_level,
                    escalation_triggered,
                    last_updated
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, threat_type) DO UPDATE SET
                    occurrence_count = excluded.occurrence_count,
                    current_severity = excluded.current_severity,
                    chaos_intensity_level = excluded.chaos_intensity_level,
                    escalation_triggered = excluded.escalation_triggered,
                    last_updated = excluded.last_updated
                """,
                (session_id, threat_type, count, severity, intensity, escalation_triggered, now),
            )
            return severity, intensity
    finally:
        conn.close()


def update_session_metrics(session_id, threat_type, is_failure: bool):
    """Increment per-session run totals and initialize the row if needed."""
    conn = get_connection()
    try:
        with conn:
            now = _iso_utc_now()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO adaptive_scores (
                    session_id,
                    threat_type,
                    occurrence_count,
                    current_severity,
                    chaos_intensity_level,
                    total_runs,
                    total_failures,
                    last_updated
                )
                VALUES (?, ?, 0, 'Low', 1, 1, ?, ?)
                ON CONFLICT(session_id, threat_type) DO UPDATE SET
                    total_runs = COALESCE(adaptive_scores.total_runs, 0) + 1,
                    total_failures = COALESCE(adaptive_scores.total_failures, 0) + ?,
                    last_updated = excluded.last_updated
                """,
                (
                    session_id,
                    threat_type,
                    1 if is_failure else 0,
                    now,
                    1 if is_failure else 0,
                ),
            )
    finally:
        conn.close()


def update_prediction_metrics(session_id, threat_type, failure_rate: float, risk_score: float):
    now = _iso_utc_now()
    safe_execute(
        """
        UPDATE adaptive_scores
        SET predicted_risk_score = ?,
            is_weakness = CASE WHEN ? > 0.6 THEN 1 ELSE is_weakness END,
            last_updated = ?
        WHERE session_id = ? AND threat_type = ?
        """,
        (float(risk_score), float(failure_rate), now, session_id, threat_type),
    )


def get_adaptive_state(session_id, threat_type):
    rows = safe_execute(
        """
        SELECT total_runs, total_failures, is_scaled, scaled_until, last_scaled_at, predicted_risk_score
        FROM adaptive_scores
        WHERE session_id = ? AND threat_type = ?
        """,
        (session_id, threat_type),
        fetch=True,
    )
    if not rows:
        return {
            "total_runs": 0,
            "total_failures": 0,
            "is_scaled": False,
            "scaled_until": None,
            "last_scaled_at": None,
            "predicted_risk_score": 0.0,
        }

    row = rows[0]
    return {
        "total_runs": int(row[0] or 0),
        "total_failures": int(row[1] or 0),
        "is_scaled": bool(row[2]),
        "scaled_until": row[3],
        "last_scaled_at": row[4],
        "predicted_risk_score": float(row[5] or 0.0),
    }


def check_and_reset_scaling(session_id, threat_type):
    """
    Reset expired scaling windows using UTC-aware timestamp comparison.
    """
    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT is_scaled, scaled_until
                FROM adaptive_scores
                WHERE session_id = ? AND threat_type = ?
                """,
                (session_id, threat_type),
            )
            row = cursor.fetchone()
            if not row or not row["is_scaled"]:
                return False

            scaled_until = _parse_utc(row["scaled_until"])
            now = _utc_now()
            if scaled_until and now >= scaled_until:
                cursor.execute(
                    """
                    UPDATE adaptive_scores
                    SET is_scaled = 0,
                        scaled_until = NULL,
                        last_scaled_at = COALESCE(last_scaled_at, ?),
                        last_updated = ?
                    WHERE session_id = ? AND threat_type = ?
                    """,
                    (now.isoformat(), now.isoformat(), session_id, threat_type),
                )
                return True
            return False
    finally:
        conn.close()


def simulate_scaling(session_id, threat_type):
    """
    Trigger simulated scaling with a UTC expiry, cooldown enforcement, and a
    short debounce window to absorb noisy watcher spikes.
    """
    now = _utc_now()
    last_attempt = _last_scale_attempts.get(threat_type)
    if last_attempt and (now - last_attempt).total_seconds() < DEBOUNCE_WINDOW_SECS:
        return False
    _last_scale_attempts[threat_type] = now

    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT last_scaled_at, is_scaled, scaled_until
                FROM adaptive_scores
                WHERE session_id = ? AND threat_type = ?
                """,
                (session_id, threat_type),
            )
            row = cursor.fetchone()
            if not row:
                return False

            if row["is_scaled"]:
                scaled_until = _parse_utc(row["scaled_until"])
                if scaled_until and now < scaled_until:
                    return False

            last_scaled = _parse_utc(row["last_scaled_at"])
            if last_scaled and now - last_scaled < SCALING_COOLDOWN:
                return False

            scaled_until = now + SCALING_WINDOW
            cursor.execute(
                """
                UPDATE adaptive_scores
                SET is_scaled = 1,
                    scaled_until = ?,
                    last_scaled_at = ?,
                    last_updated = ?
                WHERE session_id = ? AND threat_type = ?
                """,
                (
                    scaled_until.isoformat(),
                    now.isoformat(),
                    now.isoformat(),
                    session_id,
                    threat_type,
                ),
            )
            return cursor.rowcount > 0
    finally:
        conn.close()


def mark_weakness(session_id, threat_type):
    now = _iso_utc_now()
    safe_execute(
        """
        UPDATE adaptive_scores
        SET is_weakness = 1,
            last_updated = ?
        WHERE session_id = ? AND threat_type = ?
        """,
        (now, session_id, threat_type),
    )
