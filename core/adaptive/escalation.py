from core.database.db_client import get_connection

def update_adaptive_score(session_id, threat_type):
    """
    Refined: Escalates severity and intensity ONLY on modulo 5 thresholds
    to ensure system stability and predictable research data.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # 1. Fetch current state for THIS session's specific threat
    cursor.execute("""
        SELECT occurrence_count, current_severity, chaos_intensity_level 
        FROM adaptive_scores 
        WHERE session_id = ? AND threat_type = ?
    """, (session_id, threat_type))
    
    row = cursor.fetchone()

    # Increment count or initialize
    count = row["occurrence_count"] + 1 if row else 1
    severity = row["current_severity"] if row else "Low"
    intensity = row["chaos_intensity_level"] if row else 1
    escalation_triggered = 0

    # 2. Refined Escalation: Only flip state at specific milestones (5, 10, 15...)
    if count > 0 and count % 5 == 0:
        escalation_triggered = 1
        if severity == "Low":
            severity = "Medium"
            intensity = 2
        elif severity == "Medium":
            severity = "High"
            intensity = 3
        # If already High, intensity stays at 3 but count continues to rise

    # 3. UPSERT into the database
    cursor.execute("""
        INSERT INTO adaptive_scores 
        (session_id, threat_type, occurrence_count, current_severity, chaos_intensity_level, escalation_triggered)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id, threat_type) DO UPDATE SET
            occurrence_count = excluded.occurrence_count,
            current_severity = excluded.current_severity,
            chaos_intensity_level = excluded.chaos_intensity_level,
            escalation_triggered = excluded.escalation_triggered,
            last_updated = CURRENT_TIMESTAMP
    """, (session_id, threat_type, count, severity, intensity, escalation_triggered))

    conn.commit()
    conn.close()
    return severity, intensity