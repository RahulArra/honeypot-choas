import sqlite3
from core.config import DATABASE_PATH

conn = sqlite3.connect(DATABASE_PATH)
conn.execute("DROP TABLE IF EXISTS adaptive_scores;")
conn.execute("""
    CREATE TABLE adaptive_scores (
        session_id TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        occurrence_count INTEGER DEFAULT 0,
        current_severity TEXT DEFAULT 'Low',
        chaos_intensity_level INTEGER DEFAULT 1,
        escalation_triggered INTEGER DEFAULT 0,
        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (session_id, threat_type),
        FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    );
""")
conn.close()
print("Schema updated successfully!")