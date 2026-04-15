import sqlite3
import os


def _ensure_chaos_results_supports_process_disruption(conn: sqlite3.Connection):
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='chaos_results'"
    ).fetchone()
    if not row or not row[0]:
        return
    if "process_disruption" in row[0]:
        return

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS chaos_results_new (
            experiment_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id          INTEGER NOT NULL,
            experiment_type    TEXT NOT NULL CHECK (experiment_type IN ('cpu_stress', 'memory_stress', 'disk_io', 'process_disruption')),
            intensity_level    INTEGER NOT NULL DEFAULT 1,
            cpu_peak           REAL,
            memory_peak        REAL,
            disk_io_peak       REAL,
            duration_secs      INTEGER,
            recovery_time_secs REAL,
            result             TEXT CHECK (result IN ('Resilient', 'Vulnerable')),
            started_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at       DATETIME,
            notes              TEXT,
            is_retest          INTEGER NOT NULL DEFAULT 0 CHECK (is_retest IN (0, 1)),
            FOREIGN KEY (threat_id) REFERENCES threats(threat_id)
        );

        INSERT INTO chaos_results_new (
            experiment_id, threat_id, experiment_type, intensity_level,
            cpu_peak, memory_peak, disk_io_peak, duration_secs, recovery_time_secs,
            result, started_at, completed_at, notes, is_retest
        )
        SELECT
            experiment_id, threat_id, experiment_type, intensity_level,
            cpu_peak, memory_peak, disk_io_peak, duration_secs, recovery_time_secs,
            result, started_at, completed_at, notes, is_retest
        FROM chaos_results;

        DROP TABLE chaos_results;
        ALTER TABLE chaos_results_new RENAME TO chaos_results;

        CREATE INDEX IF NOT EXISTS idx_chaos_threat ON chaos_results(threat_id);
        """
    )


def init_db():
    schema_path = os.path.join(os.path.dirname(__file__), "../../database/schema.sql")
    db_path = os.path.join(os.path.dirname(__file__), "../../database/honeypot.db")
    
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = f.read()
    
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.executescript(schema)
    _ensure_chaos_results_supports_process_disruption(conn)
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == "__main__":
    init_db()
