
-- ============================================================
-- Adaptive Deception-Driven Cyber Resilience Validation System
-- Refined SQLite Schema — V2 (Production Ready)
-- ============================================================

-- 1. SESSIONS
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    sensor_id       TEXT DEFAULT 'local-node-1',
    source_ip       TEXT NOT NULL,
    start_time      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    end_time        DATETIME,
    duration_secs   INTEGER,
    total_commands  INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'active' CHECK (status IN ('active', 'closed', 'timeout'))
);

-- 2. COMMANDS
CREATE TABLE IF NOT EXISTS commands (
    command_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    raw_input       TEXT NOT NULL,
    parsed_command  TEXT,
    timestamp       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    response_type   TEXT CHECK (response_type IN ('rule', 'ai', 'unknown')), 
    response_text   TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

-- 3. THREATS
CREATE TABLE IF NOT EXISTS threats (
    threat_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    command_id      INTEGER NOT NULL,
    threat_type     TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'Low' CHECK (severity IN ('Low', 'Medium', 'High')),
    confidence      REAL NOT NULL DEFAULT 1.0,
    source          TEXT DEFAULT 'rule' CHECK (source IN ('rule', 'ai')),
    experiment_type TEXT NOT NULL DEFAULT 'cpu_stress',
    experiment_intensity INTEGER NOT NULL DEFAULT 1,
    experiment_duration  INTEGER NOT NULL DEFAULT 10,
    timestamp       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed       INTEGER NOT NULL DEFAULT 0 CHECK (processed IN (0, 1)),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (command_id) REFERENCES commands(command_id)
);

-- 4. CHAOS_RESULTS
CREATE TABLE IF NOT EXISTS chaos_results (
    experiment_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id          INTEGER NOT NULL,
    experiment_type    TEXT NOT NULL CHECK (experiment_type IN ('cpu_stress', 'memory_stress', 'disk_io')),
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

DROP TABLE IF EXISTS adaptive_scores;

CREATE TABLE IF NOT EXISTS adaptive_scores (
    session_id            TEXT NOT NULL,
    threat_type           TEXT NOT NULL,
    occurrence_count      INTEGER NOT NULL DEFAULT 0,
    current_severity      TEXT NOT NULL DEFAULT 'Low' CHECK (current_severity IN ('Low', 'Medium', 'High')),
    chaos_intensity_level INTEGER NOT NULL DEFAULT 1,     
    escalation_triggered  INTEGER NOT NULL DEFAULT 0 CHECK (escalation_triggered IN (0, 1)),
    is_weakness           INTEGER NOT NULL DEFAULT 0 CHECK (is_weakness IN (0, 1)),
    last_updated          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id, threat_type),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_commands_session   ON commands(session_id);
CREATE INDEX IF NOT EXISTS idx_threats_session    ON threats(session_id);
CREATE INDEX IF NOT EXISTS idx_threats_processed  ON threats(processed);
CREATE INDEX IF NOT EXISTS idx_threats_type       ON threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_chaos_threat       ON chaos_results(threat_id);
