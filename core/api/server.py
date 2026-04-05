from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.database.db_client import safe_execute

app = FastAPI(title="Honeypot Chaos API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/overview")
def get_overview():
    sessions = safe_execute("SELECT COUNT(*) FROM sessions", fetch=True)[0][0]
    threats = safe_execute("SELECT COUNT(*) FROM threats", fetch=True)[0][0]
    vuln_runs = safe_execute("SELECT COUNT(*) FROM chaos_results WHERE result = 'Vulnerable'", fetch=True)[0][0]
    return {
        "total_sessions": sessions,
        "total_threats": threats,
        "vulnerable_runs": vuln_runs
    }

@app.get("/api/sessions")
def get_sessions():
    rows = safe_execute("SELECT session_id, source_ip, start_time, duration_secs, total_commands, status FROM sessions ORDER BY start_time DESC LIMIT 50", fetch=True)
    return [{"session_id": r[0], "source_ip": r[1], "start_time": r[2], "duration_secs": r[3], "total_commands": r[4], "status": r[5]} for r in rows] if rows else []

@app.get("/api/threats")
def get_threats():
    rows = safe_execute("""
    SELECT t.threat_id, t.session_id, c.raw_input, t.threat_type, t.severity, t.source, t.timestamp
    FROM threats t
    JOIN commands c ON t.command_id = c.command_id
    ORDER BY t.timestamp DESC LIMIT 50
    """, fetch=True)
    return [{"threat_id": r[0], "session_id": r[1], "raw_input": r[2], "threat_type": r[3], "severity": r[4], "source": r[5], "timestamp": r[6]} for r in rows] if rows else []

@app.get("/api/chaos_analytics")
def get_chaos():
    rows = safe_execute("""
    SELECT experiment_id, threat_id, experiment_type, intensity_level, result, cpu_peak, recovery_time_secs, started_at, is_retest
    FROM chaos_results
    ORDER BY started_at DESC LIMIT 50
    """, fetch=True)
    return [{"experiment_id": r[0], "threat_id": r[1], "experiment_type": r[2], "intensity_level": r[3], "result": r[4], "cpu_peak": r[5], "recovery_time_secs": r[6], "started_at": r[7], "is_retest": r[8]} for r in rows] if rows else []
