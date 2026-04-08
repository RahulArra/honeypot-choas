from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.database.db_client import safe_execute
from core.chaos.threat_map import get_experiment_type

app = FastAPI(title="Honeypot Chaos API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _to_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_notes(notes):
    parsed = {
        "metric_source": "unknown",
        "target_service": "",
        "service_down_time": None,
        "restart_attempts": None,
        "cpu_variant": "",
        "variant_combination": False,
        "baseline_cpu": None,
        "baseline_mem": None,
        "cpu_normalized_secs": None,
        "mem_stabilized_secs": None,
        "cpu_limit": None,
        "mem_limit": None,
        "score": None,
        "normalized_recovery": None,
        "instability_score": None,
        "degrading": None,
        "threads": None,
        "memory_mb": None,
        "disk_intensity": None,
        "forks": None,
    }
    text = notes or ""
    for part in text.split(","):
        token = part.strip()
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key == "MetricSource":
            parsed["metric_source"] = value
        elif key == "TargetService":
            parsed["target_service"] = value
        elif key == "ServiceDownTime":
            parsed["service_down_time"] = _to_float(value, None)
        elif key == "RestartAttempts":
            parsed["restart_attempts"] = int(_to_float(value, 0))
        elif key == "CpuVariant":
            parsed["cpu_variant"] = value
        elif key == "VariantCombination":
            parsed["variant_combination"] = value.lower() == "true"
        elif key == "BaselineCPU":
            parsed["baseline_cpu"] = _to_float(value, None)
        elif key == "BaselineMem":
            parsed["baseline_mem"] = _to_float(value, None)
        elif key == "CPUNormSecs":
            parsed["cpu_normalized_secs"] = _to_float(value, None)
        elif key == "MemStabilizedSecs":
            parsed["mem_stabilized_secs"] = _to_float(value, None)
        elif key == "CPULimit":
            parsed["cpu_limit"] = _to_float(value, None)
        elif key == "MemLimit":
            parsed["mem_limit"] = _to_float(value, None)
        elif key == "Score":
            parsed["score"] = _to_float(value, None)
        elif key == "NormalizedRecovery":
            parsed["normalized_recovery"] = _to_float(value, None)
        elif key == "InstabilityScore":
            parsed["instability_score"] = _to_float(value, None)
        elif key == "Degrading":
            parsed["degrading"] = value.lower() == "true"
        elif key == "Threads":
            parsed["threads"] = int(_to_float(value, 0))
        elif key == "Memory":
            parsed["memory_mb"] = int(_to_float(value.replace("MB", ""), 0))
        elif key == "DiskIntensity":
            parsed["disk_intensity"] = int(_to_float(value, 0))
        elif key == "Forks":
            parsed["forks"] = int(_to_float(value, 0))
    return parsed

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


@app.get("/api/sessions/{session_id}")
def get_session_detail(session_id: str):
    # Session metadata
    session_row = safe_execute(
        "SELECT session_id, source_ip, start_time, end_time, duration_secs, total_commands, status FROM sessions WHERE session_id = ?",
        params=(session_id,), fetch=True
    )
    if not session_row:
        return {"error": "Session not found"}
    s = session_row[0]
    session_info = {
        "session_id": s[0],
        "source_ip": s[1],
        "start_time": s[2],
        "end_time": s[3],
        "duration_secs": s[4],
        "total_commands": s[5],
        "status": s[6],
    }

    # All commands for this session with threat + chaos results joined
    rows = safe_execute(
        """
        SELECT
            c.command_id,
            c.timestamp,
            c.raw_input,
            c.parsed_command,
            c.response_type,
            t.threat_id,
            t.threat_type,
            t.severity,
            t.confidence,
            t.source,
            t.experiment_type,
            cr.experiment_id,
            cr.result,
            cr.cpu_peak,
            cr.memory_peak,
            cr.recovery_time_secs,
            cr.intensity_level,
            cr.experiment_type
        FROM commands c
        LEFT JOIN threats t ON t.command_id = c.command_id
        LEFT JOIN chaos_results cr
          ON cr.threat_id = t.threat_id
         AND cr.experiment_id = (
             SELECT MAX(cr2.experiment_id)
             FROM chaos_results cr2
             WHERE cr2.threat_id = t.threat_id
         )
        WHERE c.session_id = ?
        ORDER BY c.timestamp ASC
        """,
        params=(session_id,), fetch=True
    )

    commands = []
    resilient_count = 0
    vulnerable_count = 0
    threat_types_seen = set()

    for r in (rows or []):
        chaos_result = r[12]
        if chaos_result == "Vulnerable":
            vulnerable_count += 1
        elif chaos_result == "Resilient":
            resilient_count += 1
        threat_type = r[6] or "None"
        if threat_type != "None":
            threat_types_seen.add(threat_type)
        commands.append({
            "command_id": r[0],
            "timestamp": r[1],
            "raw_input": r[2] or "",
            "parsed_command": r[3] or "",
            "response_type": r[4] or "unknown",
            "threat_id": r[5],
            "threat_type": threat_type,
            "severity": r[7] or "None",
            "confidence": round(float(r[8] or 0.0), 2),
            "source": r[9] or "",
            "experiment_type": r[17] or r[10] or "",
            "experiment_id": r[11],
            "chaos_result": chaos_result or "",
            "cpu_peak": round(float(r[13] or 0.0), 2),
            "memory_peak": round(float(r[14] or 0.0), 2),
            "recovery_time_secs": round(float(r[15] or 0.0), 2),
            "intensity_level": r[16],
        })

    # Determine overall session verdict
    if vulnerable_count > 0:
        verdict = "Suspicious"
    elif any(c["threat_type"] != "None" for c in commands):
        verdict = "Monitored"
    else:
        verdict = "Normal"

    return {
        "session": session_info,
        "commands": commands,
        "summary": {
            "total_commands": len(commands),
            "resilient_count": resilient_count,
            "vulnerable_count": vulnerable_count,
            "threat_types": sorted(threat_types_seen),
            "verdict": verdict,
        }
    }


@app.get("/api/session_activity")
def get_session_activity():
    rows = safe_execute(
        """
        SELECT
            c.command_id,
            c.session_id,
            c.timestamp,
            c.raw_input,
            c.parsed_command,
            c.response_type,
            t.threat_id,
            t.threat_type,
            t.severity,
            t.confidence,
            t.source,
            t.experiment_type,
            cr.experiment_id,
            cr.result,
            cr.recovery_time_secs,
            cr.intensity_level
        FROM commands c
        LEFT JOIN threats t ON t.command_id = c.command_id
        LEFT JOIN chaos_results cr
          ON cr.threat_id = t.threat_id
         AND cr.experiment_id = (
             SELECT MAX(cr2.experiment_id)
             FROM chaos_results cr2
             WHERE cr2.threat_id = t.threat_id
         )
        ORDER BY c.timestamp DESC
        LIMIT 500
        """,
        fetch=True,
    )
    return [
        {
            "command_id": r[0],
            "session_id": r[1],
            "timestamp": r[2],
            "raw_input": r[3] or "",
            "parsed_command": r[4] or "",
            "response_type": r[5] or "unknown",
            "threat_id": r[6],
            "threat_type": r[7] or "None",
            "severity": r[8] or "",
            "confidence": float(r[9] or 0.0),
            "source": r[10] or "",
            "experiment_type": r[11] or "",
            "experiment_id": r[12],
            "result": r[13] or "",
            "recovery_time_secs": r[14],
            "intensity_level": r[15],
        }
        for r in (rows or [])
    ]


@app.get("/api/threats")
def get_threats():
    rows = safe_execute("""
    SELECT t.threat_id, t.session_id, c.raw_input, t.threat_type, t.severity, t.confidence, t.source, t.experiment_type, t.timestamp
    FROM threats t
    JOIN commands c ON t.command_id = c.command_id
    ORDER BY t.timestamp DESC LIMIT 50
    """, fetch=True)
    return [{
        "threat_id": r[0],
        "session_id": r[1],
        "raw_input": r[2],
        "threat_type": r[3],
        "severity": r[4],
        "confidence": r[5],
        "source": r[6],
        "experiment_type": r[7],
        "mapped_experiment_type": get_experiment_type(r[3]),
        "timestamp": r[8],
    } for r in rows] if rows else []

@app.get("/api/chaos_analytics")
def get_chaos():
    rows = safe_execute("""
    SELECT
        cr.experiment_id, cr.threat_id, cr.experiment_type, cr.intensity_level,
        cr.result, cr.cpu_peak, cr.recovery_time_secs, cr.started_at, cr.is_retest, cr.notes,
        t.threat_type, t.severity, c.raw_input
    FROM chaos_results cr
    LEFT JOIN threats t ON t.threat_id = cr.threat_id
    LEFT JOIN commands c ON c.command_id = t.command_id
    ORDER BY cr.started_at DESC
    LIMIT 80
    """, fetch=True)
    data = []
    for r in (rows or []):
        parsed = _parse_notes(r[9] or "")
        data.append({
            "experiment_id": r[0],
            "threat_id": r[1],
            "experiment_type": r[2],
            "intensity_level": r[3],
            "result": r[4],
            "cpu_peak": r[5],
            "recovery_time_secs": r[6],
            "started_at": r[7],
            "is_retest": r[8],
            "notes": r[9] or "",
            "threat_type": r[10] or "Unknown",
            "severity": r[11] or "Low",
            "raw_input": r[12] or "",
            "metric_source": parsed["metric_source"],
            "target_service": parsed["target_service"],
            "service_down_time": parsed["service_down_time"],
            "restart_attempts": parsed["restart_attempts"],
            "cpu_variant": parsed["cpu_variant"],
            "variant_combination": parsed["variant_combination"],
            "baseline_cpu": parsed["baseline_cpu"],
            "baseline_mem": parsed["baseline_mem"],
            "cpu_normalized_secs": parsed["cpu_normalized_secs"],
            "mem_stabilized_secs": parsed["mem_stabilized_secs"],
            "cpu_limit": parsed["cpu_limit"],
            "mem_limit": parsed["mem_limit"],
        })
    return data


@app.get("/api/vulnerability_metrics")
def get_vulnerability_metrics():
    rows = safe_execute(
        """
        SELECT threat_type, total_runs, total_failures, failure_rate, risk_score
        FROM v_vulnerability_metrics
        ORDER BY risk_score DESC, total_runs DESC
        LIMIT 50
        """,
        fetch=True,
    )
    return [
        {
            "threat_type": r[0],
            "total_runs": r[1],
            "total_failures": r[2],
            "failure_rate": round(float(r[3] or 0.0), 2),
            "risk_score": round(float(r[4] or 0.0), 2),
        }
        for r in rows
    ] if rows else []


@app.get("/api/learning_insights")
def get_learning_insights():
    rows = safe_execute(
        """
        SELECT
            t.threat_type,
            cr.experiment_type,
            cr.intensity_level,
            cr.duration_secs,
            cr.result,
            cr.recovery_time_secs,
            cr.cpu_peak,
            cr.notes,
            cr.started_at
        FROM chaos_results cr
        JOIN threats t ON t.threat_id = cr.threat_id
        ORDER BY cr.started_at DESC
        LIMIT 500
        """,
        fetch=True,
    ) or []

    by_threat = {}
    by_config = {}

    for r in rows:
        threat_type = r[0] or "Unknown"
        experiment_type = r[1] or "unknown"
        intensity = int(r[2] or 1)
        duration = int(r[3] or 0)
        result = r[4] or "Resilient"
        recovery = _to_float(r[5], 0.0)
        cpu_peak = _to_float(r[6], 0.0)
        notes = r[7] or ""
        started_at = r[8]
        parsed = _parse_notes(notes)
        metric_source = parsed["metric_source"] or "unknown"
        if metric_source == "unknown" or cpu_peak <= 0.0:
            continue

        score = parsed["score"]
        if score is None:
            score = recovery + (10.0 if result == "Vulnerable" else 0.0)
        instability = parsed["instability_score"] or 0.0
        degrading = bool(parsed["degrading"])
        variant = parsed["cpu_variant"] or ""
        normalized_recovery = parsed["normalized_recovery"]
        if normalized_recovery is None:
            normalized_recovery = recovery / max(1, intensity)

        item = {
            "experiment_type": experiment_type,
            "intensity": intensity,
            "duration": duration,
            "variant": variant,
            "result": result,
            "score": score,
            "recovery_time": recovery,
            "normalized_recovery": normalized_recovery,
            "instability": instability,
            "degrading": degrading,
            "started_at": started_at,
            "settings": {
                "threads": parsed["threads"],
                "memory_mb": parsed["memory_mb"],
                "disk_intensity": parsed["disk_intensity"],
                "forks": parsed["forks"],
                "target_service": parsed["target_service"],
                "variant_combination": parsed["variant_combination"],
            },
        }
        by_threat.setdefault(threat_type, []).append(item)

        key = (threat_type, experiment_type, intensity, duration, variant)
        by_config.setdefault(key, []).append(item)

    report = []
    for threat_type, runs in by_threat.items():
        if not runs:
            continue
        best = min(runs, key=lambda x: x["score"])
        worst = max(runs, key=lambda x: x["score"])
        vuln_intensities = [x["intensity"] for x in runs if x["result"] == "Vulnerable"]
        threshold = min(vuln_intensities) if vuln_intensities else None
        unstable = [x for x in runs if x["degrading"] or x["instability"] >= 0.5]
        unstable_patterns = sorted({
            f"{x['experiment_type']}:Lv{x['intensity']}{':' + x['variant'] if x['variant'] else ''}"
            for x in unstable
        })
        report.append(
            {
                "threat_type": threat_type,
                "runs": len(runs),
                "best_config": {
                    "type": best["experiment_type"],
                    "intensity": best["intensity"],
                    "duration": best["duration"],
                    "variant": best["variant"],
                    "score": round(best["score"], 3),
                    "settings": best.get("settings", {}),
                },
                "worst_config": {
                    "type": worst["experiment_type"],
                    "intensity": worst["intensity"],
                    "duration": worst["duration"],
                    "variant": worst["variant"],
                    "score": round(worst["score"], 3),
                    "settings": worst.get("settings", {}),
                },
                "threshold": threshold,
                "unstable_patterns": unstable_patterns[:6],
                "degrading_runs": sum(1 for x in runs if x["degrading"]),
                "max_instability": round(max((x["instability"] for x in runs), default=0.0), 3),
            }
        )

    config_memory = []
    for key, runs in by_config.items():
        threat_type, experiment_type, intensity, duration, variant = key
        ordered = sorted(runs, key=lambda x: x["started_at"], reverse=True)
        last3 = ordered[:3]
        last3_scores = [round(x["score"], 3) for x in last3]
        avg_score = sum(x["score"] for x in runs) / len(runs)
        trend = "stable"
        if len(last3) >= 2:
            if last3[0]["score"] > last3[-1]["score"] + 0.2:
                trend = "degrading"
            elif last3[0]["score"] + 0.2 < last3[-1]["score"]:
                trend = "improving"
        config_memory.append(
            {
                "threat_type": threat_type,
                "experiment_type": experiment_type,
                "intensity": intensity,
                "duration": duration,
                "variant": variant,
                "runs": len(runs),
                "avg_score": round(avg_score, 3),
                "last3_scores": last3_scores,
                "trend": trend,
            }
        )

    report.sort(key=lambda x: (-x["max_instability"], -x["degrading_runs"], x["threat_type"]))
    config_memory.sort(key=lambda x: (x["avg_score"], -x["runs"]))
    return {"report": report, "config_memory": config_memory[:20]}


@app.get("/api/critical_threats")
def get_critical_threats():
    rows = safe_execute(
        """
        SELECT
            cr.experiment_id, cr.threat_id, t.threat_type, cr.experiment_type, cr.intensity_level,
            cr.result, cr.recovery_time_secs, c.raw_input, cr.started_at
        FROM chaos_results cr
        JOIN threats t ON t.threat_id = cr.threat_id
        LEFT JOIN commands c ON c.command_id = t.command_id
        WHERE cr.result = 'Vulnerable'
          AND cr.intensity_level >= 6
        ORDER BY cr.started_at DESC
        LIMIT 20
        """,
        fetch=True,
    )
    return [
        {
            "experiment_id": r[0],
            "threat_id": r[1],
            "threat_type": r[2],
            "experiment_type": r[3],
            "intensity_level": r[4],
            "result": r[5],
            "recovery_time_secs": r[6],
            "raw_input": r[7] or "",
            "started_at": r[8],
        }
        for r in (rows or [])
    ]
