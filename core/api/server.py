from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.database.db_client import safe_execute
from core.chaos.threat_map import get_experiment_type
import os
import json

try:
    from openai import OpenAI
except Exception:
    OpenAI = None

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
        "defense_action": "",
        "outcome_state": "",
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
        elif key == "DefenseAction":
            parsed["defense_action"] = value
        elif key == "OutcomeState":
            parsed["outcome_state"] = value
    return parsed


def _pick_defense_action_from_timeline_row(row) -> str:
    # row shape for session timeline:
    # (..., notes, fallback_defense_action)
    parsed = _parse_notes(row[11] or "")
    if parsed.get("defense_action"):
        return parsed["defense_action"]
    return row[12] or "no_action"

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
    rows = safe_execute(
        """
        SELECT
            s.session_id,
            s.source_ip,
            s.start_time,
            s.duration_secs,
            s.total_commands,
            s.status,
            COALESCE((
                SELECT t2.threat_type
                FROM threats t2
                WHERE t2.session_id = s.session_id
                GROUP BY t2.threat_type
                ORDER BY COUNT(*) DESC, t2.threat_type
                LIMIT 1
            ), 'None') AS top_threat,
            COALESCE((
                SELECT ROUND(AVG(CASE WHEN cr.result = 'Vulnerable' THEN 1.0 ELSE 0.0 END), 3)
                FROM threats t3
                JOIN chaos_results cr ON cr.threat_id = t3.threat_id
                WHERE t3.session_id = s.session_id
            ), 0.0) AS failure_rate
        FROM sessions s
        ORDER BY s.start_time DESC
        LIMIT 100
        """,
        fetch=True,
    )
    return [
        {
            "session_id": r[0],
            "source_ip": r[1],
            "start_time": r[2],
            "duration_secs": r[3],
            "total_commands": r[4],
            "status": r[5],
            "top_threat": r[6] or "None",
            "failure_rate": float(r[7] or 0.0),
        }
        for r in (rows or [])
    ]


@app.get("/api/session/{session_id}")
def get_session_timeline(session_id: str):
    rows = safe_execute(
        """
        SELECT
            c.command_id,
            c.raw_input,
            c.timestamp,
            t.threat_id,
            t.threat_type,
            t.severity,
            cr.experiment_type,
            cr.intensity_level,
            cr.duration_secs,
            cr.recovery_time_secs,
            cr.result,
            cr.notes,
            COALESCE((
                SELECT adr.defense_action
                FROM adaptive_defense_runs adr
                WHERE adr.threat_type = t.threat_type
                  AND adr.experiment_type = cr.experiment_type
                  AND adr.intensity_level = cr.intensity_level
                  AND adr.duration_secs = cr.duration_secs
                ORDER BY adr.run_id DESC
                LIMIT 1
            ), 'no_action') AS fallback_defense_action
        FROM commands c
        LEFT JOIN threats t ON t.command_id = c.command_id
        LEFT JOIN chaos_results cr ON cr.threat_id = t.threat_id
        WHERE c.session_id = ?
        ORDER BY c.timestamp ASC, cr.experiment_id ASC
        """,
        (session_id,),
        fetch=True,
    ) or []

    timeline = []
    for r in rows:
        timeline.append(
            {
                "command_id": r[0],
                "command": r[1] or "",
                "timestamp": r[2],
                "threat_id": r[3],
                "threat_type": r[4] or "Unknown",
                "severity": r[5] or "Low",
                "experiment_type": r[6] or "",
                "intensity": int(r[7] or 0),
                "duration_secs": int(r[8] or 0),
                "recovery_time_secs": _to_float(r[9], 0.0),
                "result": r[10] or "",
                "defense_action": _pick_defense_action_from_timeline_row(r),
                "outcome_state": (_parse_notes(r[11] or "").get("outcome_state") or r[10] or "Resilient"),
            }
        )
    return timeline


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
            "defense_action": parsed["defense_action"] or "no_action",
            "outcome_state": parsed["outcome_state"] or r[4] or "Resilient",
        })
    return data


@app.get("/api/attack_behavior_insights")
def get_attack_behavior_insights():
    top_commands_rows = safe_execute(
        """
        SELECT raw_input, COUNT(*) AS cnt
        FROM commands
        WHERE TRIM(raw_input) <> ''
        GROUP BY raw_input
        ORDER BY cnt DESC, raw_input
        LIMIT 15
        """,
        fetch=True,
    ) or []

    top_threat_rows = safe_execute(
        """
        SELECT threat_type, COUNT(*) AS cnt
        FROM threats
        GROUP BY threat_type
        ORDER BY cnt DESC, threat_type
        LIMIT 15
        """,
        fetch=True,
    ) or []

    experiment_rows = safe_execute(
        """
        SELECT experiment_type, COUNT(*) AS cnt
        FROM chaos_results
        GROUP BY experiment_type
        ORDER BY cnt DESC, experiment_type
        LIMIT 15
        """,
        fetch=True,
    ) or []

    return {
        "top_commands": [{"command": r[0] or "", "count": int(r[1] or 0)} for r in top_commands_rows],
        "top_threat_types": [{"threat_type": r[0] or "Unknown", "count": int(r[1] or 0)} for r in top_threat_rows],
        "top_experiment_types": [{"experiment_type": r[0] or "unknown", "count": int(r[1] or 0)} for r in experiment_rows],
    }


@app.get("/api/malicious_activity")
def get_malicious_activity():
    rows = safe_execute(
        """
        SELECT category, command, COUNT(*) AS cnt
        FROM (
            SELECT 'Sensitive Access' AS category, raw_input AS command
            FROM commands
            WHERE lower(raw_input) LIKE '%cat %'
               OR lower(raw_input) LIKE '%/etc%'
               OR lower(raw_input) LIKE '%password%'
            UNION ALL
            SELECT 'Downloads' AS category, raw_input AS command
            FROM commands
            WHERE lower(raw_input) LIKE '%wget%'
               OR lower(raw_input) LIKE '%curl%'
            UNION ALL
            SELECT 'Execution' AS category, raw_input AS command
            FROM commands
            WHERE lower(raw_input) LIKE '%chmod%'
               OR lower(raw_input) LIKE '%.sh%'
               OR lower(raw_input) LIKE './%'
               OR lower(raw_input) LIKE 'bash %'
               OR lower(raw_input) LIKE 'sh %'
        ) x
        GROUP BY category, command
        ORDER BY cnt DESC, command
        LIMIT 40
        """,
        fetch=True,
    ) or []
    return [{"category": r[0], "command": r[1], "count": int(r[2] or 0)} for r in rows]


@app.get("/api/learning_transparency")
def get_learning_transparency():
    rows = safe_execute(
        """
        SELECT defense_action, ROUND(AVG(score), 3) AS avg_score, COUNT(*) AS runs
        FROM adaptive_defense_runs
        GROUP BY defense_action
        ORDER BY avg_score ASC, runs DESC
        """,
        fetch=True,
    ) or []
    return [{"defense_action": r[0] or "no_action", "avg_score": float(r[1] or 0.0), "runs": int(r[2] or 0)} for r in rows]


def _heuristic_session_analysis(commands, threats, chaos_rows):
    top_threat = "Unknown"
    if threats:
        counts = {}
        for t in threats:
            tt = t.get("threat_type", "Unknown")
            counts[tt] = counts.get(tt, 0) + 1
        top_threat = sorted(counts.items(), key=lambda x: x[1], reverse=True)[0][0]
    vuln = sum(1 for x in chaos_rows if (x.get("result") or "") == "Vulnerable")
    total = max(1, len(chaos_rows))
    fail_pct = round((vuln / total) * 100, 1)
    pattern = f"Session shows repeated {top_threat.replace('_', ' ')} activity with {fail_pct}% vulnerable outcomes."
    intent = "Likely resource exhaustion / service disruption probing." if "Exhaustion" in top_threat or "Privilege" in top_threat else "Likely reconnaissance or capability testing."
    weakness = "Adaptive defenses are still not reducing failure rate consistently."
    recommendation = "Prioritize actions with lower defense score, increase pre-emptive limits, and isolate high-risk command patterns."
    return {
        "attack_pattern": pattern,
        "attacker_intent": intent,
        "system_weakness": weakness,
        "recommendation": recommendation,
    }


@app.post("/api/session_analysis/{session_id}")
def post_session_analysis(session_id: str):
    command_rows = safe_execute(
        """
        SELECT command_id, raw_input, timestamp
        FROM commands
        WHERE session_id = ?
        ORDER BY timestamp ASC
        LIMIT 200
        """,
        (session_id,),
        fetch=True,
    ) or []
    threat_rows = safe_execute(
        """
        SELECT t.threat_id, t.threat_type, t.severity, t.confidence, t.source
        FROM threats t
        WHERE t.session_id = ?
        ORDER BY t.timestamp ASC
        LIMIT 200
        """,
        (session_id,),
        fetch=True,
    ) or []
    chaos_rows = safe_execute(
        """
        SELECT cr.experiment_type, cr.intensity_level, cr.recovery_time_secs, cr.result
        FROM chaos_results cr
        JOIN threats t ON t.threat_id = cr.threat_id
        WHERE t.session_id = ?
        ORDER BY cr.started_at ASC
        LIMIT 300
        """,
        (session_id,),
        fetch=True,
    ) or []

    commands = [{"command_id": r[0], "raw_input": r[1] or "", "timestamp": r[2]} for r in command_rows]
    threats = [{"threat_id": r[0], "threat_type": r[1] or "Unknown", "severity": r[2] or "Low", "confidence": float(r[3] or 0.0), "source": r[4] or "rule"} for r in threat_rows]
    chaos = [{"experiment_type": r[0] or "", "intensity_level": int(r[1] or 0), "recovery_time_secs": _to_float(r[2], 0.0), "result": r[3] or ""} for r in chaos_rows]

    # AI optional: use Groq OpenAI-compatible endpoint if key exists.
    api_key = os.environ.get("GROK_API_KEY", "")
    if not api_key or OpenAI is None:
        return _heuristic_session_analysis(commands, threats, chaos)

    summary_payload = {
        "commands": [c["raw_input"] for c in commands[:40]],
        "threats": threats[:40],
        "chaos": chaos[:60],
    }
    prompt = (
        "Analyze this honeypot session and return JSON with keys: "
        "attack_pattern, attacker_intent, system_weakness, recommendation.\n"
        f"Session data:\n{json.dumps(summary_payload)}"
    )
    try:
        client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1", timeout=8)
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a SOC analyst. Return compact JSON only."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=260,
            temperature=0.2,
            response_format={"type": "json_object"},
        )
        text = (resp.choices[0].message.content or "").strip()
        parsed = json.loads(text)
        return {
            "attack_pattern": str(parsed.get("attack_pattern", "")),
            "attacker_intent": str(parsed.get("attacker_intent", "")),
            "system_weakness": str(parsed.get("system_weakness", "")),
            "recommendation": str(parsed.get("recommendation", "")),
        }
    except Exception:
        return _heuristic_session_analysis(commands, threats, chaos)


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


@app.get("/api/defense_learning")
def get_defense_learning():
    action_rows = safe_execute(
        """
        SELECT
            threat_type,
            defense_action,
            COUNT(*) as runs,
            ROUND(AVG(score), 3) as avg_score,
            ROUND(AVG(recovery_time_secs), 3) as avg_recovery,
            ROUND(AVG(CASE WHEN result='Vulnerable' THEN 1.0 ELSE 0.0 END), 3) as fail_rate
        FROM adaptive_defense_runs
        GROUP BY threat_type, defense_action
        ORDER BY threat_type ASC, avg_score ASC
        """,
        fetch=True,
    ) or []

    by_threat = {}
    for r in action_rows:
        threat = r[0] or "Unknown"
        by_threat.setdefault(threat, []).append(
            {
                "action": r[1] or "no_action",
                "runs": int(r[2] or 0),
                "avg_score": float(r[3] or 0.0),
                "avg_recovery": float(r[4] or 0.0),
                "fail_rate": float(r[5] or 0.0),
            }
        )

    summary = []
    for threat, actions in by_threat.items():
        ranked = sorted(actions, key=lambda x: x["avg_score"])
        decision_reason = "No action history yet."
        if ranked:
            best = ranked[0]
            decision_reason = (
                f"Selected {best['action']} because it has the lowest avg score "
                f"({round(float(best['avg_score']), 2)}) over {int(best['runs'])} run(s)."
            )
        summary.append(
            {
                "threat_type": threat,
                "best_action": ranked[0] if ranked else None,
                "actions": ranked,
                "decision_reason": decision_reason,
            }
        )

    recent_rows = safe_execute(
        """
        SELECT
            run_id, threat_type, experiment_type, intensity_level, duration_secs, variant,
            defense_action, recovery_time_secs, result, score, created_at
        FROM adaptive_defense_runs
        ORDER BY run_id DESC
        LIMIT 40
        """,
        fetch=True,
    ) or []

    recent = [
        {
            "run_id": r[0],
            "threat_type": r[1] or "Unknown",
            "experiment_type": r[2] or "cpu_stress",
            "intensity_level": int(r[3] or 1),
            "duration_secs": int(r[4] or 0),
            "variant": r[5] or "",
            "defense_action": r[6] or "no_action",
            "recovery_time_secs": float(r[7] or 0.0),
            "result": r[8] or "Resilient",
            "score": float(r[9] or 0.0),
            "created_at": r[10],
        }
        for r in recent_rows
    ]
    return {"summary": summary, "recent": recent}


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
