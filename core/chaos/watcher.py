"""
Chaos Watcher — Chaos Validation Engine

Orchestrates experiment discovery, execution, adaptive updates, and
cross-session learning with structured JSON logs.
"""

import json
import logging
import threading
import time
from datetime import datetime, timezone

from core.adaptive.escalation import (
    check_and_reset_scaling,
    get_adaptive_state,
    mark_weakness,
    simulate_scaling,
    update_prediction_metrics,
    update_session_metrics,
)
from core.chaos.experiments import (
    DEFAULT_SAFE_CONFIG,
    MAX_DURATION_SECS,
    MAX_INTENSITY,
    run_experiment,
    validate_experiment_config,
)
from core.chaos.threat_map import get_experiment_type, get_rule_based_experiment
from core.database.db_client import get_connection, safe_execute
from core.database.queries import get_threat_prediction, upsert_global_threat_stats
from core.intelligence.ai_classifier import generate_experiment_with_ai

logger = logging.getLogger(__name__)

POLL_INTERVAL = 5
DEBOUNCE_WINDOW_SECS = 2
last_processed_time = {}


def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _log_event(event, **payload):
    logger.info(json.dumps({"event": event, **payload, "timestamp": _utc_now_iso()}))


def _fetch_unprocessed_threats():
    rows = safe_execute(
        """
        SELECT
            t.threat_id,
            t.session_id,
            t.threat_type,
            t.severity,
            t.experiment_type,
            t.experiment_intensity,
            t.experiment_duration,
            c.raw_input
        FROM threats t
        LEFT JOIN commands c ON c.command_id = t.command_id
        WHERE t.processed = 0
        ORDER BY t.timestamp ASC
        """,
        fetch=True,
    )
    return rows or []


def _insert_chaos_result(threat_id: int, metrics: dict, is_retest: bool = False):
    conn = get_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO chaos_results (
                    threat_id, experiment_type, intensity_level,
                    cpu_peak, memory_peak, disk_io_peak,
                    duration_secs, recovery_time_secs, result,
                    started_at, completed_at, notes, is_retest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    threat_id,
                    metrics.get("experiment_type", "cpu_stress"),
                    metrics.get("intensity_level", 1),
                    metrics.get("cpu_peak", 0.0),
                    metrics.get("memory_peak", 0.0),
                    metrics.get("disk_io_peak", 0.0),
                    metrics.get("duration_secs", 0),
                    metrics.get("recovery_time_secs", 0.0),
                    metrics.get("result", "Resilient"),
                    _utc_now_iso(),
                    _utc_now_iso(),
                    metrics.get("notes", ""),
                    1 if is_retest else 0,
                ),
            )
    finally:
        conn.close()


def _mark_threat_processed(threat_id: int):
    safe_execute("UPDATE threats SET processed = 1 WHERE threat_id = ?", (threat_id,))


def _should_debounce(threat_type: str) -> bool:
    now = datetime.now(timezone.utc)
    stale_keys = [key for key, seen in last_processed_time.items() if (now - seen).total_seconds() > 60]
    for key in stale_keys:
        last_processed_time.pop(key, None)
    last_seen = last_processed_time.get(threat_type)
    if last_seen and (now - last_seen).total_seconds() < DEBOUNCE_WINDOW_SECS:
        return True
    last_processed_time[threat_type] = now
    return False


def _has_non_generic_db_experiment(db_exp_type, db_exp_int, db_exp_dur):
    if not db_exp_type:
        return False
    if db_exp_int is None or db_exp_dur is None:
        return False
    try:
        db_exp_int = int(db_exp_int)
        db_exp_dur = int(db_exp_dur)
    except (TypeError, ValueError):
        return False
    generic = (
        db_exp_type == DEFAULT_SAFE_CONFIG["type"]
        and db_exp_int == DEFAULT_SAFE_CONFIG["intensity"]
        and db_exp_dur == 10
    )
    return not generic


def _apply_adaptive_overrides(config: dict, historical_failure_rate: float):
    updated = dict(config)
    was_adapted = False
    if historical_failure_rate >= 0.6:
        updated["intensity"] = min(MAX_INTENSITY, int(updated.get("intensity", 1)) + 1)
        updated["duration"] = min(MAX_DURATION_SECS, int(updated.get("duration", 5)) + 5)
        was_adapted = True
    return validate_experiment_config(updated), was_adapted


def _resolve_experiment_config(threat_type, severity, command, db_exp_type, db_exp_int, db_exp_dur):
    source = "rule"
    config = {
        "type": db_exp_type,
        "intensity": db_exp_int,
        "duration": db_exp_dur,
    }

    if _has_non_generic_db_experiment(db_exp_type, db_exp_int, db_exp_dur):
        source = "db"
    else:
        config = get_rule_based_experiment(threat_type, severity)

    if source == "rule" and config.get("confidence", 0.0) < 0.9:
        ai_config = generate_experiment_with_ai(threat_type, severity, command)
        if ai_config:
            config = ai_config
            source = "ai"

    validated = validate_experiment_config(config)
    expected_type = get_experiment_type(threat_type)
    if validated.get("type") != expected_type:
        validated["type"] = expected_type
        source = "mapped"

    return validate_experiment_config(validated), source


def _build_retest_config(base_config: dict):
    retest_candidate = {
        "type": base_config.get("type", DEFAULT_SAFE_CONFIG["type"]),
        "intensity": min(MAX_INTENSITY, int(base_config.get("intensity", 1)) + 1),
        "duration": min(MAX_DURATION_SECS, int(base_config.get("duration", 5)) + 5),
    }
    return validate_experiment_config(retest_candidate)


def _watcher_loop():
    _log_event("watcher_started", command="", threat_type="", source="watcher", risk_score=0.0)

    while True:
        try:
            for row in _fetch_unprocessed_threats():
                threat_id = row[0]
                session_id = row[1]
                threat_type = row[2]
                severity = row[3]
                db_exp_type = row[4]
                db_exp_int = row[5]
                db_exp_dur = row[6]
                command = row[7] or ""

                if _should_debounce(threat_type):
                    continue

                check_and_reset_scaling(session_id, threat_type)
                config, source = _resolve_experiment_config(
                    threat_type,
                    severity,
                    command,
                    db_exp_type,
                    db_exp_int,
                    db_exp_dur,
                )
                prior_stats = get_threat_prediction(threat_type)
                config, adapted = _apply_adaptive_overrides(config, prior_stats["failure_rate"])

                adaptive_state = get_adaptive_state(session_id, threat_type)
                is_scaled = adaptive_state["is_scaled"]

                logger.info(
                    json.dumps(
                        {
                            "event": "experiment_start",
                            "command": command,
                            "threat_type": threat_type,
                            "source": "adaptive" if adapted else source,
                            "risk_score": adaptive_state["predicted_risk_score"],
                            "experiment_type": config["type"],
                            "experiment_intensity": config["intensity"],
                            "experiment_duration": config["duration"],
                            "scaled": is_scaled,
                            "timestamp": _utc_now_iso(),
                        }
                    )
                )
                metrics = run_experiment(
                    config["type"],
                    config["duration"],
                    config["intensity"],
                    is_scaled,
                )
                _insert_chaos_result(threat_id, metrics)

                is_failure = metrics.get("result") == "Vulnerable"
                update_session_metrics(session_id, threat_type, is_failure)
                upsert_global_threat_stats(threat_type, is_failure, config["intensity"])

                stats = get_threat_prediction(threat_type)
                update_prediction_metrics(session_id, threat_type, stats["failure_rate"], stats["risk_score"])

                latest_state = get_adaptive_state(session_id, threat_type)
                scaled_now = False
                if latest_state["total_runs"] >= 5 and stats["failure_rate"] >= 0.6:
                    scaled_now = simulate_scaling(session_id, threat_type)
                    if scaled_now:
                        _log_event("scaling_triggered", command=command, threat_type=threat_type, source="adaptive", risk_score=stats["risk_score"])
                        latest_state = get_adaptive_state(session_id, threat_type)

                if stats["failure_rate"] >= 0.6:
                    mark_weakness(session_id, threat_type)

                # Optional adaptive re-test: when first run is vulnerable, rerun once
                # with stronger config and scaled resources to capture before/after proof.
                if metrics.get("result") == "Vulnerable":
                    retest_config = _build_retest_config(config)
                    _log_event(
                        "retest_start",
                        command=command,
                        threat_type=threat_type,
                        source="adaptive",
                        risk_score=stats["risk_score"],
                        experiment_type=retest_config["type"],
                        experiment_intensity=retest_config["intensity"],
                        experiment_duration=retest_config["duration"],
                    )
                    retest_metrics = run_experiment(
                        retest_config["type"],
                        retest_config["duration"],
                        retest_config["intensity"],
                        True,  # simulate protection/scaling on re-test
                    )
                    _insert_chaos_result(threat_id, retest_metrics, is_retest=True)
                    _log_event(
                        "retest_complete",
                        command=command,
                        threat_type=threat_type,
                        source="adaptive",
                        risk_score=stats["risk_score"],
                        result=retest_metrics.get("result", "Resilient"),
                        scaled=True,
                    )

                _log_event(
                    "experiment_complete",
                    command=command,
                    threat_type=threat_type,
                    source="adaptive" if adapted else source,
                    risk_score=stats["risk_score"],
                    result=metrics.get("result", "Resilient"),
                    failure_rate=stats["failure_rate"],
                    scaled=latest_state["is_scaled"],
                )
                _mark_threat_processed(threat_id)
        except Exception as exc:
            logger.error(json.dumps({"event": "watcher_error", "command": "", "threat_type": "", "source": "watcher", "risk_score": 0.0, "error": str(exc)}), exc_info=True)

        time.sleep(POLL_INTERVAL)


def start_chaos_watcher():
    thread = threading.Thread(target=_watcher_loop, name="ChaosWatcher", daemon=True)
    thread.start()
    return thread
