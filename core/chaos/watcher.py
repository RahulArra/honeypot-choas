"""
Chaos Watcher — Chaos Validation Engine

Orchestrates experiment discovery, execution, adaptive updates, and
cross-session learning with structured JSON logs.
"""

import json
import logging
import random
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
    DEFENSE_ACTIONS,
    CPU_VARIANTS,
    DEFAULT_SAFE_CONFIG,
    MAX_DURATION_SECS,
    MAX_INTENSITY,
    SAFE_MODE,
    run_experiment,
    validate_experiment_config,
)
from core.chaos.threat_map import get_experiment_type, get_rule_based_experiment
from core.database.db_client import get_connection, safe_execute
from core.database.queries import (
    get_defense_action_avg_scores,
    get_threat_prediction,
    insert_adaptive_defense_run,
    upsert_global_threat_stats,
)
from core.intelligence.ai_classifier import generate_experiment_with_ai

logger = logging.getLogger(__name__)

POLL_INTERVAL = 5
DEBOUNCE_WINDOW_SECS = 2
COMMAND_DEDUPE_WINDOW_SECS = 5
EXPLORATION_DURATION_STEP = 30
DEFENSE_EXPLORATION_PROB = 0.05
DEFENSE_MIN_TRIES_PER_ACTION = 2
DEFENSE_BOOTSTRAP_RUNS = 5
NO_ACTION_PENALTY = 2.0
last_processed_time = {}
last_processed_command_time = {}
best_config_by_threat = {}


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


def _should_skip_duplicate_command(command: str) -> bool:
    now = datetime.now(timezone.utc)
    normalized = " ".join((command or "").strip().lower().split())
    if not normalized:
        return False

    stale_keys = [key for key, seen in last_processed_command_time.items() if (now - seen).total_seconds() > 60]
    for key in stale_keys:
        last_processed_command_time.pop(key, None)

    last_seen = last_processed_command_time.get(normalized)
    if last_seen and (now - last_seen).total_seconds() < COMMAND_DEDUPE_WINDOW_SECS:
        return True
    last_processed_command_time[normalized] = now
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


def _fetch_threat_history(threat_type: str, limit: int = 30):
    rows = safe_execute(
        """
        SELECT cr.intensity_level, cr.duration_secs, cr.result, cr.recovery_time_secs, cr.notes, cr.cpu_peak, cr.started_at
        FROM chaos_results cr
        JOIN threats t ON t.threat_id = cr.threat_id
        WHERE t.threat_type = ?
        ORDER BY cr.started_at DESC
        LIMIT ?
        """,
        (threat_type, limit),
        fetch=True,
    )
    history = []
    for r in (rows or []):
        metric_source = _extract_note_value(r[4], "MetricSource") or "unknown"
        variant = _extract_note_value(r[4], "CpuVariant") or ""
        recovery = float(r[3] or 0.0)
        intensity = int(r[0] or 1)
        result = str(r[2] or "")
        score = recovery + (10.0 if result == "Vulnerable" else 0.0)
        normalized_recovery = recovery / max(1, intensity)
        history.append(
            {
                "intensity": intensity,
                "duration": int(r[1] or 5),
                "result": result,
                "recovery": recovery,
                "normalized_recovery": normalized_recovery,
                "score": score,
                "variant": variant,
                "metric_source": metric_source,
                "cpu_peak": float(r[5] or 0.0),
                "started_at": r[6] or "",
            }
        )
    return history


def _is_valid_metrics(metrics: dict) -> bool:
    cpu_peak = float(metrics.get("cpu_peak", 0.0) or 0.0)
    metric_source = str(metrics.get("metric_source", "unknown") or "unknown")
    return cpu_peak > 0.0 and metric_source != "unknown"


def _config_key(config: dict, cpu_variant: str) -> tuple:
    return (
        str(config.get("type", "")),
        int(config.get("intensity", 1)),
        int(config.get("duration", 5)),
        (cpu_variant or "").strip().lower(),
    )


def _tested_config_keys(history: list, exp_type: str) -> set:
    keys = set()
    for h in history:
        if h.get("metric_source") == "unknown" or float(h.get("cpu_peak", 0.0) or 0.0) <= 0.0:
            continue
        variant = h.get("variant", "") if exp_type == "cpu_stress" else ""
        keys.add((exp_type, int(h.get("intensity", 1)), int(h.get("duration", 5)), variant))
    return keys


def _is_recent_duplicate(history: list, exp_type: str, intensity: int, duration: int, variant: str = "", window_secs: int = 30) -> bool:
    now = datetime.now(timezone.utc)
    target_variant = (variant or "").strip().lower() if exp_type == "cpu_stress" else ""
    for h in history:
        h_variant = (h.get("variant", "") or "").strip().lower() if exp_type == "cpu_stress" else ""
        if (
            int(h.get("intensity", 0) or 0) == int(intensity)
            and int(h.get("duration", 0) or 0) == int(duration)
            and h_variant == target_variant
        ):
            started_at = str(h.get("started_at", "") or "")
            try:
                seen = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            except ValueError:
                return True
            return (now - seen).total_seconds() <= window_secs
    return False


def _failure_threshold(history: list):
    failing = [
        int(h.get("intensity", 0))
        for h in history
        if h.get("result") == "Vulnerable" and h.get("metric_source") != "unknown" and float(h.get("cpu_peak", 0.0) or 0.0) > 0.0
    ]
    return min(failing) if failing else None


def _variant_scores(history: list) -> dict:
    scores = {}
    for h in history:
        variant = h.get("variant") or ""
        if not variant:
            continue
        if h.get("metric_source") == "unknown" or float(h.get("cpu_peak", 0.0) or 0.0) <= 0.0:
            continue
        scores.setdefault(variant, []).append(float(h.get("score", 0.0) or 0.0))
    return {k: (sum(v) / len(v)) for k, v in scores.items() if v}


def _config_performance(history: list) -> dict:
    """
    Build config-level learning memory from recent valid runs.
    key = (intensity, duration, variant)
    """
    groups = {}
    for h in history:
        if h.get("metric_source") == "unknown" or float(h.get("cpu_peak", 0.0) or 0.0) <= 0.0:
            continue
        key = (
            int(h.get("intensity", 1)),
            int(h.get("duration", 5)),
            str(h.get("variant", "")),
        )
        groups.setdefault(key, []).append(h)

    perf = {}
    for key, runs in groups.items():
        # History is DESC by time, keep last-3 trend window.
        latest = runs[:3]
        recoveries = [float(r.get("recovery", 0.0) or 0.0) for r in latest]
        if not recoveries:
            continue
        avg_recovery_3 = sum(recoveries) / len(recoveries)
        mean = avg_recovery_3
        variance = sum((x - mean) ** 2 for x in recoveries) / len(recoveries)
        instability = max(recoveries) - min(recoveries)
        degrading = len(recoveries) >= 2 and recoveries[0] > recoveries[-1]
        failure_rate = (
            sum(1 for r in latest if str(r.get("result", "")) == "Vulnerable") / len(latest)
            if latest else 0.0
        )
        # Trend-aware score: lower is better.
        score = (
            avg_recovery_3 * 0.5
            + float(key[1]) * 0.1
            + failure_rate * 10.0 * 0.2
            + instability * 0.2
            + variance * 0.2
            + (1.5 if degrading else 0.0)
        )
        perf[key] = {
            "avg_recovery_3": avg_recovery_3,
            "variance": variance,
            "instability": instability,
            "degrading": degrading,
            "failure_rate": failure_rate,
            "score": score,
            "sample": latest[0],
        }
    return perf


def _all_configs_vulnerable(history: list, min_unique: int = 4) -> bool:
    valid = [h for h in history if h.get("metric_source") != "unknown" and float(h.get("cpu_peak", 0.0) or 0.0) > 0.0]
    if not valid:
        return False
    groups = {}
    for h in valid:
        key = (int(h.get("intensity", 1)), int(h.get("duration", 5)), str(h.get("variant", "")))
        groups.setdefault(key, []).append(h.get("result"))
    if len(groups) < min_unique:
        return False
    failure_rate = sum(1 for h in valid if str(h.get("result", "")) == "Vulnerable") / max(1, len(valid))
    recent = valid[: min(10, len(valid))]
    avg_recovery = sum(float(h.get("recovery", 0.0) or 0.0) for h in recent) / max(1, len(recent))
    return failure_rate > 0.9 and avg_recovery > 2.0


def _attach_learning_metrics(metrics: dict, config_meta: dict = None):
    copied = dict(metrics)
    intensity = max(1, int(copied.get("intensity_level", 1) or 1))
    recovery = float(copied.get("recovery_time_secs", 0.0) or 0.0)
    result = str(copied.get("result", "Resilient") or "Resilient")
    score = recovery + (10.0 if result == "Vulnerable" else 0.0)
    normalized_recovery = recovery / intensity
    notes = str(copied.get("notes", "") or "")
    if notes:
        notes = f"{notes}, "
    extra = ""
    if config_meta:
        instability = config_meta.get("instability_score")
        degrading = config_meta.get("degrading")
        if instability is not None:
            extra += f", InstabilityScore={round(float(instability), 3)}"
        if degrading is not None:
            extra += f", Degrading={bool(degrading)}"
    copied["notes"] = f"{notes}Score={round(score, 3)}, NormalizedRecovery={round(normalized_recovery, 3)}{extra}"
    return copied


def _extract_note_value(notes: str, key: str):
    text = str(notes or "")
    marker = f"{key}="
    start = text.find(marker)
    if start < 0:
        return ""
    segment = text[start + len(marker):]
    return segment.split(",", 1)[0].strip()


def _compute_score(recovery_time: float, result: str, defense_action: str = "no_action") -> float:
    score = float(recovery_time or 0.0) + (10.0 if str(result) == "Vulnerable" else 0.0)
    if str(defense_action or "no_action") == "no_action":
        score += NO_ACTION_PENALTY
    return score
def select_defense_action(threat_type: str) -> str:
    scores = get_defense_action_avg_scores(threat_type)
    action_order = {name: idx for idx, name in enumerate(DEFENSE_ACTIONS)}

    # STEP 1: Ensure each action is tried once
    for action in DEFENSE_ACTIONS:
        if action not in scores:
            _log_event(
                "action_selected",
                command="",
                threat_type=threat_type,
                source="bandit",
                risk_score=0.0,
                action=action,
                mode="initial_explore"
            )
            return action

    # STEP 2: Controlled exploration (only if needed)
    under_tested = [
        name for name in scores.keys()
        if int(scores.get(name, {}).get("runs", 0)) < DEFENSE_MIN_TRIES_PER_ACTION
    ]

    if under_tested:
        action = sorted(
            under_tested,
            key=lambda name: (
                int(scores.get(name, {}).get("runs", 0)),
                action_order.get(name, 999)
            ),
        )[0]

        _log_event(
            "action_selected",
            command="",
            threat_type=threat_type,
            source="bandit",
            risk_score=0.0,
            action=action,
            mode="force_explore",
            runs=int(scores.get(action, {}).get("runs", 0)),
        )
        return action

    # STEP 3: Filter out BAD actions and avoid repeated restart attempts
    filtered_scores = {
        k: v for k, v in scores.items()
        if not (
            k == "restart_container" and float(v.get("avg_score", 0)) > 11.0
        )
    }

    if not filtered_scores:
        filtered_scores = scores  # fallback

    # STEP 4: Occasional exploration (safe)
    if random.random() < 0.1:
        action = random.choice(list(filtered_scores.keys()))
        _log_event(
            "action_selected",
            command="",
            threat_type=threat_type,
            source="bandit",
            risk_score=0.0,
            action=action,
            mode="explore"
        )
        return action

    # STEP 5: Exploit BEST action
    ranked = sorted(
        filtered_scores.items(),
        key=lambda kv: (
            float(kv[1].get("avg_score", 9999.0))
            + (NO_ACTION_PENALTY if kv[0] == "no_action" else 0.0)
        ),
    )

    action, meta = ranked[0]

    _log_event(
        "action_selected",
        command="",
        threat_type=threat_type,
        source="bandit",
        risk_score=0.0,
        action=action,
        mode="exploit",
        avg_score=round(float(meta.get("avg_score", 0.0)), 3),
        runs=int(meta.get("runs", 0)),
    )

    return action


def _remember_best_config(threat_type: str, config: dict, recovery_time: float, result: str):
    score = float(recovery_time or 0.0) + (10.0 if str(result) == "Vulnerable" else 0.0)
    prev = best_config_by_threat.get(threat_type)
    if prev is None or score < float(prev.get("score", 9999.0)):
        best_config_by_threat[threat_type] = {
            "config": {
                "type": config.get("type"),
                "intensity": int(config.get("intensity", 1)),
                "duration": int(config.get("duration", 5)),
            },
            "score": score,
        }


def _inject_best_config(threat_type: str, config: dict) -> dict:
    remembered = best_config_by_threat.get(threat_type)
    if not remembered:
        return config
    candidate = dict(config)
    learned = remembered.get("config", {})
    if learned.get("type") == candidate.get("type"):
        candidate["intensity"] = int(learned.get("intensity", candidate.get("intensity", 1)))
        candidate["duration"] = int(learned.get("duration", candidate.get("duration", 5)))
    return validate_experiment_config(candidate)


def _fetch_cpu_variant_history(threat_type: str, limit: int = 60):
    rows = safe_execute(
        """
        SELECT cr.notes, cr.result, cr.recovery_time_secs, cr.cpu_peak
        FROM chaos_results cr
        JOIN threats t ON t.threat_id = cr.threat_id
        WHERE t.threat_type = ?
          AND cr.experiment_type = 'cpu_stress'
        ORDER BY cr.started_at DESC
        LIMIT ?
        """,
        (threat_type, limit),
        fetch=True,
    )
    history = []
    for notes, result, recovery, cpu_peak in (rows or []):
        variant = _extract_note_value(notes, "CpuVariant")
        metric_source = _extract_note_value(notes, "MetricSource") or "unknown"
        if variant:
            result_str = str(result or "")
            rec = float(recovery or 0.0)
            history.append(
                {
                    "variant": variant,
                    "result": result_str,
                    "recovery": rec,
                    "score": rec + (10.0 if result_str == "Vulnerable" else 0.0),
                    "metric_source": metric_source,
                    "cpu_peak": float(cpu_peak or 0.0),
                }
            )
    return history


def _choose_next_cpu_variant(variant_history: list):
    scores = _variant_scores(variant_history)
    if scores:
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return ranked[0][0]
    seen = [h.get("variant") for h in variant_history if h.get("variant") in CPU_VARIANTS]
    for variant in CPU_VARIANTS:
        if variant not in seen:
            return variant
    return CPU_VARIANTS[0]


def _choose_exploration_cpu_variant(variant_history: list, current_variant: str = ""):
    counts = {v: 0 for v in CPU_VARIANTS}
    for h in variant_history:
        v = h.get("variant")
        if v in counts:
            counts[v] += 1
    # Exploration: prefer least-tested variant and avoid reusing current when possible.
    ranked = sorted(CPU_VARIANTS, key=lambda v: (counts[v], v == current_variant))
    return ranked[0] if ranked else CPU_VARIANTS[0]


def _apply_adaptive_overrides(config: dict, context: dict, history: list):
    updated = dict(config)
    was_adapted = False
    meta = {}

    if history:
        perf = _config_performance(history)
        prev_intensity = int(updated.get("intensity", 1))
        prev_duration = int(updated.get("duration", 5))
        if perf:
            best_key, best_stats = min(perf.items(), key=lambda item: item[1]["score"])
            updated["intensity"] = min(MAX_INTENSITY, max(1, int(best_key[0])))
            updated["duration"] = min(MAX_DURATION_SECS, max(1, int(best_key[1])))
            meta["variant_hint"] = str(best_key[2] or "")
            meta["instability_score"] = round(float(best_stats.get("instability", 0.0)), 3)
            meta["degrading"] = bool(best_stats.get("degrading", False))
            # Reward stability: if variance is low, keep config unchanged.
            if float(best_stats.get("variance", 0.0)) <= 0.05:
                was_adapted = (updated["intensity"] != prev_intensity) or (updated["duration"] != prev_duration)
                validated = validate_experiment_config(updated)
                validated.update(meta)
                return validated, was_adapted
        else:
            valid = [h for h in history if h.get("metric_source") != "unknown" and float(h.get("cpu_peak", 0.0) or 0.0) > 0.0]
            best = min(valid, key=lambda h: float(h.get("score", 9999.0))) if valid else min(history, key=lambda h: float(h.get("score", 9999.0)))
            updated["intensity"] = min(MAX_INTENSITY, max(1, int(best.get("intensity", prev_intensity))))
            updated["duration"] = min(MAX_DURATION_SECS, max(1, int(best.get("duration", prev_duration))))
        threshold = _failure_threshold(history)
        last_result = str(history[0].get("result", "")) if history else ""
        if last_result == "Vulnerable":
            updated["duration"] = min(MAX_DURATION_SECS, int(updated.get("duration", 5)) + 5)
            if threshold is not None:
                updated["intensity"] = min(MAX_INTENSITY, max(int(updated.get("intensity", 1)), int(threshold)))
        elif last_result == "Resilient":
            updated["intensity"] = min(MAX_INTENSITY, int(updated.get("intensity", 1)) + 1)
        was_adapted = (updated["intensity"] != prev_intensity) or (updated["duration"] != prev_duration)
    elif float(context.get("failure_rate", 0.0)) >= 0.6:
        updated["intensity"] = min(MAX_INTENSITY, int(updated.get("intensity", 1)) + 1)
        updated["duration"] = min(MAX_DURATION_SECS, int(updated.get("duration", 5)) + 5)
        was_adapted = True

    validated = validate_experiment_config(updated)
    validated.update(meta)
    return validated, was_adapted


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


def _build_retest_config(base_config: dict, prior_result: str = "Vulnerable"):
    retest_candidate = {
        "type": base_config.get("type", DEFAULT_SAFE_CONFIG["type"]),
        "intensity": int(base_config.get("intensity", 1)),
        "duration": int(base_config.get("duration", 5)),
    }
    if prior_result == "Vulnerable":
        retest_candidate["duration"] = min(MAX_DURATION_SECS, retest_candidate["duration"] + 5)
        retest_candidate["intensity"] = min(MAX_INTENSITY, retest_candidate["intensity"] + 1)
    else:
        retest_candidate["intensity"] = min(MAX_INTENSITY, retest_candidate["intensity"] + 1)
    return validate_experiment_config(retest_candidate)


def _build_exploration_config(base_config: dict, history: list = None):
    history = history or []
    valid = [h for h in history if h.get("metric_source") != "unknown" and float(h.get("cpu_peak", 0.0) or 0.0) > 0.0]
    max_seen_duration = max([int(h.get("duration", 0) or 0) for h in valid], default=int(base_config.get("duration", 5)))
    max_seen_intensity = max([int(h.get("intensity", 0) or 0) for h in valid], default=int(base_config.get("intensity", 1)))
    exploratory = {
        "type": base_config.get("type", DEFAULT_SAFE_CONFIG["type"]),
        "intensity": min(MAX_INTENSITY, max(int(base_config.get("intensity", 1)), max_seen_intensity) + 1),
        "duration": min(MAX_DURATION_SECS, max(int(base_config.get("duration", 5)), max_seen_duration) + EXPLORATION_DURATION_STEP),
    }
    return validate_experiment_config(exploratory)


def _infer_target_service(command: str) -> str:
    text = (command or "").lower()
    if "sshd" in text or "ssh " in text:
        return "sshd"
    if "nginx" in text:
        return "nginx"
    if "apache2" in text or "httpd" in text or "apache" in text:
        return "apache"
    if "mysql" in text or "mysqld" in text:
        return "mysql"
    if "postgres" in text or "postgresql" in text or "psql" in text:
        return "postgres"
    if "redis" in text:
        return "redis"
    if "docker" in text or "containerd" in text:
        return "docker"
    if "kubelet" in text or "kubectl" in text:
        return "kubelet"
    return "generic"


def _is_lightweight_recon_or_access(threat_type: str, command: str) -> bool:
    t = str(threat_type or "")
    c = " ".join(str(command or "").lower().split())
    if t == "Sensitive_Data_Access":
        return True
    if t != "Reconnaissance":
        return False
    lightweight_tokens = (
        "whoami",
        "id",
        "uname -a",
        "hostname",
        "ps aux",
        "ps -ef",
        "top",
    )
    return c in lightweight_tokens


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
                if _should_skip_duplicate_command(command):
                    _mark_threat_processed(threat_id)
                    _log_event(
                        "duplicate_command_skipped",
                        command=command,
                        threat_type=threat_type,
                        source="watcher",
                        risk_score=0.0,
                    )
                    continue

                if _is_lightweight_recon_or_access(threat_type, command):
                    _mark_threat_processed(threat_id)
                    _log_event(
                        "lightweight_threat_skip",
                        command=command,
                        threat_type=threat_type,
                        source="watcher",
                        risk_score=0.0,
                        reason="recon_or_sensitive_access_no_heavy_chaos",
                    )
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
                config = _inject_best_config(threat_type, config)
                prior_stats = get_threat_prediction(threat_type)
                history = _fetch_threat_history(threat_type)
                exploration_mode = _all_configs_vulnerable(history)
                if exploration_mode:
                    _log_event(
                        "system_unstable_detected",
                        command=command,
                        threat_type=threat_type,
                        source="adaptive",
                        risk_score=prior_stats.get("risk_score", 0.0),
                        reason="all_known_configs_vulnerable_enter_exploration_mode",
                    )
                context = {
                    "command": command,
                    "threat_type": threat_type,
                    "failure_rate": prior_stats["failure_rate"],
                    "previous_intensity": config.get("intensity", 1),
                    "previous_duration": config.get("duration", 5),
                    "scaled": False,
                }
                config, adapted = _apply_adaptive_overrides(config, context, history)
                if exploration_mode:
                    config = _build_exploration_config(config, history)
                    adapted = True

                adaptive_state = get_adaptive_state(session_id, threat_type)
                is_scaled = adaptive_state["is_scaled"]
                target_service = _infer_target_service(command) if config["type"] == "process_disruption" else "generic"
                variant_history = _fetch_cpu_variant_history(threat_type) if config["type"] == "cpu_stress" else []
                cpu_variant = _choose_next_cpu_variant(variant_history) if config["type"] == "cpu_stress" else ""
                if config.get("type") == "cpu_stress" and str(config.get("variant_hint", "")) in CPU_VARIANTS:
                    cpu_variant = str(config.get("variant_hint"))
                if exploration_mode and config.get("type") == "cpu_stress":
                    cpu_variant = _choose_exploration_cpu_variant(variant_history, cpu_variant)
                if bool(config.get("degrading", False)):
                    _log_event(
                        "degrading_config_detected",
                        command=command,
                        threat_type=threat_type,
                        source="adaptive_learning",
                        risk_score=adaptive_state["predicted_risk_score"],
                        intensity=int(config.get("intensity", 1)),
                        duration=int(config.get("duration", 5)),
                        instability_score=float(config.get("instability_score", 0.0) or 0.0),
                    )
                variant_combination = bool((not SAFE_MODE) and exploration_mode and config.get("type") == "cpu_stress")

                threshold = _failure_threshold(history)
                if threshold is not None and int(config.get("intensity", 1)) > threshold + 1:
                    config["intensity"] = min(MAX_INTENSITY, threshold + 1)
                    adapted = True

                tested_keys = _tested_config_keys(history, config.get("type", ""))
                run_key = _config_key(config, cpu_variant if config.get("type") == "cpu_stress" else "")
                if run_key in tested_keys:
                    if config.get("type") == "cpu_stress":
                        picked = None
                        variant_pool = CPU_VARIANTS[:]
                        if exploration_mode:
                            variant_pool = sorted(CPU_VARIANTS, key=lambda v: v == cpu_variant)
                        for v in variant_pool:
                            candidate = _config_key(config, v)
                            if candidate not in tested_keys:
                                picked = v
                                break
                        if picked:
                            cpu_variant = picked
                            adapted = True
                        else:
                            if exploration_mode:
                                config = _build_exploration_config(config, history)
                                cpu_variant = _choose_exploration_cpu_variant(variant_history, cpu_variant)
                                run_key = _config_key(config, cpu_variant)
                                if run_key in tested_keys:
                                    _log_event(
                                        "config_skip_duplicate",
                                        command=command,
                                        threat_type=threat_type,
                                        source="adaptive",
                                        risk_score=adaptive_state["predicted_risk_score"],
                                        reason="exploration_duplicate_after_expand",
                                    )
                                    _mark_threat_processed(threat_id)
                                    continue
                            else:
                                _log_event(
                                    "config_skip_duplicate",
                                    command=command,
                                    threat_type=threat_type,
                                    source="adaptive",
                                    risk_score=adaptive_state["predicted_risk_score"],
                                    reason="all_variants_already_tested_for_config",
                                )
                                _mark_threat_processed(threat_id)
                                continue
                    else:
                        adjusted = False
                        for _ in range(4):
                            config["duration"] = min(MAX_DURATION_SECS, int(config.get("duration", 5)) + 5)
                            candidate = _config_key(config, "")
                            if candidate not in tested_keys:
                                adjusted = True
                                adapted = True
                                break
                        if not adjusted:
                            _log_event(
                                "config_skip_duplicate",
                                command=command,
                                threat_type=threat_type,
                                source="adaptive",
                                risk_score=adaptive_state["predicted_risk_score"],
                                reason="config_already_tested",
                            )
                            _mark_threat_processed(threat_id)
                            continue

                defense_action = select_defense_action(threat_type)
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
                            "cpu_variant": cpu_variant,
                            "variant_combination": variant_combination,
                            "target_service": target_service,
                            "defense_action": defense_action,
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
                    target_service,
                    cpu_variant,
                    variant_combination,
                    defense_action,
                )
                metrics = _attach_learning_metrics(metrics, config)
                if not _is_valid_metrics(metrics):
                    _log_event(
                        "invalid_metrics_discarded",
                        command=command,
                        threat_type=threat_type,
                        source="adaptive",
                        risk_score=adaptive_state["predicted_risk_score"],
                        experiment_type=config["type"],
                        cpu_peak=metrics.get("cpu_peak", 0.0),
                        metric_source=metrics.get("metric_source", "unknown"),
                    )
                    _mark_threat_processed(threat_id)
                    continue
                _insert_chaos_result(threat_id, metrics)
                # Recovery is computed inside run_experiment and must complete
                # before any critical decision is made.
                recovery_time_secs = float(metrics.get("recovery_time_secs", 0.0) or 0.0)
                primary_score = _compute_score(recovery_time_secs, metrics.get("result", "Resilient"), defense_action)
                insert_adaptive_defense_run(
                    threat_type=threat_type,
                    experiment_type=config.get("type", "cpu_stress"),
                    intensity_level=int(config.get("intensity", 1)),
                    duration_secs=int(config.get("duration", 5)),
                    variant=cpu_variant if config.get("type") == "cpu_stress" else "",
                    defense_action=defense_action,
                    recovery_time_secs=recovery_time_secs,
                    result=metrics.get("result", "Resilient"),
                    score=primary_score,
                )
                _log_event(
                    "action_score",
                    command=command,
                    threat_type=threat_type,
                    source="bandit",
                    risk_score=0.0,
                    action=defense_action,
                    score=round(primary_score, 3),
                )
                _remember_best_config(threat_type, config, recovery_time_secs, metrics.get("result", "Resilient"))

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

                is_critical = (
                    metrics.get("result") == "Vulnerable"
                    and int(config.get("intensity", 1)) >= int(MAX_INTENSITY)
                )
                if is_critical:
                    _log_event(
                        "critical_threat_detected",
                        command=command,
                        threat_type=threat_type,
                        source="adaptive",
                        risk_score=stats["risk_score"],
                        intensity=int(config.get("intensity", 1)),
                        duration=int(config.get("duration", 0)),
                        recovery_time_secs=recovery_time_secs,
                        experiment_type=config.get("type"),
                        cpu_variant=cpu_variant,
                        target_service=target_service,
                    )

                post_history = _fetch_threat_history(threat_type)
                if _all_configs_vulnerable(post_history):
                    _log_event(
                        "system_unstable_detected",
                        command=command,
                        threat_type=threat_type,
                        source="adaptive",
                        risk_score=stats["risk_score"],
                        reason="all_known_configs_vulnerable",
                    )

                # Optional adaptive re-test:
                # - normal path: rerun once with stronger config
                # - max-level CPU path: rotate stress variant instead of stopping
                if metrics.get("result") == "Vulnerable" and not is_critical:
                    retest_config = _build_retest_config(config, metrics.get("result", "Vulnerable"))
                    if _all_configs_vulnerable(post_history):
                        retest_config = _build_exploration_config(retest_config, post_history)
                    retest_variant = cpu_variant
                    if retest_config.get("type") == "cpu_stress":
                        retest_variant = _choose_next_cpu_variant(post_history)
                        if _all_configs_vulnerable(post_history):
                            retest_variant = _choose_exploration_cpu_variant(post_history, retest_variant)
                    retest_key = _config_key(retest_config, retest_variant if retest_config.get("type") == "cpu_stress" else "")
                    recent_duplicate = _is_recent_duplicate(
                        post_history,
                        retest_config.get("type", ""),
                        int(retest_config.get("intensity", 1)),
                        int(retest_config.get("duration", 5)),
                        retest_variant if retest_config.get("type") == "cpu_stress" else "",
                        window_secs=30,
                    )
                    if retest_key in _tested_config_keys(post_history, retest_config.get("type", "")) and recent_duplicate:
                        _log_event(
                            "retest_skip_duplicate",
                            command=command,
                            threat_type=threat_type,
                            source="adaptive",
                            risk_score=stats["risk_score"],
                            experiment_type=retest_config["type"],
                        )
                    else:
                        retest_defense_action = select_defense_action(threat_type)
                        _log_event(
                            "retest_start",
                            command=command,
                            threat_type=threat_type,
                            source="adaptive",
                            risk_score=stats["risk_score"],
                            experiment_type=retest_config["type"],
                            experiment_intensity=retest_config["intensity"],
                            experiment_duration=retest_config["duration"],
                            cpu_variant=retest_variant,
                            target_service=target_service,
                            defense_action=retest_defense_action,
                        )
                        retest_metrics = run_experiment(
                            retest_config["type"],
                            retest_config["duration"],
                            retest_config["intensity"],
                            True,  # simulate protection/scaling on re-test
                            target_service,
                            retest_variant,
                            variant_combination,
                            retest_defense_action,
                        )
                        retest_metrics = _attach_learning_metrics(retest_metrics, retest_config)
                        if _is_valid_metrics(retest_metrics):
                            _insert_chaos_result(threat_id, retest_metrics, is_retest=True)
                            retest_recovery = float(retest_metrics.get("recovery_time_secs", 0.0) or 0.0)
                            retest_score = _compute_score(retest_recovery, retest_metrics.get("result", "Resilient"), retest_defense_action)
                            insert_adaptive_defense_run(
                                threat_type=threat_type,
                                experiment_type=retest_config.get("type", "cpu_stress"),
                                intensity_level=int(retest_config.get("intensity", 1)),
                                duration_secs=int(retest_config.get("duration", 5)),
                                variant=retest_variant if retest_config.get("type") == "cpu_stress" else "",
                                defense_action=retest_defense_action,
                                recovery_time_secs=retest_recovery,
                                result=retest_metrics.get("result", "Resilient"),
                                score=retest_score,
                            )
                            _log_event(
                                "action_score",
                                command=command,
                                threat_type=threat_type,
                                source="bandit",
                                risk_score=stats["risk_score"],
                                action=retest_defense_action,
                                score=round(retest_score, 3),
                            )
                            _remember_best_config(threat_type, retest_config, retest_recovery, retest_metrics.get("result", "Resilient"))
                            _log_event(
                                "retest_complete",
                                command=command,
                                threat_type=threat_type,
                                source="adaptive",
                                risk_score=stats["risk_score"],
                                result=retest_metrics.get("result", "Resilient"),
                                scaled=True,
                            )
                        else:
                            _log_event(
                                "invalid_metrics_discarded",
                                command=command,
                                threat_type=threat_type,
                                source="adaptive_retest",
                                risk_score=stats["risk_score"],
                                experiment_type=retest_config["type"],
                                cpu_peak=retest_metrics.get("cpu_peak", 0.0),
                                metric_source=retest_metrics.get("metric_source", "unknown"),
                            )
                elif (
                    metrics.get("result") == "Vulnerable"
                    and is_critical
                    and config.get("type") == "cpu_stress"
                ):
                    variant_history = _fetch_cpu_variant_history(threat_type)
                    next_variant = _choose_next_cpu_variant(variant_history)
                    if _all_configs_vulnerable(post_history):
                        next_variant = _choose_exploration_cpu_variant(variant_history, next_variant)
                    variant_key = _config_key(config, next_variant)
                    recent_variant_duplicate = _is_recent_duplicate(
                        post_history,
                        config.get("type", ""),
                        int(config.get("intensity", 1)),
                        int(config.get("duration", 5)),
                        next_variant,
                        window_secs=30,
                    )
                    if variant_key in _tested_config_keys(post_history, config.get("type", "")) and recent_variant_duplicate:
                        _log_event(
                            "variant_retest_skip_duplicate",
                            command=command,
                            threat_type=threat_type,
                            source="adaptive_variant",
                            risk_score=stats["risk_score"],
                            cpu_variant=next_variant,
                        )
                        next_variant = ""
                    if not next_variant:
                        pass
                    else:
                        retest_defense_action = select_defense_action(threat_type)
                        _log_event(
                            "variant_retest_start",
                            command=command,
                            threat_type=threat_type,
                            source="adaptive_variant",
                            risk_score=stats["risk_score"],
                            experiment_type=config["type"],
                            experiment_intensity=config["intensity"],
                            experiment_duration=config["duration"],
                            cpu_variant=next_variant,
                            defense_action=retest_defense_action,
                        )
                        retest_metrics = run_experiment(
                            config["type"],
                            config["duration"],
                            config["intensity"],
                            True,
                            target_service,
                            next_variant,
                            variant_combination,
                            retest_defense_action,
                        )
                        retest_metrics = _attach_learning_metrics(retest_metrics, config)
                        if _is_valid_metrics(retest_metrics):
                            _insert_chaos_result(threat_id, retest_metrics, is_retest=True)
                            retest_recovery = float(retest_metrics.get("recovery_time_secs", 0.0) or 0.0)
                            retest_score = _compute_score(retest_recovery, retest_metrics.get("result", "Resilient"), retest_defense_action)
                            insert_adaptive_defense_run(
                                threat_type=threat_type,
                                experiment_type=config.get("type", "cpu_stress"),
                                intensity_level=int(config.get("intensity", 1)),
                                duration_secs=int(config.get("duration", 5)),
                                variant=next_variant if config.get("type") == "cpu_stress" else "",
                                defense_action=retest_defense_action,
                                recovery_time_secs=retest_recovery,
                                result=retest_metrics.get("result", "Resilient"),
                                score=retest_score,
                            )
                            _log_event(
                                "action_score",
                                command=command,
                                threat_type=threat_type,
                                source="bandit",
                                risk_score=stats["risk_score"],
                                action=retest_defense_action,
                                score=round(retest_score, 3),
                            )
                            _remember_best_config(threat_type, config, retest_recovery, retest_metrics.get("result", "Resilient"))
                            _log_event(
                                "variant_retest_complete",
                                command=command,
                                threat_type=threat_type,
                                source="adaptive_variant",
                                risk_score=stats["risk_score"],
                                result=retest_metrics.get("result", "Resilient"),
                                cpu_variant=next_variant,
                                scaled=True,
                            )
                        else:
                            _log_event(
                                "invalid_metrics_discarded",
                                command=command,
                                threat_type=threat_type,
                                source="adaptive_variant",
                                risk_score=stats["risk_score"],
                                experiment_type=config["type"],
                                cpu_peak=retest_metrics.get("cpu_peak", 0.0),
                                metric_source=retest_metrics.get("metric_source", "unknown"),
                            )
                    failed_variants = {
                        h["variant"]
                        for h in _fetch_cpu_variant_history(threat_type)
                        if h.get("result") == "Vulnerable"
                        and h.get("variant") in CPU_VARIANTS
                        and h.get("metric_source") != "unknown"
                        and float(h.get("cpu_peak", 0.0) or 0.0) > 0.0
                    }
                    recent_variant_runs = [
                        h for h in _fetch_cpu_variant_history(threat_type)
                        if h.get("result") == "Vulnerable"
                        and h.get("variant") in CPU_VARIANTS
                        and h.get("metric_source") != "unknown"
                        and float(h.get("cpu_peak", 0.0) or 0.0) > 0.0
                    ]
                    avg_variant_recovery = (
                        sum(float(h.get("recovery", 0.0) or 0.0) for h in recent_variant_runs[:10]) / max(1, len(recent_variant_runs[:10]))
                    ) if recent_variant_runs else 0.0
                    if (
                        len(failed_variants) == len(CPU_VARIANTS)
                        and float(stats.get("failure_rate", 0.0) or 0.0) > 0.9
                        and avg_variant_recovery > 1.5
                    ):
                        _log_event(
                            "severe_weakness_all_cpu_variants",
                            command=command,
                            threat_type=threat_type,
                            source="adaptive_variant",
                            risk_score=stats["risk_score"],
                            failed_variants=sorted(failed_variants),
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
