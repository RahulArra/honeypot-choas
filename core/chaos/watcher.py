"""
Chaos Watcher — Chaos Validation Engine
Member B (Sesh) Responsibility

Background daemon thread that:
    1. Polls threats table every 5 seconds for processed=0
    2. Maps threat_type → experiment_type
    3. Runs controlled stress experiment
    4. Stores metrics in chaos_results
    5. Updates adaptive_scores
    6. Marks threat as processed=1
"""

import time
import threading
import logging
from datetime import datetime

from core.chaos.experiments import run_experiment
from core.chaos.threat_map  import get_experiment_type, get_duration
from core.database.db_client import safe_execute, get_connection
from core.adaptive.escalation import update_adaptive_score, mark_weakness, increase_intensity, simulate_scaling

logger = logging.getLogger(__name__)

POLL_INTERVAL = 5   # seconds between DB polls


# ── DB Helpers ─────────────────────────────────────────────────────────────────

def _fetch_unprocessed_threats():
    """Fetch all unprocessed threats ordered by timestamp."""
    rows = safe_execute(
        "SELECT threat_id, session_id, threat_type, severity, experiment_type, experiment_intensity, experiment_duration FROM threats WHERE processed = 0 ORDER BY timestamp ASC",
        fetch=True
    )
    return rows or []


def _get_chaos_intensity(session_id: str, threat_type: str) -> int:
    """Get current chaos intensity level from adaptive_scores."""
    rows = safe_execute(
        "SELECT chaos_intensity_level FROM adaptive_scores WHERE session_id = ? AND threat_type = ?",
        params=(session_id, threat_type),
        fetch=True
    )
    if rows:
        return rows[0][0]
    return 1  # Default intensity


def _insert_chaos_result(threat_id: int, metrics: dict, is_retest: int = 0):
    """Insert experiment metrics into chaos_results table."""
    conn = get_connection()
    try:
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
                metrics["experiment_type"],
                metrics["intensity_level"],
                metrics["cpu_peak"],
                metrics["memory_peak"],
                metrics["disk_io_peak"],
                metrics["duration_secs"],
                metrics["recovery_time_secs"],
                metrics["result"],
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                metrics.get("notes", ""),
                is_retest,
            )
        )
        conn.commit()
        logger.info(f"[Chaos] Result stored → experiment_id={cursor.lastrowid}")
    finally:
        conn.close()


def _mark_threat_processed(threat_id: int):
    """Mark threat as processed in DB."""
    safe_execute(
        "UPDATE threats SET processed = 1 WHERE threat_id = ?",
        params=(threat_id,)
    )


# ── Core Watcher Loop ──────────────────────────────────────────────────────────

def _watcher_loop():
    """
    Main watcher loop — runs forever as a daemon thread.
    Polls DB every POLL_INTERVAL seconds.
    """
    logger.info(f"[Chaos] Watcher started — polling every {POLL_INTERVAL}s")

    while True:
        try:
            threats = _fetch_unprocessed_threats()

            if threats:
                logger.info(f"[Chaos] Found {len(threats)} unprocessed threat(s)")

            for row in threats:
                threat_id   = row[0]
                session_id  = row[1]
                threat_type = row[2]
                severity    = row[3]
                exp_type    = row[4]
                exp_intensity = row[5]
                exp_duration  = row[6]

                logger.info(
                    f"[Chaos] Processing threat_id={threat_id} "
                    f"type={threat_type} severity={severity}"
                )

                try:
                    # ── Step 1: Run Primary Experiment ────────────────────────
                    logger.info(
                        f"[Chaos] Running Primary Test {exp_type} "
                        f"intensity={exp_intensity} duration={exp_duration}s"
                    )

                    metrics = run_experiment(exp_type, exp_duration, exp_intensity)
                    _insert_chaos_result(threat_id, metrics, is_retest=0)
                    update_adaptive_score(session_id, threat_type)

                    logger.info(f"[Chaos] ✓ Primary Result: {metrics['result']}")

                    # ── Step 2: Adaptive Engine (NEW) ──────────────────────────
                    if metrics["result"] == "Vulnerable":
                        logger.warning(f"[Chaos] 🚨 System Vulnerable! Activating Adaptive Engine.")
                        mark_weakness(session_id, threat_type)
                        increase_intensity(session_id, threat_type)
                        simulate_scaling(session_id, threat_type) # Simulate stronger system for re-test

                        # Fetch improved configuration
                        new_intensity = _get_chaos_intensity(session_id, threat_type)
                        logger.info(f"[Chaos] Re-testing with simulated scaling (intensity {new_intensity})")
                        
                        # ── Step 3: Re-Test ──────────────────────────────────────
                        retest_metrics = run_experiment(exp_type, exp_duration, new_intensity)
                        _insert_chaos_result(threat_id, retest_metrics, is_retest=1)

                        if retest_metrics["result"] == "Resilient":
                            logger.info("[Chaos] 🛡️ Re-test Resilient! System successfully demonstrated adaptation.")
                        else:
                            logger.warning("[Chaos] 🚨 Re-test Vulnerable. Weakness persists.")

                    # ── Step 4: Mark processed ─────────────────────────────────
                    _mark_threat_processed(threat_id)

                except Exception as e:
                    logger.error(
                        f"[Chaos] Failed to process threat_id={threat_id}: {e}",
                        exc_info=True
                    )
                    # Still mark as processed to avoid infinite retry loop
                    _mark_threat_processed(threat_id)

        except Exception as e:
            logger.error(f"[Chaos] Watcher loop error: {e}", exc_info=True)

        time.sleep(POLL_INTERVAL)


# ── Public Interface ───────────────────────────────────────────────────────────

def start_chaos_watcher():
    """
    Start the chaos watcher as a background daemon thread.
    Called once from core/main.py at startup.
    """
    thread = threading.Thread(
        target=_watcher_loop,
        name="ChaosWatcher",
        daemon=True   # Dies automatically when main process exits
    )
    thread.start()
    logger.info("[Chaos] Watcher thread launched")
    return thread