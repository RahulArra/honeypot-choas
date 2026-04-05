"""
Threat Service — Honeypot Chaos Project
Member B (Sesh) Responsibility

Fixed to match Rahul's existing call signature:
    handle_threat_detection(session_id, command_id, raw_input)

Rahul already handles:
    - insert_command()
    - increment_command_count()

This file handles:
    - Rule engine check
    - AI fallback when rule engine returns None (with DB-backed cache)
    - insert_threat() when threat detected
    - update_adaptive_score() after every threat
"""

import logging
from core.intelligence.classifier import classify_command
from core.intelligence.ai_classifier import classify_with_ai
from core.database.db_client import safe_execute
from core.database.queries import insert_threat, update_command_response_type
from core.adaptive.escalation import update_adaptive_score

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

NON_THREAT_TYPES = {"Benign", "Unknown"}

# Commands handled by virtual filesystem — skip classification entirely
SAFE_COMMANDS = {
    "ls", "pwd", "cd", "mkdir", "touch",
    "rm", "rmdir", "cat", "echo", "clear",
    "exit", "logout"
}

# Fake shell responses for rule-matched threat commands
RULE_FAKE_RESPONSES = {
    "wget":  "Connecting to {host}... HTTP request sent, awaiting response... 200 OK\nSaving to: '{file}'\n{file} 100%[=================================================>] 1.00K  --.-KB/s",
    "curl":  "  % Total    % Received % Xferd  Average Speed\n100  1024  100  1024    0     0   2048      0 --:--:-- --:--:-- 0",
    "sudo":  "[sudo] password for root:",
    "chmod": "",
}

# ── DB-backed AI cache ─────────────────────────────────────────────────────────

def _load_ai_cache_from_db() -> dict:
    """Load previously AI-classified commands from DB into memory on startup."""
    cache = {}
    try:
        rows = safe_execute(
            """
            SELECT c.parsed_command, c.response_text, t.threat_type, t.severity, t.confidence, t.experiment_type, t.experiment_intensity, t.experiment_duration
            FROM commands c
            LEFT JOIN threats t ON c.command_id = t.command_id
            WHERE c.response_type = 'ai'
            AND c.parsed_command IS NOT NULL
            ORDER BY c.timestamp DESC
            """,
            fetch=True
        )
        if rows:
            for row in rows:
                cmd = row[0]
                if cmd and cmd not in cache:
                    cache[cmd] = {
                        "shell_response": row[1] or "bash: command not found",
                        "threat_type":    row[2] or "Unknown",
                        "severity":       row[3] or "Low",
                        "confidence":     float(row[4]) if row[4] else 0.0,
                        "experiment":     {"type": row[5] or "cpu_stress", "intensity": row[6] or 1, "duration": row[7] or 10}
                    }
            logger.info(f"[ThreatService] Loaded {len(cache)} AI-learned commands from DB")
        else:
            logger.info("[ThreatService] No AI-learned commands in DB yet")
    except Exception as e:
        logger.warning(f"[ThreatService] Could not load AI cache from DB: {e}")
    return cache

# Load cache once on module import
_AI_CACHE = _load_ai_cache_from_db()

# ── Helpers ────────────────────────────────────────────────────────────────────

def _fake_response_for_rule(raw_input: str) -> str:
    """Generate a fake shell response for rule-matched threat commands."""
    parts = raw_input.strip().split()
    cmd   = parts[0].lower() if parts else ""

    if cmd == "wget" and len(parts) > 1:
        url      = parts[1]
        filename = url.split("/")[-1] or "index.html"
        host     = url.split("/")[2] if len(url.split("/")) > 2 else "unknown"
        return RULE_FAKE_RESPONSES["wget"].format(host=host, file=filename)

    return RULE_FAKE_RESPONSES.get(cmd, f"bash: {cmd}: command not found")

# ── Main Orchestrator ──────────────────────────────────────────────────────────

def handle_threat_detection(
    session_id: str,
    command_id: int,
    raw_input: str,
    current_dir: str = "/home/root",
    session_fs: dict = None,
) -> dict:
    """
    Orchestrator called by Rahul's ssh_server.py after every command.

    Flow:
        1. Skip safe filesystem commands entirely
        2. Check rule engine
        3. Check in-memory cache (populated from DB on startup)
        4. Call AI if cache miss
        5. Persist threat + update adaptive score
    """
    if session_fs is None:
        session_fs = {}

    cmd_token = raw_input.strip().split()[0].lower() if raw_input.strip() else ""

    # ── Safe defaults ──────────────────────────────────────────────────────────
    result = {
        "detected":          False,
        "type":              "Unknown",
        "severity":          "Low",
        "confidence":        0.0,
        "source":            "unknown",
        "adaptive_severity": "Low",
        "chaos_level":       1,
        "shell_response":    f"bash: {cmd_token or 'command'}: command not found",
    }

    try:
        # ── Step 0: Skip safe filesystem commands ──────────────────────────────
        if cmd_token in SAFE_COMMANDS:
            logger.debug(f"[ThreatService] '{cmd_token}' is safe — skipping")
            return result

        # ── Step 1: Rule Engine ────────────────────────────────────────────────
        threat_data   = classify_command(raw_input)
        response_type = "rule" if threat_data else None

        if threat_data is not None:
            result["shell_response"] = _fake_response_for_rule(raw_input)

        # ── Step 2: Cache check then AI fallback ───────────────────────────────
        if threat_data is None:
            if cmd_token in _AI_CACHE:
                # ── Cache hit — no AI call needed ──────────────────────────────
                cached = _AI_CACHE[cmd_token]
                logger.info(f"[ThreatService] Cache hit for '{cmd_token}' — skipping AI")
                result["shell_response"] = cached["shell_response"]

                if cached["threat_type"] not in NON_THREAT_TYPES:
                    threat_data   = {
                        "type":       cached["threat_type"],
                        "severity":   cached["severity"],
                        "confidence": cached["confidence"],
                        "experiment": cached["experiment"]
                    }
                    response_type = "ai"
                else:
                    response_type = "unknown"

            else:
                # ── Cache miss — call AI ───────────────────────────────────────
                logger.info(f"[ThreatService] Cache miss for '{cmd_token}' → calling AI")
                ai_result = classify_with_ai(raw_input, current_dir, session_fs)

                result["shell_response"] = ai_result["shell_response"]

                # Determine response_type before caching
                response_type = "ai" if ai_result["threat_type"] not in NON_THREAT_TYPES else "unknown"

                # Update DB record with correct response_type and shell response
                update_command_response_type(
                    command_id,
                    response_type,
                    ai_result["shell_response"]
                )

                # Store in memory cache for this session
                _AI_CACHE[cmd_token] = {
                    "shell_response": ai_result["shell_response"],
                    "threat_type":    ai_result["threat_type"],
                    "severity":       ai_result["severity"],
                    "confidence":     ai_result["confidence"],
                    "experiment":     ai_result.get("experiment")
                }
                logger.info(f"[ThreatService] Cached '{cmd_token}' for future use")

                if ai_result["threat_type"] not in NON_THREAT_TYPES:
                    threat_data = {
                        "type":       ai_result["threat_type"],
                        "severity":   ai_result["severity"],
                        "confidence": ai_result["confidence"],
                        "experiment": ai_result.get("experiment")
                    }
                    logger.info(
                        f"[ThreatService] AI classified '{raw_input}' → "
                        f"{threat_data['type']} ({threat_data['severity']})"
                    )
                else:
                    logger.debug(
                        f"[ThreatService] AI returned '{ai_result['threat_type']}' "
                        f"for '{raw_input}' — no threat"
                    )

        # ── Step 3: Insert threat if detected ──────────────────────────────────
        if threat_data is not None:
            insert_threat(
                session_id=session_id,
                command_id=command_id,
                threat_type=threat_data["type"],
                severity=threat_data["severity"],
                confidence=threat_data["confidence"],
                source=response_type,
                experiment=threat_data.get("experiment")
            )
            logger.info(
                f"[ThreatService] Threat inserted → {threat_data['type']} "
                f"(severity={threat_data['severity']}, source={response_type})"
            )

            # ── Step 4: Adaptive score update ──────────────────────────────────
            new_severity, new_intensity = update_adaptive_score(
                session_id, threat_data["type"]
            )
            logger.info(
                f"[ThreatService] Adaptive update → "
                f"severity={new_severity}, chaos_level={new_intensity}"
            )

            result.update({
                "detected":          True,
                "type":              threat_data["type"],
                "severity":          threat_data["severity"],
                "confidence":        threat_data["confidence"],
                "source":            response_type,
                "adaptive_severity": new_severity,
                "chaos_level":       new_intensity,
            })

    except Exception as e:
        logger.error(
            f"[ThreatService] Unhandled exception for '{raw_input}': {e}",
            exc_info=True
        )

    return result