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
    - AI fallback when rule engine returns None
    - insert_threat() when threat detected
    - update_adaptive_score() after every threat
"""

import logging
from core.intelligence.classifier import classify_command
from core.intelligence.ai_classifier import classify_with_ai
from core.database.queries import insert_threat
from core.adaptive.escalation import update_adaptive_score

logger = logging.getLogger(__name__)

# Threat types that do NOT warrant a DB threat record or chaos trigger
NON_THREAT_TYPES = {"Benign", "Unknown"}

RULE_FAKE_RESPONSES = {
    "wget":   "Connecting to {host}... HTTP request sent, awaiting response... 200 OK\nSaving to: '{file}'\n{file} 100%[=================================================>] 1.00K  --.-KB/s",
    "curl":   "  % Total    % Received % Xferd  Average Speed\n100  1024  100  1024    0     0   2048      0 --:--:-- --:--:-- 0",
    "sudo":   "[sudo] password for root:",
    "chmod":  "",
}

def _fake_response_for_rule(raw_input: str) -> str:
    cmd = raw_input.strip().split()[0].lower()
    parts = raw_input.strip().split()
    
    if cmd == "wget" and len(parts) > 1:
        url = parts[1]
        filename = url.split("/")[-1] or "index.html"
        host = url.split("/")[2] if len(url.split("/")) > 2 else "unknown"
        template = RULE_FAKE_RESPONSES["wget"]
        return template.format(host=host, file=filename)
    
    return RULE_FAKE_RESPONSES.get(cmd, f"bash: {cmd}: command not found")

def handle_threat_detection(
    session_id: str,
    command_id: int,
    raw_input: str,
    current_dir: str = "/home/root",
    session_fs: dict = None,
) -> dict:
    """
    Orchestrator called by Rahul's ssh_server.py after every command.

    Args:
        session_id:  Active session UUID
        command_id:  DB row ID already inserted by Rahul's ssh_server.py
        raw_input:   Full raw command string typed by attacker
        current_dir: Attacker's current directory in fake shell
        session_fs:  Session filesystem snapshot for AI context

    Returns:
        {
            "detected":          bool,
            "type":              str,
            "severity":          str,
            "confidence":        float,
            "source":            str,   # "rule" / "ai" / "unknown"
            "adaptive_severity": str,
            "chaos_level":       int,
            "shell_response":    str,   # AI-generated response for unknown commands
        }
    """
    if session_fs is None:
        session_fs = {}

    # ── Safe defaults ──────────────────────────────────────────────────────────
    result = {
        "detected":          False,
        "type":              "Unknown",
        "severity":          "Low",
        "confidence":        0.0,
        "source":            "unknown",
        "adaptive_severity": "Low",
        "chaos_level":       1,
        "shell_response":    f"bash: {raw_input.split()[0] if raw_input.strip() else 'command'}: command not found",
    }

    try:
        threat_data   = classify_command(raw_input)
        response_type = "rule" if threat_data else None

        # Generate fake shell response for rule-matched threats
        if threat_data is not None:
            result["shell_response"] = _fake_response_for_rule(raw_input)

        # ── Step 2: AI Fallback (Sesh's code) ─────────────────────────────────
        if threat_data is None:
            logger.info(f"[ThreatService] Rule engine missed '{raw_input}' → calling AI")
            ai_result = classify_with_ai(raw_input, current_dir, session_fs)

            # Always use AI shell response for unknown commands
            result["shell_response"] = ai_result["shell_response"]

            if ai_result["threat_type"] not in NON_THREAT_TYPES:
                threat_data = {
                    "type":       ai_result["threat_type"],
                    "severity":   ai_result["severity"],
                    "confidence": ai_result["confidence"],
                }
                response_type = "ai"
                logger.info(
                    f"[ThreatService] AI classified '{raw_input}' → "
                    f"{threat_data['type']} ({threat_data['severity']})"
                )
            else:
                response_type = "unknown"
                logger.debug(
                    f"[ThreatService] AI returned '{ai_result['threat_type']}' "
                    f"for '{raw_input}' — no threat"
                )

        # ── Step 3: Threat detected — persist + adapt ──────────────────────────
        if threat_data is not None:
            insert_threat(
                session_id=session_id,
                command_id=command_id,
                threat_type=threat_data["type"],
                severity=threat_data["severity"],
                confidence=threat_data["confidence"],
                source=response_type,
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