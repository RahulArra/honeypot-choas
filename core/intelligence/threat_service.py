"""
Threat service orchestrator.

Flow:
1) rule detection
2) cache lookup
3) AI fallback
4) persist threat + adaptive score
"""

import json
import logging
from collections import OrderedDict

from core.adaptive.escalation import update_adaptive_score
from core.chaos.threat_map import get_rule_based_experiment
from core.chaos.experiments import validate_experiment_config
from core.database.db_client import safe_execute
from core.database.queries import insert_threat, update_command_response_type
from core.intelligence.ai_classifier import classify_with_ai
from core.intelligence.classifier import classify_command, normalize_command

logger = logging.getLogger(__name__)

NON_THREAT_TYPES = {"Benign", "Unknown"}
CACHE_MAX_SIZE = 256
AI_CONFIDENCE_THRESHOLD = 0.6

SAFE_COMMANDS = {"ls", "pwd", "cd", "mkdir", "touch", "rmdir", "echo", "clear", "exit", "logout"}

RULE_FAKE_RESPONSES = {
    "wget": "Connecting to {host}... HTTP request sent, awaiting response... 200 OK\nSaving to: '{file}'\n{file} 100%[=================================================>] 1.00K  --.-KB/s",
    "curl": "  % Total    % Received % Xferd  Average Speed\n100  1024  100  1024    0     0   2048      0 --:--:-- --:--:-- 0",
    "sudo": "[sudo] password for root:",
    "chmod": "mode of '/tmp/agent.bin' changed from 0644 (rw-r--r--) to 0777 (rwxrwxrwx)",
    "default": "Process completed successfully.\nNo terminal errors were reported.",
}


def _load_ai_cache_from_db() -> dict:
    cache = OrderedDict()
    try:
        rows = safe_execute(
            """
            SELECT c.parsed_command, c.response_text, t.threat_type, t.severity, t.confidence,
                   t.experiment_type, t.experiment_intensity, t.experiment_duration
            FROM commands c
            LEFT JOIN threats t ON c.command_id = t.command_id
            WHERE c.response_type = 'ai'
              AND c.parsed_command IS NOT NULL
            ORDER BY c.timestamp DESC
            """,
            fetch=True,
        )
        if rows:
            for row in rows:
                cmd = row[0]
                if cmd and cmd not in cache:
                    cache[cmd] = {
                        "shell_response": row[1] or RULE_FAKE_RESPONSES["default"],
                        "threat_type": row[2] or "Unknown",
                        "severity": row[3] or "Low",
                        "confidence": float(row[4]) if row[4] else 0.0,
                        "experiment": {"type": row[5] or "cpu_stress", "intensity": row[6] or 1, "duration": row[7] or 10},
                    }
                    if len(cache) > CACHE_MAX_SIZE:
                        cache.popitem(last=False)
            logger.info("[ThreatService] Loaded %s AI-learned commands from DB", len(cache))
        else:
            logger.info("[ThreatService] No AI-learned commands in DB yet")
    except Exception as exc:
        logger.warning("[ThreatService] Could not load AI cache from DB: %s", exc)
    return cache


_AI_CACHE = _load_ai_cache_from_db()


def _fake_response_for_rule(raw_input: str) -> str:
    parts = raw_input.strip().split()
    cmd = parts[0].lower() if parts else ""
    if cmd == "wget" and len(parts) > 1:
        url = parts[1]
        filename = url.split("/")[-1] or "index.html"
        host = url.split("/")[2] if len(url.split("/")) > 2 else "unknown"
        return RULE_FAKE_RESPONSES["wget"].format(host=host, file=filename)
    return RULE_FAKE_RESPONSES.get(cmd, RULE_FAKE_RESPONSES["default"])


def _normalize_cache_key(raw_input: str) -> str:
    return normalize_command(raw_input)


def _is_noise_command(raw_input: str) -> bool:
    normalized = normalize_command(raw_input)
    if not normalized:
        return True
    # Ignore control-key residue/noise that has no actionable command token.
    if not any(ch.isalnum() for ch in normalized):
        return True
    return False


def _cache_get(cache_key):
    cached = _AI_CACHE.get(cache_key)
    if cached is not None:
        _AI_CACHE.move_to_end(cache_key)
    return cached


def _cache_put(cache_key, value):
    _AI_CACHE[cache_key] = value
    _AI_CACHE.move_to_end(cache_key)
    if len(_AI_CACHE) > CACHE_MAX_SIZE:
        _AI_CACHE.popitem(last=False)


def _log_event(event, **payload):
    logger.info(json.dumps({"event": event, **payload}))


def _deterministic_override(raw_input: str):
    normalized = _normalize_cache_key(raw_input)
    # Disk-heavy operations must not be treated as CPU exhaustion.
    if normalized.startswith("dd ") and ("if=/dev/zero" in normalized or "if=/dev/urandom" in normalized) and "of=" in normalized:
        return {
            "type": "Integrity_Risk",
            "severity": "High",
            "confidence": 0.98,
            "experiment": get_rule_based_experiment("Integrity_Risk", "High"),
            "source": "rule",
        }
    if normalized.startswith("fallocate ") and " -l " in f" {normalized} ":
        return {
            "type": "Integrity_Risk",
            "severity": "High",
            "confidence": 0.95,
            "experiment": get_rule_based_experiment("Integrity_Risk", "High"),
            "source": "rule",
        }
    if normalized.startswith("shred "):
        return {
            "type": "Integrity_Risk",
            "severity": "High",
            "confidence": 0.98,
            "experiment": get_rule_based_experiment("Integrity_Risk", "High"),
            "source": "rule",
        }
    return None


def _normalize_experiment_for_threat(threat_type: str, severity: str, experiment: dict):
    """
    Keep classification flexible for new commands, but always align experiment type
    with mapped threat semantics (CPU / memory / disk).
    """
    rule_exp = get_rule_based_experiment(threat_type, severity)
    ai_or_db_exp = validate_experiment_config(experiment or {})
    normalized = {
        "type": rule_exp["type"],  # canonical mapping by threat type
        "intensity": ai_or_db_exp.get("intensity", rule_exp["intensity"]),
        "duration": ai_or_db_exp.get("duration", rule_exp["duration"]),
    }
    return validate_experiment_config(normalized)


def handle_threat_detection(
    session_id: str,
    command_id: int,
    raw_input: str,
    current_dir: str = "/home/root",
    session_fs: dict = None,
) -> dict:
    if session_fs is None:
        session_fs = {}

    result = {
        "detected": False,
        "type": "Unknown",
        "severity": "Low",
        "confidence": 0.0,
        "source": "unknown",
        "adaptive_severity": "Low",
        "chaos_level": 1,
        "shell_response": RULE_FAKE_RESPONSES["default"],
    }

    cache_key = _normalize_cache_key(raw_input)
    if _is_noise_command(raw_input):
        _log_event("noise_command_skip", command=cache_key, source="sanitizer", threat_type="Unknown", risk_score=0.0)
        return result

    cmd_token = cache_key.split()[0] if cache_key else ""
    if not cmd_token or cache_key.startswith("#"):
        return result

    try:
        if cmd_token in SAFE_COMMANDS:
            _log_event("safe_command_skip", command=cache_key, source="safe_list", threat_type="Unknown", risk_score=0.0)
            return result

        override = _deterministic_override(raw_input)
        threat_data = None
        response_type = None

        if override:
            threat_data = {
                "type": override["type"],
                "severity": override["severity"],
                "confidence": override["confidence"],
                "experiment": override["experiment"],
            }
            response_type = override["source"]
            result["shell_response"] = _fake_response_for_rule(raw_input)
            _log_event("deterministic_override", command=cache_key, threat_type=threat_data["type"], source=response_type, risk_score=0.0)

        if threat_data is None:
            threat_data = classify_command(raw_input)
            response_type = "rule" if threat_data else None
            if threat_data is not None:
                result["shell_response"] = _fake_response_for_rule(raw_input)
                _log_event("rule_match", command=cache_key, threat_type=threat_data["type"], source="rule", risk_score=0.0)

        if threat_data is None:
            cached = _cache_get(cache_key)
            if cached is not None:
                _log_event("ai_cache_hit", command=cache_key, threat_type=cached["threat_type"], source="cache", risk_score=0.0)
                result["shell_response"] = cached["shell_response"]
                if cached["threat_type"] not in NON_THREAT_TYPES:
                    threat_data = {
                        "type": cached["threat_type"],
                        "severity": cached["severity"],
                        "confidence": cached["confidence"],
                        "experiment": cached["experiment"],
                    }
                    response_type = "ai"
                else:
                    response_type = "unknown"
            else:
                _log_event("ai_cache_miss", command=cache_key, threat_type="Unknown", source="ai", risk_score=0.0)
                ai_result = classify_with_ai(raw_input, current_dir, session_fs)
                result["shell_response"] = ai_result["shell_response"]

                if ai_result["confidence"] < AI_CONFIDENCE_THRESHOLD:
                    ai_result = {**ai_result, "threat_type": "Unknown", "severity": "Low", "confidence": 0.0}

                response_type = "ai" if ai_result["threat_type"] not in NON_THREAT_TYPES else "unknown"
                update_command_response_type(command_id, response_type, ai_result["shell_response"])

                _cache_put(
                    cache_key,
                    {
                        "shell_response": ai_result["shell_response"],
                        "threat_type": ai_result["threat_type"],
                        "severity": ai_result["severity"],
                        "confidence": ai_result["confidence"],
                        "experiment": ai_result.get("experiment"),
                    },
                )

                if ai_result["threat_type"] not in NON_THREAT_TYPES:
                    threat_data = {
                        "type": ai_result["threat_type"],
                        "severity": ai_result["severity"],
                        "confidence": ai_result["confidence"],
                        "experiment": ai_result.get("experiment"),
                    }
                    # Consistency guard: when AI says CPU but proposes disk_io, treat as disk risk.
                    ai_exp = (ai_result.get("experiment") or {}).get("type")
                    if threat_data["type"] == "CPU_Exhaustion" and ai_exp == "disk_io":
                        threat_data = {
                            "type": "Integrity_Risk",
                            "severity": "High" if threat_data["severity"] == "High" else "Medium",
                            "confidence": max(float(threat_data["confidence"]), 0.85),
                            "experiment": get_rule_based_experiment("Integrity_Risk", "High" if threat_data["severity"] == "High" else "Medium"),
                        }
                        response_type = "rule"
                    # Safety net: deterministic override still wins after AI.
                    override_after_ai = _deterministic_override(raw_input)
                    if override_after_ai:
                        threat_data = {
                            "type": override_after_ai["type"],
                            "severity": override_after_ai["severity"],
                            "confidence": override_after_ai["confidence"],
                            "experiment": override_after_ai["experiment"],
                        }
                        response_type = override_after_ai["source"]
                    _log_event("ai_classified", command=cache_key, threat_type=threat_data["type"], source=response_type, risk_score=0.0)
                else:
                    _log_event("ai_no_threat", command=cache_key, threat_type=ai_result["threat_type"], source="ai", risk_score=0.0)

        if threat_data is not None:
            threat_data["experiment"] = _normalize_experiment_for_threat(
                threat_data["type"],
                threat_data["severity"],
                threat_data.get("experiment"),
            )
            insert_threat(
                session_id=session_id,
                command_id=command_id,
                threat_type=threat_data["type"],
                severity=threat_data["severity"],
                confidence=threat_data["confidence"],
                source=response_type,
                experiment=threat_data.get("experiment"),
            )
            new_severity, new_intensity = update_adaptive_score(session_id, threat_data["type"])
            _log_event("threat_persisted", command=cache_key, threat_type=threat_data["type"], source=response_type, risk_score=0.0)

            result.update(
                {
                    "detected": True,
                    "type": threat_data["type"],
                    "severity": threat_data["severity"],
                    "confidence": threat_data["confidence"],
                    "source": response_type,
                    "adaptive_severity": new_severity,
                    "chaos_level": new_intensity,
                }
            )
    except Exception as exc:
        logger.error(json.dumps({"event": "threat_service_error", "command": cache_key, "error": str(exc)}), exc_info=True)

    return result
