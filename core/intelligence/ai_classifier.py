"""
AI Integration Layer — Honeypot Chaos Project
Member B (Sesh) Responsibility

Plugs into Rahul's classify_command() as fallback when rule engine returns None.
Uses Grok (Llama-3.1-8b-instant) via OpenAI-compatible API.

Returns:
    - threat_type, severity, confidence  (for threat intelligence)
    - shell_response                     (for fake shell output shown to attacker)
"""

import os
import json
import re
import logging
from typing import Optional
from openai import OpenAI

from core.chaos.experiments import DEFAULT_SAFE_CONFIG, validate_experiment_config
from core.intelligence.classifier import normalize_command

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

GROK_API_KEY  = os.environ.get("GROK_API_KEY", "")   # Set in environment, never hardcode
GROK_BASE_URL = "https://api.groq.com/openai/v1"                # Grok OpenAI-compatible endpoint
GROK_MODEL    = "llama-3.3-70b-versatile"          # xAI Grok model (cost-efficient, fast)

MAX_RETRIES   = 2       # One initial attempt + one retry
TIMEOUT_SECS  = 10      # Per-request timeout
MIN_CONFIDENCE = 0.6
MAX_SHELL_RESPONSE_CHARS = 400

# Valid threat types the AI is allowed to return (keeps output controlled)
VALID_THREAT_TYPES = {
    "Malware_Download",
    "Privilege_Escalation",
    "Integrity_Risk",
    "CPU_Exhaustion",
    "Reconnaissance",
    "Sensitive_Data_Access",
    "Data_Exfiltration",
    "Persistence_Attempt",
    "Lateral_Movement",
    "Unknown",
    "Benign",
}

VALID_SEVERITIES = {"Low", "Medium", "High"}

_CLIENT = None

# ── Prompt Builder ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a fake Linux shell running inside an SSH honeypot.

Your job is to analyze commands and return TWO things:
1. A threat classification
2. A REALISTIC fake Linux shell response — as if the command actually ran on a real Ubuntu 20.04 server

CRITICAL RULES FOR shell_response:
- NEVER return "command not found" — always simulate the command running
- For network tools (ifconfig, netstat, ss): return realistic network interface/connection data
- For system info (uname, uptime, id, whoami): return realistic system info
- For help/man commands: return realistic help text excerpt
- For file operations: return realistic file output
- For reconnaissance tools (nmap, ping, traceroute): return realistic scan output
- Make the output look like a real Ubuntu 20.04 server with normal services running
- Keep responses to 3-6 lines maximum

RESPONSE FORMAT (strict JSON, nothing else):
{
  "threat_type": "...",
  "severity": "...",
  "confidence": 0.0,
  "shell_response": "...",
  "experiment": {
    "type": "cpu_stress",
    "intensity": 1,
    "duration": 10
  }
}

threat_type must be one of: Malware_Download, Privilege_Escalation, Integrity_Risk, CPU_Exhaustion, Reconnaissance, Sensitive_Data_Access, Data_Exfiltration, Persistence_Attempt, Lateral_Movement, Unknown, Benign
severity must be one of: Low, Medium, High
confidence must be a float between 0.0 and 1.0
experiment.type must be one of: cpu_stress, memory_stress, disk_io, process_disruption
experiment.intensity must be an integer between 1 and 3
experiment.duration must be an integer between 5 and 20"""

def _build_user_prompt(command: str, current_dir: str, session_fs: dict) -> str:
    """Build the user message with session context for better AI accuracy."""
    fs_summary = json.dumps(session_fs, indent=2) if session_fs else "{}"
    return (
        f"Attacker's current directory: {current_dir}\n"
        f"Session filesystem snapshot:\n{fs_summary}\n\n"
        f"Command typed by attacker: {command}\n\n"
        f"Analyze this command and respond with the JSON object."
    )

# ── Core AI Call ───────────────────────────────────────────────────────────────

def _get_client():
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = OpenAI(
            api_key=GROK_API_KEY,
            base_url=GROK_BASE_URL,
            timeout=TIMEOUT_SECS,
        )
    return _CLIENT


def _safe_shell_response(command: str) -> str:
    normalized = normalize_command(command)
    if normalized.startswith("whoami"):
        return "root"
    if normalized.startswith("id"):
        return "uid=0(root) gid=0(root) groups=0(root)"
    if normalized.startswith("uname"):
        return "Linux ip-172-31-18-42 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux"
    if normalized.startswith("pwd"):
        return "/home/root"
    if normalized.startswith("cat "):
        return "root:x:0:0:root:/root:/bin/bash\nsys:x:3:3:sys:/dev:/usr/sbin/nologin"
    if normalized.startswith("ls"):
        return "drwxr-xr-x 2 root root 4096 Apr  6 12:00 backups\n-rw-r--r-- 1 root root  512 Apr  6 11:58 notes.txt"
    return "Process completed successfully.\nNo terminal errors were reported."


def _call_grok(command: str, current_dir: str, session_fs: dict) -> Optional[dict]:
    """
    Single attempt to call Grok API.
    Returns parsed dict on success, None on any failure.
    """
    try:
        try:
            response = _get_client().chat.completions.create(
                model=GROK_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": _build_user_prompt(command, current_dir, session_fs)},
                ],
                max_tokens=200,
                temperature=0.2,
                response_format={"type": "json_object"},
            )
        except Exception:
            # Fallback for providers/models that ignore or reject response_format.
            response = _get_client().chat.completions.create(
                model=GROK_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": _build_user_prompt(command, current_dir, session_fs)},
                ],
                max_tokens=200,
                temperature=0.2,
            )

        raw_text = response.choices[0].message.content.strip()
        logger.debug("[AI] Received response for command '%s' (%s chars)", command, len(raw_text))
        parsed = _parse_ai_json_payload(raw_text)
        return parsed

    except json.JSONDecodeError as e:
        logger.warning(f"[AI] JSON parse failed for '{command}': {e}")
        return None
    except Exception as e:
        logger.warning(f"[AI] API call failed for '{command}': {e}")
        return None


def _parse_ai_json_payload(raw_text: str) -> dict:
    """
    Parse model output with small repair steps for common malformed JSON cases.
    """
    text = (raw_text or "").replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(text, strict=False)
    except json.JSONDecodeError:
        pass

    # Extract the broadest JSON-looking object first.
    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        text = text[first:last + 1]

    # Repair common shell_response issue: raw newlines and unescaped quotes in string.
    shell_pat = re.compile(r'("shell_response"\s*:\s*")(.*?)("(\s*,\s*"\w+"\s*:|\s*}))', re.DOTALL)

    def _fix_shell_response(match):
        value = match.group(2)
        value = value.replace("\\", "\\\\").replace('"', '\\"')
        value = value.replace("\r\n", "\\n").replace("\n", "\\n")
        return f'{match.group(1)}{value}{match.group(3)}'

    repaired = shell_pat.sub(_fix_shell_response, text, count=1)
    try:
        return json.loads(repaired, strict=False)
    except json.JSONDecodeError:
        pass

    # Final fallback: salvage key fields even when shell_response JSON is broken.
    threat_match = re.search(
        r'"threat_type"\s*:\s*"(?P<threat>Malware_Download|Privilege_Escalation|Integrity_Risk|CPU_Exhaustion|Reconnaissance|Sensitive_Data_Access|Data_Exfiltration|Persistence_Attempt|Lateral_Movement|Unknown|Benign)"',
        text,
    )
    severity_match = re.search(r'"severity"\s*:\s*"(?P<severity>Low|Medium|High)"', text)
    confidence_match = re.search(r'"confidence"\s*:\s*(?P<confidence>[0-9]*\.?[0-9]+)', text)
    exp_type_match = re.search(r'"type"\s*:\s*"(?P<exp_type>cpu_stress|memory_stress|disk_io|process_disruption)"', text)
    exp_int_match = re.search(r'"intensity"\s*:\s*(?P<intensity>[1-3])', text)
    exp_dur_match = re.search(r'"duration"\s*:\s*(?P<duration>\d+)', text)

    if threat_match:
        return {
            "threat_type": threat_match.group("threat"),
            "severity": severity_match.group("severity") if severity_match else "Low",
            "confidence": float(confidence_match.group("confidence")) if confidence_match else 0.6,
            "shell_response": _safe_shell_response(""),
            "experiment": {
                "type": exp_type_match.group("exp_type") if exp_type_match else "cpu_stress",
                "intensity": int(exp_int_match.group("intensity")) if exp_int_match else 1,
                "duration": int(exp_dur_match.group("duration")) if exp_dur_match else 10,
            },
        }

    # Bubble up parse error path if we cannot salvage any structured signal.
    raise json.JSONDecodeError("Unable to parse or salvage AI JSON response", text, 0)

# ── Validator ──────────────────────────────────────────────────────────────────

def _validate_and_clean(parsed: dict) -> Optional[dict]:
    """
    Validate AI response fields.
    Returns cleaned dict or None if critically malformed.
    """
    if not isinstance(parsed, dict):
        return None

    threat_type    = parsed.get("threat_type", "Unknown")
    severity       = parsed.get("severity", "Low")
    confidence     = parsed.get("confidence", 0.5)
    shell_response = parsed.get("shell_response", _safe_shell_response(parsed.get("command", "")))

    # Sanitize threat_type
    if threat_type not in VALID_THREAT_TYPES:
        logger.warning(f"[AI] Invalid threat_type '{threat_type}', defaulting to Unknown")
        threat_type = "Unknown"

    # Sanitize severity
    if severity not in VALID_SEVERITIES:
        logger.warning(f"[AI] Invalid severity '{severity}', defaulting to Low")
        severity = "Low"

    # Sanitize confidence
    try:
        confidence = float(confidence)
        confidence = max(0.0, min(1.0, confidence))   # Clamp to [0.0, 1.0]
    except (TypeError, ValueError):
        confidence = 0.5

    # Sanitize shell_response
    if not isinstance(shell_response, str) or not shell_response.strip():
        shell_response = _safe_shell_response("")
    shell_response = shell_response.strip()[:MAX_SHELL_RESPONSE_CHARS]

    # Sanitize experiment
    experiment_raw = parsed.get("experiment", {})
    experiment = validate_experiment_config(experiment_raw)

    return {
        "threat_type":    threat_type,
        "severity":       severity,
        "confidence":     confidence,
        "shell_response": shell_response,
        "experiment":     experiment,
        "source":         "ai",         # Marks this as AI-classified for DB
    }

# ── Public Interface ───────────────────────────────────────────────────────────

# Safe fallback returned when AI completely fails
_FALLBACK_RESULT = {
    "threat_type":    "Unknown",
    "severity":       "Low",
    "confidence":     0.0,
    "shell_response": "root",
    "experiment":     DEFAULT_SAFE_CONFIG.copy(),
    "source":         "ai",
}

def classify_with_ai(
    command: str,
    current_dir: str = "/home/root",
    session_fs: dict = None,
) -> dict:
    """
    Public entry point — called by threat_service.py when rule engine returns None.

    Args:
        command:     Raw command string typed by attacker
        current_dir: Attacker's current working directory in fake shell
        session_fs:  Current session filesystem snapshot (for context)

    Returns:
        dict with keys: threat_type, severity, confidence, shell_response, source
        Never raises — always returns a safe fallback on failure.

    Example return:
        {
            "threat_type":    "Reconnaissance",
            "severity":       "Low",
            "confidence":     0.78,
            "shell_response": "uid=0(root) gid=0(root) groups=0(root)",
            "source":         "ai"
        }
    """
    if session_fs is None:
        session_fs = {}

    if not command or not command.strip():
        logger.debug("[AI] Empty command received, skipping AI call")
        return _FALLBACK_RESULT.copy()

    if not GROK_API_KEY:
        logger.error("[AI] GROK_API_KEY not set in environment — AI fallback disabled")
        return _FALLBACK_RESULT.copy()

    # Attempt with one retry
    for attempt in range(1, MAX_RETRIES + 1):
        logger.info(f"[AI] Attempt {attempt}/{MAX_RETRIES} for command: '{command}'")
        raw_result = _call_grok(command, current_dir, session_fs)

        if raw_result is not None:
            cleaned = _validate_and_clean(raw_result)
            if cleaned is not None:
                if cleaned["confidence"] < MIN_CONFIDENCE:
                    logger.info(
                        "[AI] Ignoring low-confidence classification for '%s' (%.2f)",
                        command,
                        cleaned["confidence"],
                    )
                    return _FALLBACK_RESULT.copy()
                logger.info(
                    f"[AI] Classified '{command}' → {cleaned['threat_type']} "
                    f"({cleaned['severity']}, conf={cleaned['confidence']:.2f})"
                )
                return cleaned
            logger.warning(f"[AI] Attempt {attempt} returned invalid structure, retrying...")
        else:
            logger.warning(f"[AI] Attempt {attempt} failed (API/parse error), retrying...")

    # Both attempts failed
    logger.error(f"[AI] All {MAX_RETRIES} attempts failed for '{command}', using fallback")
    return _FALLBACK_RESULT.copy()


# ── AI Experiment Generator (Optional Upgrade) ────────────────────────────────

def generate_experiment_with_ai(threat_type: str, severity: str, command: str = "") -> dict:
    """
    Generates a custom chaos experiment configuration using AI.
    Includes a strict 2-second timeout and safe fallback.
    """
    if not GROK_API_KEY:
        return DEFAULT_SAFE_CONFIG.copy()
    
    prompt = f"""Generate a JSON chaos experiment configuration for:
Threat Type: {threat_type}
Severity: {severity}
Command: {command or "N/A"}

Constraints:
- type: one of [cpu_stress, memory_stress, disk_io, process_disruption]
- intensity: integer 1-3
- duration: integer 5-20

JSON Output only:"""

    try:
        response = _get_client().chat.completions.create(
            model=GROK_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=60,
            temperature=0.1,
            timeout=2  # Strict timeout for responsiveness
        )
        
        text = response.choices[0].message.content.strip().replace("```json", "").replace("```", "").strip()
        parsed = json.loads(text)
        return validate_experiment_config(parsed)
    except Exception as e:
        logger.warning(f"[AI] custom experiment generation timed out or failed ({e}). Using safety default.")
        return DEFAULT_SAFE_CONFIG.copy()


# ── Integration Guide (for threat_service.py) ─────────────────────────────────
#
#   from core.intelligence.classifier import classify_command
#   from core.intelligence.ai_classifier import classify_with_ai
#
#   def process_command(raw_input, session_id, command_id, current_dir, session_fs):
#       # Step 1: Try rule engine first (Rahul's code)
#       result = classify_command(raw_input)
#       source = "rule"
#
#       # Step 2: Rule engine missed it → AI fallback (Sesh's code)
#       if result is None:
#           ai_result = classify_with_ai(raw_input, current_dir, session_fs)
#           result = {
#               "type":       ai_result["threat_type"],
#               "severity":   ai_result["severity"],
#               "confidence": ai_result["confidence"],
#           }
#           source = ai_result["source"]
#           # Use ai_result["shell_response"] as the output shown to attacker
#
#       # Step 3: Only insert threat if it's not Benign/Unknown (your call)
#       if result["type"] not in ("Benign", "Unknown"):
#           insert_threat(session_id, command_id, result["type"],
#                         result["severity"], result["confidence"], source)
#           update_adaptive_score(session_id, result["type"], result["severity"])


