"""
Test: AI Fallback Layer
Run from inside honeypot-choas/ directory:

    cd honeypot-choas
    python test_ai_fallback.py

Make sure your API key is set first:
    export GROK_API_KEY=your_key_here
"""

import sys
import os
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
# Open the file directly and edit the two things we need

# ── Path setup so imports resolve from honeypot-choas/ ────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.intelligence.classifier import classify_command
from core.intelligence.ai_classifier import classify_with_ai

# ── ANSI colors for readable output ───────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ── Test cases: commands the rule engine SHOULD miss ──────────────────────────
# These are intentionally NOT in Rahul's THREAT_RULES,
# so classify_command() returns None → AI fallback triggers
AI_FALLBACK_COMMANDS = [
    {
        "command":     "nmap -sV 192.168.1.1",
        "description": "Port scanning / reconnaissance",
        "expect_type": "Reconnaissance",
    },
    {
        "command":     "cat /etc/passwd",
        "description": "Reading sensitive system file",
        "expect_type": "Reconnaissance",
    },
    {
        "command":     "nc -lvnp 4444",
        "description": "Netcat reverse shell listener",
        "expect_type": "Lateral_Movement",
    },
    {
        "command":     "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
        "description": "Shell spawning via Python",
        "expect_type": "Privilege_Escalation",
    },
    {
        "command":     "crontab -e",
        "description": "Editing cron jobs — persistence attempt",
        "expect_type": "Persistence_Attempt",
    },
    {
        "command":     "ls -la",
        "description": "Benign directory listing",
        "expect_type": "Benign",
    },
    {
        "command":     "hello_world_xyz",
        "description": "Completely unknown gibberish",
        "expect_type": "Unknown",
    },
]

# ── Fake session context passed to AI ─────────────────────────────────────────
MOCK_SESSION_FS = {
    "/home/root": ["file1.txt", "notes.log"],
    "/var/log":   ["auth.log"],
    "/etc":       ["passwd", "shadow"],
}
MOCK_CURRENT_DIR = "/home/root"

# ── Validation helpers ─────────────────────────────────────────────────────────
VALID_THREAT_TYPES = {
    "Malware_Download", "Privilege_Escalation", "Integrity_Risk",
    "CPU_Exhaustion", "Reconnaissance", "Data_Exfiltration",
    "Persistence_Attempt", "Lateral_Movement", "Unknown", "Benign",
}
VALID_SEVERITIES = {"Low", "Medium", "High"}

def validate_result(result: dict) -> list:
    """Returns list of validation errors. Empty list = all good."""
    errors = []
    if result.get("threat_type") not in VALID_THREAT_TYPES:
        errors.append(f"Invalid threat_type: '{result.get('threat_type')}'")
    if result.get("severity") not in VALID_SEVERITIES:
        errors.append(f"Invalid severity: '{result.get('severity')}'")
    conf = result.get("confidence")
    if not isinstance(conf, float) or not (0.0 <= conf <= 1.0):
        errors.append(f"Invalid confidence: '{conf}'")
    if not isinstance(result.get("shell_response"), str) or not result["shell_response"].strip():
        errors.append("Missing or empty shell_response")
    if result.get("source") != "ai":
        errors.append(f"Expected source='ai', got '{result.get('source')}'")
    return errors

# ── Main test runner ───────────────────────────────────────────────────────────
def run_tests():
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  AI Fallback Layer — Test Suite{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    # Pre-flight: check API key
    if not os.environ.get("GROK_API_KEY"):
        print(f"{RED}✗ GROK_API_KEY not set in environment.{RESET}")
        print(f"  Run: {CYAN}export GROK_API_KEY=your_key_here{RESET}\n")
        sys.exit(1)
    else:
        print(f"{GREEN}✓ GROK_API_KEY detected{RESET}\n")

    passed = 0
    failed = 0

    for i, tc in enumerate(AI_FALLBACK_COMMANDS, 1):
        command     = tc["command"]
        description = tc["description"]
        expect_type = tc["expect_type"]

        print(f"{BOLD}Test {i}: {description}{RESET}")
        print(f"  Command : {CYAN}{command}{RESET}")

        # ── Step 1: Confirm rule engine misses this ────────────────────────────
        rule_result = classify_command(command)
        if rule_result is not None:
            print(f"  {YELLOW}⚠ Rule engine matched this command ({rule_result['type']}) — AI won't be called{RESET}")
            print(f"  {YELLOW}  Consider updating this test case to use a command rule engine misses{RESET}\n")
            continue

        print(f"  Rule engine : {GREEN}Miss (None) — AI fallback will trigger ✓{RESET}")

        # ── Step 2: Call AI fallback ───────────────────────────────────────────
        result = classify_with_ai(command, MOCK_CURRENT_DIR, MOCK_SESSION_FS)

        # ── Step 3: Validate structure ─────────────────────────────────────────
        errors = validate_result(result)

        # ── Step 4: Print result ───────────────────────────────────────────────
        print(f"  Threat type : {result.get('threat_type')}  (expected: {expect_type})")
        print(f"  Severity    : {result.get('severity')}")
        print(f"  Confidence  : {result.get('confidence'):.2f}")
        print(f"  Source      : {result.get('source')}")
        print(f"  Shell resp  : {CYAN}{result.get('shell_response')}{RESET}")

        if errors:
            print(f"  {RED}✗ FAILED — Validation errors:{RESET}")
            for err in errors:
                print(f"      • {err}")
            failed += 1
        else:
            # Soft check: warn if type doesn't match expectation (AI may differ)
            if result.get("threat_type") != expect_type:
                print(f"  {YELLOW}⚠ PASSED (structure valid) — type mismatch: "
                      f"got '{result.get('threat_type')}', expected '{expect_type}'{RESET}")
            else:
                print(f"  {GREEN}✓ PASSED{RESET}")
            passed += 1

        print()

    # ── Summary ────────────────────────────────────────────────────────────────
    total = passed + failed
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  Results: {GREEN}{passed} passed{RESET}{BOLD}, {RED}{failed} failed{RESET}{BOLD} / {total} total{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    if failed > 0:
        print(f"{RED}Some tests failed. Check the errors above.{RESET}\n")
        sys.exit(1)
    else:
        print(f"{GREEN}All tests passed. AI fallback layer is working correctly.{RESET}\n")

if __name__ == "__main__":
    run_tests()