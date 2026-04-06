"""
Threat Map — Chaos Validation Engine
Maps threat_type → experiment_type and base intensity.

Context-Aware Chaos Engineering:
  - Malware_Download      → CPU stress + disk I/O (simulates payload execution)
  - Reconnaissance        → Light CPU (simulates port scan response load)
  - Credential_Attack     → Memory stress (simulates auth handler overload)
  - Data_Exfiltration     → Disk I/O (simulates mass-read exfil patterns)
  - Privilege_Escalation  → Memory stress (simulates kernel escalation attempts)
  - Integrity_Risk        → Disk I/O (simulates file permission modification)
  - Persistence_Attempt   → Disk I/O (simulates cron/profile write patterns)
  - Lateral_Movement      → Memory stress (simulates pivoting session overhead)
"""

from core.chaos.experiments import DEFAULT_SAFE_CONFIG, MAX_INTENSITY, validate_experiment_config

# Maps threat_type to the most contextually appropriate experiment_type
THREAT_TO_EXPERIMENT = {
    "Malware_Download":     "cpu_stress",       # Payload execution burns CPU
    "Reconnaissance":       "cpu_stress",       # Light scan response
    "Credential_Attack":    "memory_stress",    # Auth handler / session overload
    "Data_Exfiltration":    "disk_io",          # Mass-read/write patterns
    "Privilege_Escalation": "memory_stress",    # Kernel-level memory pressure
    "Integrity_Risk":       "disk_io",          # File permission mass-writes
    "Persistence_Attempt":  "disk_io",          # Cron / profile disk writes
    "Lateral_Movement":     "memory_stress",    # Pivoting session overhead
    "CPU_Exhaustion":       "cpu_stress",
}

# Default experiment if threat type not in map
DEFAULT_EXPERIMENT = "cpu_stress"

# Base duration (seconds) per intensity level
INTENSITY_DURATION = {
    1: 5,   # Low    →  5 seconds
    2: 10,  # Medium → 10 seconds
    3: 15,  # High   → 15 seconds
}

SEVERITY_TO_CONFIDENCE = {
    "Low": 0.75,
    "Medium": 0.85,
    "High": 0.95,
}


def normalize_threat_type(threat_type: str) -> str:
    if not threat_type:
        return ""
    normalized = " ".join(str(threat_type).replace("-", "_").split()).lower()
    for known in THREAT_TO_EXPERIMENT:
        if known.lower() == normalized:
            return known
    return threat_type

def get_experiment_type(threat_type: str) -> str:
    return THREAT_TO_EXPERIMENT.get(normalize_threat_type(threat_type), DEFAULT_EXPERIMENT)

def get_duration(intensity_level: int) -> int:
    try:
        intensity_level = max(1, min(int(intensity_level), MAX_INTENSITY))
    except (TypeError, ValueError):
        intensity_level = DEFAULT_SAFE_CONFIG["intensity"]
    return INTENSITY_DURATION.get(intensity_level, 5)

def get_rule_based_experiment(threat_type: str, severity: str) -> dict:
    """Generate a contextually-aware chaos test config from threat type and severity."""
    intensity_map = {"Low": 1, "Medium": 2, "High": 3}
    intensity = intensity_map.get(severity, 1)
    config = {
        "type": get_experiment_type(threat_type),
        "intensity": intensity,
        "duration": get_duration(intensity),
        "confidence": SEVERITY_TO_CONFIDENCE.get(severity, 0.75),
        "alternates": [get_experiment_type(threat_type)],
    }
    validated = validate_experiment_config(config)
    validated["confidence"] = config["confidence"]
    validated["alternates"] = config["alternates"]
    return validated
