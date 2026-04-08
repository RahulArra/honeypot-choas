"""
Threat Map - Chaos Validation Engine
Maps threat_type -> experiment_type and base intensity.

Context-Aware Chaos Engineering:
  - Malware_Download      -> CPU stress (payload execution pressure)
  - Reconnaissance        -> Light CPU (scan response load)
  - Credential_Attack     -> Memory stress (auth/session pressure)
  - Data_Exfiltration     -> Disk I/O (mass read/write patterns)
  - Privilege_Escalation  -> Process disruption (service/process instability)
  - Integrity_Risk        -> Disk I/O (file/permission pressure)
  - Persistence_Attempt   -> Disk I/O (cron/profile write patterns)
  - Lateral_Movement      -> Memory stress (pivot/session overhead)
"""

from core.chaos.experiments import DEFAULT_SAFE_CONFIG, MAX_INTENSITY, validate_experiment_config

THREAT_TO_EXPERIMENT = {
    "Malware_Download": "cpu_stress",
    "Reconnaissance": "cpu_stress",
    "Credential_Attack": "memory_stress",
    "Data_Exfiltration": "disk_io",
    "Privilege_Escalation": "process_disruption",
    "Integrity_Risk": "disk_io",
    "Persistence_Attempt": "disk_io",
    "Lateral_Movement": "memory_stress",
    "CPU_Exhaustion": "cpu_stress",
}

DEFAULT_EXPERIMENT = "cpu_stress"

INTENSITY_DURATION = {
    1: 5,
    2: 10,
    3: 15,
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
