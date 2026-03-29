"""
Threat Map — Chaos Validation Engine
Maps threat_type → experiment_type and base intensity
"""

# Maps threat_type to experiment_type
THREAT_TO_EXPERIMENT = {
    "CPU_Exhaustion":      "cpu_stress",
    "Malware_Download":    "cpu_stress",
    "Privilege_Escalation":"memory_stress",
    "Integrity_Risk":      "disk_io",
    "Reconnaissance":      "cpu_stress",
    "Data_Exfiltration":   "disk_io",
    "Persistence_Attempt": "memory_stress",
    "Lateral_Movement":    "memory_stress",
}

# Default experiment if threat type not in map
DEFAULT_EXPERIMENT = "cpu_stress"

# Base duration (seconds) per intensity level
INTENSITY_DURATION = {
    1: 5,   # Low    → 5 seconds
    2: 10,  # Medium → 10 seconds
    3: 15,  # High   → 15 seconds
}

def get_experiment_type(threat_type: str) -> str:
    return THREAT_TO_EXPERIMENT.get(threat_type, DEFAULT_EXPERIMENT)

def get_duration(intensity_level: int) -> int:
    return INTENSITY_DURATION.get(intensity_level, 5)