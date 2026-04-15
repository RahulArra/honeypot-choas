"""
Threat Map - Chaos Validation Engine
Maps threat_type -> experiment_type and base intensity.

Context-Aware Chaos Engineering:
  - Malware_Download      -> Process disruption (execution/runtime impact)
  - Reconnaissance        -> None (lightweight/no chaos)
  - Credential_Attack     -> Process disruption (auth/service pressure)
  - Data_Exfiltration     -> Disk I/O (mass read/write patterns)
  - Privilege_Escalation  -> Process disruption (service/process instability)
  - Integrity_Risk        -> Disk I/O (file/permission pressure)
  - Persistence_Attempt   -> Disk I/O (cron/profile write patterns)
  - Lateral_Movement      -> Process disruption (pivot/service pressure)
"""

from core.chaos.experiments import DEFAULT_SAFE_CONFIG, MAX_INTENSITY, validate_experiment_config

THREAT_TO_EXPERIMENT = {
    "Malware_Download": "process_disruption",
    "Reconnaissance": None,
    "Sensitive_Data_Access": None,
    "Credential_Attack": "process_disruption",
    "Data_Exfiltration": "disk_io",
    "Privilege_Escalation": "process_disruption",
    "Integrity_Risk": "disk_io",
    "Persistence_Attempt": "disk_io",
    "Lateral_Movement": "process_disruption",
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

# Future-proof alias map so new/variant labels still route to a semantically
# aligned canonical threat class instead of falling back to CPU by default.
THREAT_ALIASES = {
    "network_scan": "Reconnaissance",
    "port_scan": "Reconnaissance",
    "service_discovery": "Reconnaissance",
    "host_discovery": "Reconnaissance",
    "banner_grab": "Reconnaissance",
    "banner_grabbing": "Reconnaissance",
    "recon": "Reconnaissance",
    "sensitive_data_access": "Sensitive_Data_Access",
    "credential_dump": "Sensitive_Data_Access",
    "passwd_read": "Sensitive_Data_Access",
    "credential_stuffing": "Credential_Attack",
    "bruteforce": "Credential_Attack",
    "brute_force": "Credential_Attack",
    "password_spray": "Credential_Attack",
    "reverse_shell": "Privilege_Escalation",
    "suid_enumeration": "Privilege_Escalation",
    "lpe": "Privilege_Escalation",
    "file_tamper": "Integrity_Risk",
    "wiper": "Integrity_Risk",
    "ransomware": "Integrity_Risk",
    "data_theft": "Data_Exfiltration",
    "exfiltration": "Data_Exfiltration",
    "beacon": "Persistence_Attempt",
    "backdoor": "Persistence_Attempt",
    "pivoting": "Lateral_Movement",
    "remote_exec": "Lateral_Movement",
    "cpu_dos": "CPU_Exhaustion",
}


def normalize_threat_type(threat_type: str) -> str:
    if not threat_type:
        return ""
    normalized = " ".join(str(threat_type).replace("-", "_").split()).lower()
    normalized_key = normalized.replace(" ", "_")
    alias = THREAT_ALIASES.get(normalized_key)
    if alias:
        return alias
    for known in THREAT_TO_EXPERIMENT:
        if known.lower() == normalized:
            return known
    for known in THREAT_TO_EXPERIMENT:
        known_key = known.lower().replace(" ", "_")
        if known_key in normalized_key or normalized_key in known_key:
            return known
    return threat_type


def get_experiment_type(threat_type: str) -> str:
    normalized = normalize_threat_type(threat_type)
    if normalized in THREAT_TO_EXPERIMENT:
        return THREAT_TO_EXPERIMENT.get(normalized)
    return DEFAULT_EXPERIMENT


def get_duration(intensity_level: int) -> int:
    try:
        intensity_level = max(1, min(int(intensity_level), MAX_INTENSITY))
    except (TypeError, ValueError):
        intensity_level = DEFAULT_SAFE_CONFIG["intensity"]
    return INTENSITY_DURATION.get(intensity_level, 5)


def get_rule_based_experiment(threat_type: str, severity: str) -> dict:
    intensity_map = {"Low": 1, "Medium": 2, "High": 3}
    intensity = intensity_map.get(severity, 1)
    normalized_threat = normalize_threat_type(threat_type)
    if normalized_threat in {"Reconnaissance", "Sensitive_Data_Access"}:
        # Keep recon/data-read validation lightweight by default.
        intensity = 1
    mapped_type = get_experiment_type(normalized_threat) or DEFAULT_EXPERIMENT
    config = {
        "type": mapped_type,
        "intensity": intensity,
        "duration": max(6, get_duration(intensity)),
        "confidence": SEVERITY_TO_CONFIDENCE.get(severity, 0.75),
        "alternates": [mapped_type] if mapped_type else [],
    }
    if normalized_threat == "Privilege_Escalation":
        config["alternates"] = ["process_disruption", "memory_stress"]
    validated = validate_experiment_config(config)
    validated["confidence"] = config["confidence"]
    validated["alternates"] = config["alternates"]
    return validated
