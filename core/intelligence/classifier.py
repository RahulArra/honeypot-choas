from core.database.queries import insert_threat
from core.adaptive.escalation import update_adaptive_score
# Refined Rule Engine: Pattern-based matching with confidence scores
THREAT_RULES = [
    {
        "id": "malware_wget",
        "type": "Malware_Download",
        "severity": "High",
        "confidence": 0.95,
        "check": lambda c: c.startswith("wget ")
    },
    {
        "id": "malware_curl",
        "type": "Malware_Download",
        "severity": "High",
        "confidence": 0.90,
        "check": lambda c: c.startswith("curl ")
    },
    {
        "id": "priv_esc_sudo",
        "type": "Privilege_Escalation",
        "severity": "Medium",
        "confidence": 1.0,
        "check": lambda c: c == "sudo su" or c == "sudo -i"
    },
    {
        "id": "integrity_chmod",
        "type": "Integrity_Risk",
        "severity": "High",
        "confidence": 0.85,
        "check": lambda c: "chmod 777" in c or "chmod +x" in c
    }
]

def classify_command(raw_input):
    """
    Pure Logic: Only analyzes text. 
    Returns a dictionary of threat details if matched, else None.
    """
    clean_cmd = raw_input.strip().lower()

    for rule in THREAT_RULES:
        if rule["check"](clean_cmd):
            return {
                "type": rule["type"],
                "severity": rule["severity"],
                "confidence": rule["confidence"]
            }
            
    return None