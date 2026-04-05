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
        "check": lambda c: c in ("sudo su", "sudo -i", "sudo bash", "sudo sh")
    },
    {
        "id": "integrity_chmod",
        "type": "Integrity_Risk",
        "severity": "High",
        "confidence": 0.85,
        "check": lambda c: "chmod 777" in c or "chmod +x" in c
    },
    {
        "id": "credential_brute",
        "type": "Credential_Attack",
        "severity": "Medium",
        "confidence": 0.90,
        "check": lambda c: (
            "login attempt" in c or
            "brute" in c or
            "hydra" in c or
            "medusa" in c or
            ("for" in c and ("ssh" in c or "login" in c or "pass" in c))
        )
    },
    {
        "id": "data_exfil_tar",
        "type": "Data_Exfiltration",
        "severity": "High",
        "confidence": 0.88,
        "check": lambda c: (
            ("tar" in c and (".tar" in c or "-c" in c)) or
            ("scp " in c) or
            ("rsync " in c and ("@" in c or "://" in c))
        )
    },
    {
        "id": "persistence_cron",
        "type": "Persistence_Attempt",
        "severity": "High",
        "confidence": 0.92,
        "check": lambda c: (
            "crontab" in c or
            "/etc/cron" in c or
            "~/.bashrc" in c or
            "~/.profile" in c or
            "/etc/rc.local" in c
        )
    },
    {
        "id": "recon_network",
        "type": "Reconnaissance",
        "severity": "Medium",
        "confidence": 0.85,
        "check": lambda c: (
            c.startswith("nmap") or
            c.startswith("masscan") or
            c in ("arp -a", "netstat", "ss -tulpn") or
            "netstat" in c
        )
    },
    {
        "id": "recon_system",
        "type": "Reconnaissance",
        "severity": "Low",
        "confidence": 0.80,
        "check": lambda c: c in ("whoami", "id", "uname -a", "hostname", "cat /etc/passwd", "cat /etc/shadow")
    },
]

from core.chaos.threat_map import get_rule_based_experiment

def classify_command(raw_input):
    """
    Pure Logic: Only analyzes text.
    Returns a dictionary of threat details if matched, else None.
    Ignores blank lines, comments, and pure whitespace.
    """
    clean_cmd = raw_input.strip().lower()

    # Ignore blank lines, shell comments, pure whitespace
    if not clean_cmd or clean_cmd.startswith("#"):
        return None

    for rule in THREAT_RULES:
        if rule["check"](clean_cmd):
            return {
                "type": rule["type"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "experiment": get_rule_based_experiment(rule["type"], rule["severity"])
            }

    return None