from core.chaos.threat_map import get_rule_based_experiment

def normalize_command(raw_input):
    return " ".join((raw_input or "").strip().lower().split())


def _split_chained_commands(raw_input):
    normalized = normalize_command(raw_input)
    if not normalized or normalized.startswith("#"):
        return []
    return [segment.strip() for segment in normalized.split("&&") if segment.strip()]


def _starts_with_token(command, token):
    return command == token or command.startswith(f"{token} ")


THREAT_RULES = [
    {
        "id": "malware_wget",
        "type": "Malware_Download",
        "severity": "High",
        "confidence": 0.95,
        "check": lambda c: _starts_with_token(c, "wget")
    },
    {
        "id": "malware_curl",
        "type": "Malware_Download",
        "severity": "High",
        "confidence": 0.90,
        "check": lambda c: _starts_with_token(c, "curl")
    },
    {
        "id": "priv_esc_sudo",
        "type": "Privilege_Escalation",
        "severity": "Medium",
        "confidence": 1.0,
        "check": lambda c: any(
            phrase in c for phrase in ("sudo su", "sudo -i", "sudo bash", "sudo sh", "sudo -s")
        )
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
            _starts_with_token(c, "nmap") or
            _starts_with_token(c, "masscan") or
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

def classify_command(raw_input):
    """
    Pure Logic: Only analyzes text.
    Returns a dictionary of threat details if matched, else None.
    Ignores blank lines, comments, and pure whitespace.
    """
    commands = _split_chained_commands(raw_input)
    if not commands:
        return None

    for command in commands:
        for rule in THREAT_RULES:
            if rule["check"](command):
                return {
                    "type": rule["type"],
                    "severity": rule["severity"],
                    "confidence": max(0.0, min(float(rule["confidence"]), 1.0)),
                    "rule_id": rule["id"],
                    "command": command,
                    "experiment": get_rule_based_experiment(rule["type"], rule["severity"]),
                }

    return None
