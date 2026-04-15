import re

from core.chaos.threat_map import get_rule_based_experiment

def normalize_command(raw_input):
    command = str(raw_input or "")
    # Remove ANSI/terminal escape sequences.
    command = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", command)
    # Remove prompt/special glyphs often pasted from terminal output.
    command = command.replace("❯", " ")
    # Drop remaining control characters, keep printable text only.
    command = re.sub(r"[\x00-\x1F\x7F]", "", command)
    # Normalize whitespace and lowercase for stable rule matching.
    return " ".join(command.strip().lower().split())


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
        "id": "disk_fill_dd",
        "type": "Integrity_Risk",
        "severity": "High",
        "confidence": 0.95,
        "check": lambda c: (
            _starts_with_token(c, "dd") and
            ("if=/dev/zero" in c or "if=/dev/urandom" in c) and
            "of=" in c
        )
    },
    {
        "id": "disk_fallocate",
        "type": "Integrity_Risk",
        "severity": "High",
        "confidence": 0.95,
        "check": lambda c: _starts_with_token(c, "fallocate") and "-l" in c
    },
    {
        "id": "disk_shred",
        "type": "Integrity_Risk",
        "severity": "High",
        "confidence": 0.95,
        "check": lambda c: _starts_with_token(c, "shred")
    },
    {
        "id": "disk_mass_touch",
        "type": "Integrity_Risk",
        "severity": "Medium",
        "confidence": 0.90,
        "check": lambda c: ("for i in" in c and "touch /tmp/file_" in c)
    },
    {
        "id": "data_exfil_openssl_enc",
        "type": "Data_Exfiltration",
        "severity": "Medium",
        "confidence": 0.85,
        "check": lambda c: _starts_with_token(c, "openssl enc") and "-in " in c and "-out " in c
    },
    {
        "id": "sensitive_data_read",
        "type": "Sensitive_Data_Access",
        "severity": "Medium",
        "confidence": 0.9,
        "check": lambda c: (
            c in ("cat /etc/passwd", "cat /etc/shadow")
            or ("cat " in c and "/etc/" in c and ("passwd" in c or "shadow" in c))
        )
    },
    {
        "id": "cpu_fork_bomb",
        "type": "CPU_Exhaustion",
        "severity": "High",
        "confidence": 0.98,
        "check": lambda c: ":(){ :|:& };:" in c or "fork bomb" in c
    },
    {
        "id": "cpu_yes_loop",
        "type": "CPU_Exhaustion",
        "severity": "Medium",
        "confidence": 0.92,
        "check": lambda c: (
            _starts_with_token(c, "yes") or
            ("yes > /dev/null" in c) or
            ("yes > dev/null" in c) or
            ("for i in $(seq $(nproc))" in c and "yes > /dev/null" in c) or
            ("while ($true)" in c and "[math]::sqrt" in c)
        )
    },
    {
        "id": "cpu_openssl_speed",
        "type": "CPU_Exhaustion",
        "severity": "Low",
        "confidence": 0.82,
        "check": lambda c: _starts_with_token(c, "openssl speed")
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
        "id": "recon_process_list",
        "type": "Reconnaissance",
        "severity": "Low",
        "confidence": 0.82,
        "check": lambda c: c in ("ps aux", "ps -ef", "top")
    },
    {
        "id": "recon_system",
        "type": "Reconnaissance",
        "severity": "Low",
        "confidence": 0.80,
        "check": lambda c: c in ("whoami", "id", "uname -a", "hostname")
    },
    {
        "id": "malware_exec_script",
        "type": "Malware_Download",
        "severity": "High",
        "confidence": 0.9,
        "check": lambda c: (
            (c.startswith("./") and c.endswith(".sh"))
            or ("bash " in c and ".sh" in c)
            or ("sh " in c and ".sh" in c)
        )
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
