VALID = "VALID"
VALID_IMPROPER = "VALID_IMPROPER"
UNKNOWN = "UNKNOWN"
SUSPICIOUS = "SUSPICIOUS"
DANGEROUS = "DANGEROUS"

VALID_COMMANDS = {
    "ls",
    "cd",
    "pwd",
    "mkdir",
    "touch",
    "rm",
    "cat"
}

SUSPICIOUS_KEYWORDS = {
    "wget",
    "curl"
}

DANGEROUS_PATTERNS = {
    "sudo su",
    "chmod 777 /"
}