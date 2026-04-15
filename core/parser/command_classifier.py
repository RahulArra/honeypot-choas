from core.utils.constants import (
    VALID,
    VALID_IMPROPER,
    UNKNOWN,
    SUSPICIOUS,
    DANGEROUS,
    VALID_COMMANDS,
    SUSPICIOUS_KEYWORDS,
    DANGEROUS_PATTERNS
)


def classify_command(command):

    if not command:
        return UNKNOWN

    lower_cmd = command.lower()

    token = lower_cmd.split()[0]

    # dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if lower_cmd.startswith(pattern):
            return DANGEROUS

    # suspicious commands
    if token in SUSPICIOUS_KEYWORDS:
        return SUSPICIOUS

    # valid commands
    if token in VALID_COMMANDS:

        # improper usage example
        if token == "cd" and len(lower_cmd.split()) == 1:
            return VALID_IMPROPER

        return VALID

    return UNKNOWN