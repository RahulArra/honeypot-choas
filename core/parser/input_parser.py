import re
from core.config import MAX_COMMAND_LENGTH


def normalize_input(raw_input):

    if not raw_input:
        return ""

    command = raw_input.strip()

    # remove multiple spaces
    command = re.sub(r"\s+", " ", command)

    return command


def enforce_length_limit(command):

    if len(command) > MAX_COMMAND_LENGTH:
        raise ValueError("Command exceeds maximum length")

    return command


def sanitize_input(raw_text):
    # This regex removes ANSI escape sequences (arrows, home, end, etc.)
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_text = ansi_escape.sub('', raw_text)
    
    # Existing sanitization (strip, etc.)
    return clean_text.strip()

def extract_command_token(command):

    if not command:
        return None

    parts = command.split()

    return parts[0]