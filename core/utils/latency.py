import random
import time

def inject_latency(command_category):

    # fast commands
    if command_category == "VALID":
        delay = random.uniform(0.02, 0.12)

    # suspicious commands appear heavier
    elif command_category == "SUSPICIOUS":
        delay = random.uniform(0.2, 0.6)

    # dangerous commands simulate security checks
    elif command_category == "DANGEROUS":
        delay = random.uniform(0.4, 1.0)

    else:
        delay = random.uniform(0.05, 0.2)

    time.sleep(delay)