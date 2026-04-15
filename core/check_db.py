import sqlite3
from core.config import DATABASE_PATH

conn = sqlite3.connect(DATABASE_PATH)
cursor = conn.cursor()

print("--- RECENT COMMAND LOGS ---")
cursor.execute("SELECT command_id, parsed_command, response_type FROM commands ORDER BY command_id DESC LIMIT 5;")
for row in cursor.fetchall():
    print(f"ID: {row[0]} | Cmd: {row[1]} | Type: {row[2]}")

conn.close()