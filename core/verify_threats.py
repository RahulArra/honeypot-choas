import sqlite3
from core.config import DATABASE_PATH

conn = sqlite3.connect(DATABASE_PATH)
cursor = conn.cursor()

print(f"{'CMD':<15} | {'THREAT TYPE':<20} | {'SEVERITY':<10}")
print("-" * 50)

query = """
    SELECT c.raw_input, t.threat_type, t.severity 
    FROM commands c
    JOIN threats t ON c.command_id = t.command_id
"""

for row in cursor.execute(query).fetchall():
    print(f"{row[0]:<15} | {row[1]:<20} | {row[2]:<10}")

conn.close()