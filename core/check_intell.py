import sqlite3

conn = sqlite3.connect("database/honeypot.db")
cursor = conn.cursor()

cursor.execute("SELECT threat_id, threat_type, severity FROM threats;")
print(cursor.fetchall())

conn.close()