import sqlite3

conn = sqlite3.connect("database/honeypot.db")
cursor = conn.cursor()

cursor.execute("SELECT threat_type, occurrence_count, current_severity, chaos_intensity_level FROM adaptive_scores;")
print(cursor.fetchall())

conn.close()