import sqlite3
import os

base_dir = os.path.dirname(os.path.abspath(__file__))
schema_path = os.path.join(base_dir, "schema.sql")
db_path = os.path.join(base_dir, "honeypot.db")

with open(schema_path, "r", encoding="utf-8") as f:
    schema = f.read()

conn = sqlite3.connect(db_path)
conn.execute("PRAGMA foreign_keys = ON;")
conn.execute("PRAGMA journal_mode=WAL;")
conn.execute("PRAGMA synchronous=NORMAL;")
conn.executescript(schema)
conn.commit()
conn.close()

print("Database initialized successfully.")
