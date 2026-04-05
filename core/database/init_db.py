import sqlite3
import os

def init_db():
    schema_path = os.path.join(os.path.dirname(__file__), "../../database/schema.sql")
    db_path = os.path.join(os.path.dirname(__file__), "../../database/honeypot.db")
    
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = f.read()
    
    conn = sqlite3.connect(db_path)
    conn.executescript(schema)
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == "__main__":
    init_db()