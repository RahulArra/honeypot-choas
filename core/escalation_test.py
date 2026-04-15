import sqlite3

from core.config import DATABASE_PATH


def main():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT threat_type, occurrence_count, current_severity, chaos_intensity_level
        FROM adaptive_scores
        """
    )
    rows = cursor.fetchall()
    conn.close()

    print(f"DB: {DATABASE_PATH}")
    print(rows)


if __name__ == "__main__":
    main()
