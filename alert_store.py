
import sqlite3
from datetime import datetime, timedelta

DATABASE = "minisoc.db"
DEDUPLICATION_WINDOW_SECONDS = 60


def initialize_database():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT NOT NULL,
            rule TEXT NOT NULL,
            process TEXT,
            command TEXT,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()

    print("Mini SOC database initialized successfully.")


def save_alerts(alerts):
    """Save alerts while suppressing identical alerts within 60 seconds."""

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    saved_count = 0
    suppressed_count = 0

    try:
        for alert in alerts:
            severity = alert.get("severity")
            rule = alert.get("rule")
            process = alert.get("process")
            command = alert.get("command", "")

            cursor.execute("""
                SELECT id
                FROM alerts
                WHERE rule = ?
                  AND process IS ?
                  AND command = ?
                  AND detected_at >= datetime('now', ?)
                ORDER BY id DESC
                LIMIT 1
            """, (
                rule,
                process,
                command,
                f"-{DEDUPLICATION_WINDOW_SECONDS} seconds"
            ))

            existing = cursor.fetchone()

            if existing:
                suppressed_count += 1
                print(
                    f"[DEDUPLICATED] {rule} "
                    f"(existing alert ID: {existing[0]})"
                )
                continue

            cursor.execute("""
                INSERT INTO alerts
                (severity, rule, process, command)
                VALUES (?, ?, ?, ?)
            """, (severity, rule, process, command))

            saved_count += 1

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    print(f"{saved_count} alert(s) saved to database.")
    print(f"{suppressed_count} duplicate alert(s) suppressed.")

    return saved_count


def get_alerts():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, severity, rule, process, detected_at
        FROM alerts
        ORDER BY id DESC
    """)

    records = cursor.fetchall()
    connection.close()

    return records


if __name__ == "__main__":
    initialize_database()

    records = get_alerts()
    print("Existing alerts:", len(records))
