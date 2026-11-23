
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
import uuid


DATABASE = Path(__file__).resolve().parent / "minisoc.db"

VALID_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}

VALID_STATUSES = {
    "OPEN",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
    "CLOSED"
}


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_incident_tables():
    """Create incident-response tables without changing alerts."""

    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                assigned_to TEXT,
                resolution TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                closed_at TEXT
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                linked_at TEXT NOT NULL,
                UNIQUE(incident_id, alert_id),
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id) ON DELETE CASCADE,
                FOREIGN KEY (alert_id)
                    REFERENCES alerts(id)
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                analyst TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id) ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                evidence_type TEXT NOT NULL,
                description TEXT NOT NULL,
                file_path TEXT,
                collected_by TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id) ON DELETE CASCADE
            )
        """)

        connection.commit()

    print("Incident management tables initialized.")


def create_incident(
    title,
    description,
    severity,
    assigned_to=None
):
    severity = severity.upper()

    if severity not in VALID_SEVERITIES:
        raise ValueError("Invalid incident severity.")

    if not title or not title.strip():
        raise ValueError("Incident title is required.")

    now = datetime.now(timezone.utc).isoformat()
    case_id = "MINISOC-" + uuid.uuid4().hex[:8].upper()

    with get_connection() as connection:

        cursor = connection.execute("""
            INSERT INTO incidents (
                case_id,
                title,
                description,
                severity,
                status,
                assigned_to,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, 'OPEN', ?, ?, ?)
        """, (
            case_id,
            title.strip(),
            description,
            severity,
            assigned_to,
            now,
            now
        ))

        incident_id = cursor.lastrowid

    return {
        "id": incident_id,
        "case_id": case_id,
        "status": "OPEN"
    }


def link_alert_to_incident(incident_id, alert_id):
    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:

        incident = connection.execute(
            "SELECT id FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

        alert = connection.execute(
            "SELECT id FROM alerts WHERE id = ?",
            (alert_id,)
        ).fetchone()

        if incident is None:
            raise ValueError("Incident not found.")

        if alert is None:
            raise ValueError("Alert not found.")

        connection.execute("""
            INSERT INTO incident_alerts (
                incident_id,
                alert_id,
                linked_at
            )
            VALUES (?, ?, ?)
        """, (incident_id, alert_id, now))


def add_investigation_note(incident_id, analyst, note):
    if not analyst or not analyst.strip():
        raise ValueError("Analyst name is required.")

    if not note or not note.strip():
        raise ValueError("Investigation note cannot be empty.")

    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:

        incident = connection.execute(
            "SELECT id FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

        if incident is None:
            raise ValueError("Incident not found.")

        connection.execute("""
            INSERT INTO incident_notes (
                incident_id,
                analyst,
                note,
                created_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            incident_id,
            analyst.strip(),
            note.strip(),
            now
        ))


def add_evidence(
    incident_id,
    evidence_type,
    description,
    collected_by,
    file_path=None
):
    if not evidence_type or not evidence_type.strip():
        raise ValueError("Evidence type is required.")

    if not description or not description.strip():
        raise ValueError("Evidence description is required.")

    if not collected_by or not collected_by.strip():
        raise ValueError("Collector name is required.")

    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:

        incident = connection.execute(
            "SELECT id FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

        if incident is None:
            raise ValueError("Incident not found.")

        connection.execute("""
            INSERT INTO incident_evidence (
                incident_id,
                evidence_type,
                description,
                file_path,
                collected_by,
                collected_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            incident_id,
            evidence_type.strip(),
            description.strip(),
            file_path,
            collected_by.strip(),
            now
        ))


def update_incident_status(
    incident_id,
    status,
    resolution=None
):
    status = status.upper()

    if status not in VALID_STATUSES:
        raise ValueError("Invalid incident status.")

    now = datetime.now(timezone.utc).isoformat()

    closed_at = now if status == "CLOSED" else None

    with get_connection() as connection:

        incident = connection.execute(
            "SELECT id FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

        if incident is None:
            raise ValueError("Incident not found.")

        connection.execute("""
            UPDATE incidents
            SET status = ?,
                resolution = COALESCE(?, resolution),
                updated_at = ?,
                closed_at = ?
            WHERE id = ?
        """, (
            status,
            resolution,
            now,
            closed_at,
            incident_id
        ))


def assign_incident(incident_id, analyst):
    if not analyst or not analyst.strip():
        raise ValueError("Analyst name is required.")

    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:

        cursor = connection.execute("""
            UPDATE incidents
            SET assigned_to = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            analyst.strip(),
            now,
            incident_id
        ))

        if cursor.rowcount == 0:
            raise ValueError("Incident not found.")


def get_incidents():
    with get_connection() as connection:

        records = connection.execute("""
            SELECT *
            FROM incidents
            ORDER BY id DESC
        """).fetchall()

    return [dict(record) for record in records]


def get_incident_details(incident_id):
    with get_connection() as connection:

        incident = connection.execute("""
            SELECT *
            FROM incidents
            WHERE id = ?
        """, (incident_id,)).fetchone()

        if incident is None:
            raise ValueError("Incident not found.")

        alerts = connection.execute("""
            SELECT a.*
            FROM alerts a
            INNER JOIN incident_alerts ia
                ON a.id = ia.alert_id
            WHERE ia.incident_id = ?
        """, (incident_id,)).fetchall()

        notes = connection.execute("""
            SELECT *
            FROM incident_notes
            WHERE incident_id = ?
            ORDER BY id DESC
        """, (incident_id,)).fetchall()

        evidence = connection.execute("""
            SELECT *
            FROM incident_evidence
            WHERE incident_id = ?
            ORDER BY id DESC
        """, (incident_id,)).fetchall()

    return {
        "incident": dict(incident),
        "alerts": [dict(row) for row in alerts],
        "notes": [dict(row) for row in notes],
        "evidence": [dict(row) for row in evidence]
    }


if __name__ == "__main__":
    initialize_incident_tables()
    print("Existing incidents:", len(get_incidents()))
