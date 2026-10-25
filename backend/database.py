"""
database.py — SQLite schema initialization and query helpers.
Database file: backend/incidents.db (auto-created on first run).
"""

import sqlite3
import json
import logging
import os
from datetime import datetime
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# Always resolve relative to this file's directory
DB_PATH = os.path.join(os.path.dirname(__file__), "incidents.db")


def get_connection() -> sqlite3.Connection:
    """Return a thread-safe SQLite connection with row factory."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create all required tables if they do not already exist."""
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS incidents (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                filename    TEXT    NOT NULL,
                analyzed_at TEXT    NOT NULL,
                error_count INTEGER NOT NULL DEFAULT 0,
                warn_count  INTEGER NOT NULL DEFAULT 0,
                severity    TEXT    NOT NULL DEFAULT 'LOW',
                summary     TEXT,
                evidence    TEXT,   -- JSON array of log lines
                causes      TEXT,   -- JSON array of possible causes
                actions     TEXT,   -- JSON array of recommended actions
                report      TEXT,   -- full generated report text
                metadata    TEXT    -- JSON blob for extra fields
            );

            CREATE TABLE IF NOT EXISTS incident_embeddings (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                embedding    BLOB    NOT NULL,  -- numpy array serialized as bytes
                text_snippet TEXT    NOT NULL   -- text that was embedded
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_analyzed_at
                ON incidents(analyzed_at DESC);
        """)
    logger.info("Database initialized at %s", DB_PATH)


# ──────────────────────────────────────────────────────────────────────────────
# Write helpers
# ──────────────────────────────────────────────────────────────────────────────

def save_incident(
    filename: str,
    error_count: int,
    warn_count: int,
    severity: str,
    summary: str,
    evidence: List[str],
    causes: List[str],
    actions: List[str],
    report: str,
    metadata: Optional[Dict] = None,
) -> int:
    """Insert one incident record and return its new ID."""
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO incidents
                (filename, analyzed_at, error_count, warn_count, severity,
                 summary, evidence, causes, actions, report, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                filename,
                datetime.utcnow().isoformat(),
                error_count,
                warn_count,
                severity,
                summary,
                json.dumps(evidence),
                json.dumps(causes),
                json.dumps(actions),
                report,
                json.dumps(metadata or {}),
            ),
        )
        incident_id = cur.lastrowid
    logger.info("Saved incident id=%s filename=%s", incident_id, filename)
    return incident_id


def save_embedding(incident_id: int, embedding_bytes: bytes, text_snippet: str) -> None:
    """Persist a MiniLM embedding for an incident."""
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO incident_embeddings (incident_id, embedding, text_snippet)
            VALUES (?, ?, ?)
            """,
            (incident_id, embedding_bytes, text_snippet),
        )


# ──────────────────────────────────────────────────────────────────────────────
# Read helpers
# ──────────────────────────────────────────────────────────────────────────────

def get_all_incidents(
    limit: int = 50,
    offset: int = 0,
    search: Optional[str] = None,
    severity: Optional[str] = None,
) -> List[Dict]:
    """Return paginated incident list (without full report text for performance)."""
    query = """
        SELECT id, filename, analyzed_at, error_count, warn_count,
               severity, summary
        FROM incidents
        WHERE 1=1
    """
    params: List[Any] = []

    if search:
        query += " AND (filename LIKE ? OR summary LIKE ?)"
        params += [f"%{search}%", f"%{search}%"]

    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())

    query += " ORDER BY analyzed_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_incident_by_id(incident_id: int) -> Optional[Dict]:
    """Return full incident record including report and parsed JSON fields."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()

    if row is None:
        return None

    record = dict(row)
    for field in ("evidence", "causes", "actions", "metadata"):
        try:
            record[field] = json.loads(record[field] or "[]")
        except (json.JSONDecodeError, TypeError):
            record[field] = []
    return record


def get_all_embeddings() -> List[Dict]:
    """Return all stored embeddings for similarity search."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT ie.id, ie.incident_id, ie.embedding, ie.text_snippet,
                   i.summary, i.filename, i.severity, i.analyzed_at
            FROM incident_embeddings ie
            JOIN incidents i ON i.id = ie.incident_id
            """
        ).fetchall()
    return [dict(r) for r in rows]


def get_incident_count() -> int:
    """Total number of stored incidents."""
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM incidents").fetchone()
    return row["cnt"]


def get_stats() -> Dict[str, int]:
    """Dashboard statistics: totals for incidents, errors, warnings."""
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS total_incidents,
                COALESCE(SUM(error_count), 0) AS total_errors,
                COALESCE(SUM(warn_count),  0) AS total_warnings,
                COALESCE(SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END), 0) AS critical_count,
                COALESCE(SUM(CASE WHEN severity='HIGH'     THEN 1 ELSE 0 END), 0) AS high_count
            FROM incidents
            """
        ).fetchone()
    return dict(row)
