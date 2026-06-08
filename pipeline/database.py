import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from pipeline.config import DB_PATH

log = logging.getLogger(__name__)


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS processed_updates (
                update_id TEXT PRIMARY KEY,
                processed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cve_state (
                cve_id      TEXT PRIMARY KEY,
                update_id   TEXT NOT NULL,
                title       TEXT,
                binary_name TEXT,
                kb_number   TEXT,
                status      TEXT NOT NULL DEFAULT 'pending',
                error_msg   TEXT,
                diff_path   TEXT,
                blog_path   TEXT,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
        """)
    log.debug("Database initialised at %s", DB_PATH)


def is_update_processed(update_id: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM processed_updates WHERE update_id = ?", (update_id,)
        ).fetchone()
        return row is not None


def mark_update_processed(update_id: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO processed_updates (update_id, processed_at) VALUES (?, ?)",
            (update_id, datetime.utcnow().isoformat()),
        )


def upsert_cve(cve_id: str, update_id: str, title: str, binary_name: str | None, kb_number: str | None) -> None:
    now = datetime.utcnow().isoformat()
    with _connect() as conn:
        conn.execute(
            """INSERT INTO cve_state
               (cve_id, update_id, title, binary_name, kb_number, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
               ON CONFLICT(cve_id) DO UPDATE SET
                   title=excluded.title,
                   binary_name=excluded.binary_name,
                   kb_number=excluded.kb_number,
                   updated_at=excluded.updated_at
            """,
            (cve_id, update_id, title, binary_name, kb_number, now, now),
        )


def set_cve_status(cve_id: str, status: str, *, error: str | None = None,
                   diff_path: str | None = None, blog_path: str | None = None) -> None:
    now = datetime.utcnow().isoformat()
    with _connect() as conn:
        conn.execute(
            """UPDATE cve_state
               SET status=?, error_msg=?, diff_path=COALESCE(?, diff_path),
                   blog_path=COALESCE(?, blog_path), updated_at=?
               WHERE cve_id=?""",
            (status, error, diff_path, blog_path, now, cve_id),
        )


def get_cve(cve_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM cve_state WHERE cve_id=?", (cve_id,)).fetchone()
        return dict(row) if row else None
