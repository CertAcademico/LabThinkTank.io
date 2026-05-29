import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.getenv("DB_PATH", "/data/cti.db")


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS iocs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc           TEXT    NOT NULL UNIQUE,
                type          TEXT    NOT NULL DEFAULT 'UNKNOWN',
                threat_actor  TEXT    NOT NULL DEFAULT 'Unknown',
                severity      TEXT    NOT NULL DEFAULT 'medium',
                mitre         TEXT    NOT NULL DEFAULT '',
                country       TEXT    NOT NULL DEFAULT 'Unknown',
                source        TEXT    NOT NULL DEFAULT 'uploaded',
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                severity      TEXT    NOT NULL,
                title         TEXT    NOT NULL,
                description   TEXT    NOT NULL DEFAULT '',
                mitre         TEXT    NOT NULL DEFAULT '',
                source        TEXT    NOT NULL DEFAULT 'manual',
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT    NOT NULL,
                email         TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                role          TEXT    NOT NULL DEFAULT 'student',
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_iocs_ioc ON iocs(ioc);
            CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        """)


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)
