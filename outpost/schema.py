"""The SQLite file: its schema, the additions made to a store written by an earlier version, and
the certificate challenge values. Used by the server's store thread, by `outpost-admin` and by the
ACME hook, each through its own connection."""

import sqlite3
from pathlib import Path

DB_FILE_NAME = "outpost.sqlite3"
BUSY_TIMEOUT_SECONDS = 10.0
BOOTSTRAP_KEY_NAME = "default"  # the key OUTPOST_API_KEY_SHA256 names; channels from earlier versions have it

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS channels (
    channel_id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL UNIQUE,
    secret_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_call_at TEXT NOT NULL,
    last_seq INTEGER NOT NULL DEFAULT 0,
    dropped_total INTEGER NOT NULL DEFAULT 0,
    key_name TEXT NOT NULL DEFAULT '{BOOTSTRAP_KEY_NAME}',
    retention_days INTEGER
) STRICT;
CREATE TABLE IF NOT EXISTS records (
    channel_id TEXT NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    received_at TEXT NOT NULL,
    size INTEGER NOT NULL,
    sealed BLOB NOT NULL,
    PRIMARY KEY (channel_id, seq)
) STRICT;
CREATE INDEX IF NOT EXISTS records_received_at ON records(received_at);
CREATE TABLE IF NOT EXISTS api_keys (
    name TEXT PRIMARY KEY,
    key_sha256 TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    max_channels INTEGER,
    channel_rate INTEGER
) STRICT;
CREATE TABLE IF NOT EXISTS responses (
    response_id TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    path TEXT NOT NULL,
    spec TEXT NOT NULL,
    body BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    UNIQUE (channel_id, token, path)
) STRICT;
CREATE TABLE IF NOT EXISTS acme_challenges (
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (name, value)
) STRICT;
"""

# Columns added to `channels` after its first version; ALTER TABLE adds them to an existing store.
_CHANNEL_ADDITIONS = (
    ("key_name", f"TEXT NOT NULL DEFAULT '{BOOTSTRAP_KEY_NAME}'"),
    ("retention_days", "INTEGER"),
)


def connect(data_dir: Path) -> sqlite3.Connection:
    """Open (creating when missing) the store in `data_dir`, in autocommit mode with WAL."""
    data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(data_dir / DB_FILE_NAME, isolation_level=None, timeout=BUSY_TIMEOUT_SECONDS)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    present = {row[1] for row in conn.execute("PRAGMA table_info(channels)")}
    for column, definition in _CHANNEL_ADDITIONS:
        if column not in present:
            conn.execute(f"ALTER TABLE channels ADD COLUMN {column} {definition}")
    conn.execute("CREATE INDEX IF NOT EXISTS channels_key_name ON channels(key_name)")
    return conn


def challenge_name(zone: str) -> str:
    return f"_acme-challenge.{zone}"


def add_challenge(conn: sqlite3.Connection, name: str, value: str, now: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO acme_challenges (name, value, created_at) VALUES (?, ?, ?)", (name.lower(), value, now)
    )


def remove_challenge(conn: sqlite3.Connection, name: str, value: str) -> None:
    conn.execute("DELETE FROM acme_challenges WHERE name = ? AND value = ?", (name.lower(), value))


def challenge_values(conn: sqlite3.Connection) -> dict[str, tuple[str, ...]]:
    """Every name's current values, in the order they were written."""
    values: dict[str, list[str]] = {}
    for name, value in conn.execute("SELECT name, value FROM acme_challenges ORDER BY created_at, value"):
        values.setdefault(name, []).append(value)
    return {name: tuple(found) for name, found in values.items()}
