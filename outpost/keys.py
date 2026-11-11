"""Named API keys: SHA-256 only, optional quotas, revocation. The SQL runs on a connection from
`outpost.schema.connect`; the server reads keys, `outpost-admin` writes them."""

import hashlib
import re
import secrets
import sqlite3
from dataclasses import dataclass

from outpost.schema import BOOTSTRAP_KEY_NAME

KEY_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
KEY_BYTES = 32


class KeyRefused(Exception):
    """An admin request that cannot be done; the message says why."""


@dataclass(frozen=True, slots=True)
class ApiKey:
    name: str
    max_channels: int | None
    channel_rate: int | None
    revoked: bool


@dataclass(frozen=True, slots=True)
class KeyListing:
    name: str
    created_at: str
    revoked_at: str | None
    max_channels: int | None
    channel_rate: int | None
    channels: int


def bootstrap_key() -> ApiKey:
    return ApiKey(name=BOOTSTRAP_KEY_NAME, max_channels=None, channel_rate=None, revoked=False)


def key_by_sha256(conn: sqlite3.Connection, key_sha256: str) -> ApiKey | None:
    row = conn.execute(
        "SELECT name, max_channels, channel_rate, revoked_at FROM api_keys WHERE key_sha256 = ?", (key_sha256,)
    ).fetchone()
    if row is None:
        return None
    return ApiKey(name=row[0], max_channels=row[1], channel_rate=row[2], revoked=row[3] is not None)


def has_active_keys(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM api_keys WHERE revoked_at IS NULL LIMIT 1").fetchone() is not None


def add_key(
    conn: sqlite3.Connection, name: str, now: str, *, max_channels: int | None, channel_rate: int | None
) -> str:
    """Store a new key's SHA-256 and return the key, which is not kept anywhere."""
    if not KEY_NAME.fullmatch(name):
        raise KeyRefused(f"key name must match {KEY_NAME.pattern}")
    if name == BOOTSTRAP_KEY_NAME:
        raise KeyRefused(f"{BOOTSTRAP_KEY_NAME!r} is the key OUTPOST_API_KEY_SHA256 sets")
    for label, value in (("max-channels", max_channels), ("channel-rate", channel_rate)):
        if value is not None and value < 1:
            raise KeyRefused(f"{label} must be at least 1")
    key = secrets.token_urlsafe(KEY_BYTES)
    try:
        conn.execute(
            "INSERT INTO api_keys (name, key_sha256, created_at, max_channels, channel_rate) VALUES (?, ?, ?, ?, ?)",
            (name, hashlib.sha256(key.encode()).hexdigest(), now, max_channels, channel_rate),
        )
    except sqlite3.IntegrityError as exc:
        raise KeyRefused(f"a key named {name!r} exists") from exc
    return key


def list_keys(conn: sqlite3.Connection) -> list[KeyListing]:
    rows = conn.execute(
        "SELECT k.name, k.created_at, k.revoked_at, k.max_channels, k.channel_rate,"
        " (SELECT COUNT(*) FROM channels c WHERE c.key_name = k.name)"
        " FROM api_keys k ORDER BY k.name"
    )
    return [
        KeyListing(
            name=row[0], created_at=row[1], revoked_at=row[2], max_channels=row[3], channel_rate=row[4], channels=row[5]
        )
        for row in rows
    ]


def revoke_key(conn: sqlite3.Connection, name: str, now: str, *, delete_channels: bool) -> int:
    """Revoke the key; with `delete_channels`, delete its channels and their records. Returns
    the number of channels deleted."""
    if name == BOOTSTRAP_KEY_NAME:
        raise KeyRefused(f"{BOOTSTRAP_KEY_NAME!r} is set by OUTPOST_API_KEY_SHA256; remove it there")
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT revoked_at FROM api_keys WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise KeyRefused(f"no key named {name!r}")
        if row[0] is None:
            conn.execute("UPDATE api_keys SET revoked_at = ? WHERE name = ?", (now, name))
        deleted = conn.execute("DELETE FROM channels WHERE key_name = ?", (name,)).rowcount if delete_channels else 0
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
    return deleted
