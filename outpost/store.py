"""SQLite store (WAL), its single-thread access, the held-size limits and the retention task.

For a record the store keeps `channel_id`, `seq`, `received_at`, `size` and `sealed`, nothing
else (CONTRACT section 6). Every SQLite call runs on one dedicated thread, so there is one
writer and the event loop never waits on the disk.
"""

import asyncio
import enum
import hmac
import logging
import secrets
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path

from outpost.config import Limits
from outpost.records import format_time, utc_now
from outpost.sealing import seal

log = logging.getLogger("outpost.store")

RETENTION_INTERVAL_SECONDS = 3600
_CHANNEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS channels (
    channel_id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL UNIQUE,
    secret_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_call_at TEXT NOT NULL,
    last_seq INTEGER NOT NULL DEFAULT 0,
    dropped_total INTEGER NOT NULL DEFAULT 0
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
"""


class StoreOutcome(enum.Enum):
    STORED = "stored"
    DROPPED = "dropped"
    NO_CHANNEL = "no_channel"


@dataclass(frozen=True, slots=True)
class Registration:
    channel_id: str
    created: bool


@dataclass(frozen=True, slots=True)
class ChannelStatus:
    last_seq: int
    held_records: int
    dropped_total: int


@dataclass(frozen=True, slots=True)
class StoredRecord:
    seq: int
    received_at: str
    sealed: bytes


@dataclass(frozen=True, slots=True)
class Page:
    records: tuple[StoredRecord, ...]
    more: bool
    dropped_total: int


@dataclass(frozen=True, slots=True)
class RetentionResult:
    records_deleted: int
    channels_deleted: tuple[str, ...]


class ChannelConflict(Exception):
    """The public key holds a channel registered with another secret."""


class Store:
    """The SQL. Used only from the Database thread."""

    def __init__(self, path: Path, limits: Limits, store_max_bytes: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, isolation_level=None)
        self._limits = limits
        self._store_max_bytes = store_max_bytes
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    def channel_ids(self) -> set[str]:
        return {row[0] for row in self._conn.execute("SELECT channel_id FROM channels")}

    def register(self, public_key: bytes, secret_sha256: str, now: str) -> Registration:
        with self._transaction() as tx:
            row = tx.execute(
                "SELECT channel_id, secret_sha256 FROM channels WHERE public_key = ?", (public_key,)
            ).fetchone()
            if row is not None:
                if not hmac.compare_digest(row[1], secret_sha256):
                    raise ChannelConflict
                tx.execute("UPDATE channels SET last_call_at = ? WHERE channel_id = ?", (now, row[0]))
                return Registration(channel_id=row[0], created=False)
            while True:
                channel_id = "".join(secrets.choice(_CHANNEL_ALPHABET) for _ in range(12))
                taken = tx.execute("SELECT 1 FROM channels WHERE channel_id = ?", (channel_id,)).fetchone()
                if taken is None:
                    break
            tx.execute(
                "INSERT INTO channels (channel_id, public_key, secret_sha256, created_at, last_call_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (channel_id, public_key, secret_sha256, now, now),
            )
            return Registration(channel_id=channel_id, created=True)

    def channel_secret_sha256(self, channel_id: str) -> str | None:
        row = self._conn.execute("SELECT secret_sha256 FROM channels WHERE channel_id = ?", (channel_id,)).fetchone()
        return None if row is None else str(row[0])

    def touch(self, channel_id: str, now: str) -> None:
        self._conn.execute("UPDATE channels SET last_call_at = ? WHERE channel_id = ?", (now, channel_id))

    def channel_status(self, channel_id: str) -> ChannelStatus | None:
        row = self._conn.execute(
            "SELECT last_seq, dropped_total FROM channels WHERE channel_id = ?", (channel_id,)
        ).fetchone()
        if row is None:
            return None
        (held,) = self._conn.execute("SELECT COUNT(*) FROM records WHERE channel_id = ?", (channel_id,)).fetchone()
        return ChannelStatus(last_seq=row[0], held_records=held, dropped_total=row[1])

    def store_bytes(self) -> int:
        (page_count,) = self._conn.execute("PRAGMA page_count").fetchone()
        (free_pages,) = self._conn.execute("PRAGMA freelist_count").fetchone()
        (page_size,) = self._conn.execute("PRAGMA page_size").fetchone()
        return int((page_count - free_pages) * page_size)

    def store_full(self) -> bool:
        return self.store_bytes() >= self._store_max_bytes

    def insert(self, channel_id: str, received_at: str, plaintext: bytes) -> StoreOutcome:
        with self._transaction() as tx:
            row = tx.execute("SELECT public_key, last_seq FROM channels WHERE channel_id = ?", (channel_id,)).fetchone()
            if row is None:
                return StoreOutcome.NO_CHANNEL
            sealed = seal(row[0], plaintext)
            held_records, held_bytes = tx.execute(
                "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM records WHERE channel_id = ?", (channel_id,)
            ).fetchone()
            if (
                held_records >= self._limits.channel_max_records
                or held_bytes + len(sealed) > self._limits.channel_max_bytes
                or self.store_full()
            ):
                tx.execute("UPDATE channels SET dropped_total = dropped_total + 1 WHERE channel_id = ?", (channel_id,))
                return StoreOutcome.DROPPED
            seq = row[1] + 1
            tx.execute(
                "INSERT INTO records (channel_id, seq, received_at, size, sealed) VALUES (?, ?, ?, ?, ?)",
                (channel_id, seq, received_at, len(sealed), sealed),
            )
            tx.execute("UPDATE channels SET last_seq = ? WHERE channel_id = ?", (seq, channel_id))
            return StoreOutcome.STORED

    def add_drops(self, drops: Mapping[str, int]) -> None:
        with self._transaction() as tx:
            tx.executemany(
                "UPDATE channels SET dropped_total = dropped_total + ? WHERE channel_id = ?",
                [(count, channel_id) for channel_id, count in drops.items()],
            )

    def page(self, channel_id: str, after: int, limit: int, max_bytes: int) -> Page | None:
        row = self._conn.execute("SELECT dropped_total FROM channels WHERE channel_id = ?", (channel_id,)).fetchone()
        if row is None:
            return None
        cursor = self._conn.execute(
            "SELECT seq, received_at, sealed FROM records WHERE channel_id = ? AND seq > ? ORDER BY seq",
            (channel_id, after),
        )
        records: list[StoredRecord] = []
        total = 0
        more = False
        for seq, received_at, sealed in cursor:
            if len(records) >= limit or (records and total + len(sealed) > max_bytes):
                more = True
                break
            records.append(StoredRecord(seq=seq, received_at=received_at, sealed=sealed))
            total += len(sealed)
        cursor.close()
        return Page(records=tuple(records), more=more, dropped_total=row[0])

    def retain(self, cutoff: str) -> RetentionResult:
        """Delete records received at or before `cutoff`, then channels whose last call and
        newest record are both at or before it."""
        with self._transaction() as tx:
            deleted = tx.execute("DELETE FROM records WHERE received_at <= ?", (cutoff,)).rowcount
            channels = tuple(
                row[0]
                for row in tx.execute(
                    "SELECT channel_id FROM channels c WHERE last_call_at <= ?"
                    " AND NOT EXISTS (SELECT 1 FROM records r WHERE r.channel_id = c.channel_id)",
                    (cutoff,),
                )
            )
            tx.executemany("DELETE FROM channels WHERE channel_id = ?", [(c,) for c in channels])
        return RetentionResult(records_deleted=deleted, channels_deleted=channels)


class Database:
    """Async face of the Store: one thread owns the connection; a set of known channel ids
    lets the listeners skip unknown channels without a query."""

    def __init__(self, executor: ThreadPoolExecutor, store: Store, known: set[str]) -> None:
        self._executor = executor
        self._store = store
        self._known = known

    @classmethod
    async def open(cls, path: Path, limits: Limits, store_max_bytes: int) -> "Database":
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="outpost-sqlite")
        loop = asyncio.get_running_loop()
        try:
            store = await loop.run_in_executor(executor, Store, path, limits, store_max_bytes)
            known = await loop.run_in_executor(executor, store.channel_ids)
        except BaseException:
            executor.shutdown(wait=False)
            raise
        return cls(executor, store, known)

    async def close(self) -> None:
        await self._run(self._store.close)
        self._executor.shutdown(wait=True)

    def knows(self, channel_id: str) -> bool:
        return channel_id in self._known

    async def _run[T](self, call: Callable[[], T]) -> T:
        return await asyncio.get_running_loop().run_in_executor(self._executor, call)

    async def register(self, public_key: bytes, secret_sha256: str, now: datetime) -> Registration:
        registration = await self._run(partial(self._store.register, public_key, secret_sha256, format_time(now)))
        self._known.add(registration.channel_id)
        return registration

    async def channel_secret_sha256(self, channel_id: str) -> str | None:
        return await self._run(partial(self._store.channel_secret_sha256, channel_id))

    async def touch(self, channel_id: str, now: datetime) -> None:
        await self._run(partial(self._store.touch, channel_id, format_time(now)))

    async def channel_status(self, channel_id: str) -> ChannelStatus | None:
        return await self._run(partial(self._store.channel_status, channel_id))

    async def store_full(self) -> bool:
        return await self._run(self._store.store_full)

    async def insert(self, channel_id: str, received_at: str, plaintext: bytes) -> StoreOutcome:
        return await self._run(partial(self._store.insert, channel_id, received_at, plaintext))

    async def add_drops(self, drops: Mapping[str, int]) -> None:
        await self._run(partial(self._store.add_drops, dict(drops)))

    async def page(self, channel_id: str, after: int, limit: int, max_bytes: int) -> Page | None:
        return await self._run(partial(self._store.page, channel_id, after, limit, max_bytes))

    async def retain(self, now: datetime, retention_days: int) -> RetentionResult:
        cutoff = format_time(now - timedelta(days=retention_days))
        result = await self._run(partial(self._store.retain, cutoff))
        self._known.difference_update(result.channels_deleted)
        return result


async def run_retention_once(db: Database, retention_days: int, now: datetime | None = None) -> RetentionResult:
    result = await db.retain(now or utc_now(), retention_days)
    log.info(
        "retention: %d records deleted, %d channels deleted %s",
        result.records_deleted,
        len(result.channels_deleted),
        list(result.channels_deleted),
    )
    return result


async def retention_loop(db: Database, retention_days: int) -> None:
    while True:
        await run_retention_once(db, retention_days)
        await asyncio.sleep(RETENTION_INTERVAL_SECONDS)
