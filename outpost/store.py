"""SQLite store (WAL), its single-thread access, the held-size limits and the retention task.

For a record the store keeps `channel_id`, `seq`, `received_at`, `size` and `sealed`, nothing
else (CONTRACT section 6). Every SQLite call of the server runs on one dedicated thread, so the
event loop never waits on the disk. `outpost-admin` and the ACME hook write the same file from
their own processes (keys and challenge values); the server reads those per call or by polling.
"""

import asyncio
import enum
import hmac
import logging
import secrets
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path

from outpost import keys, schema
from outpost.config import Limits
from outpost.keys import ApiKey
from outpost.records import format_time, utc_now
from outpost.sealing import seal

log = logging.getLogger("outpost.store")

RETENTION_INTERVAL_SECONDS = 3600
_CHANNEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
_EFFECTIVE_RETENTION = "MIN(COALESCE(retention_days, :instance), :instance)"


class StoreOutcome(enum.Enum):
    STORED = "stored"
    DROPPED = "dropped"
    NO_CHANNEL = "no_channel"


@dataclass(frozen=True, slots=True)
class Registration:
    channel_id: str
    created: bool
    retention_days: int | None  # asked at registration; None means the instance's
    key_channel_rate: int | None  # the owning key's channel_rate quota


@dataclass(frozen=True, slots=True)
class ChannelStatus:
    last_seq: int
    held_records: int
    dropped_total: int
    retention_days: int | None
    key_channel_rate: int | None


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


class QuotaExceeded(Exception):
    """The key already holds its `max_channels`."""


class Store:
    """The SQL. Used only from the Database thread."""

    def __init__(self, data_dir: Path, limits: Limits, store_max_bytes: int) -> None:
        self._conn = schema.connect(data_dir)
        self._limits = limits
        self._store_max_bytes = store_max_bytes

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    def channel_quotas(self) -> dict[str, int | None]:
        """Every channel id, with its key's channel_rate quota."""
        rows = self._conn.execute(
            "SELECT c.channel_id, k.channel_rate FROM channels c LEFT JOIN api_keys k ON k.name = c.key_name"
        )
        return {row[0]: row[1] for row in rows}

    def api_key(self, key_sha256: str) -> ApiKey | None:
        return keys.key_by_sha256(self._conn, key_sha256)

    def has_active_keys(self) -> bool:
        return keys.has_active_keys(self._conn)

    def _key_channel_rate(self, key_name: str) -> int | None:
        row = self._conn.execute("SELECT channel_rate FROM api_keys WHERE name = ?", (key_name,)).fetchone()
        return None if row is None else row[0]

    def register(
        self, public_key: bytes, secret_sha256: str, now: str, key: ApiKey, retention_days: int | None
    ) -> Registration:
        with self._transaction():
            row = self._conn.execute(
                "SELECT channel_id, secret_sha256, key_name, retention_days FROM channels WHERE public_key = ?",
                (public_key,),
            ).fetchone()
            if row is not None:
                if not hmac.compare_digest(row[1], secret_sha256):
                    raise ChannelConflict
                kept = row[3] if retention_days is None else retention_days
                self._conn.execute(
                    "UPDATE channels SET last_call_at = ?, retention_days = ? WHERE channel_id = ?", (now, kept, row[0])
                )
                return Registration(
                    channel_id=row[0],
                    created=False,
                    retention_days=kept,
                    key_channel_rate=self._key_channel_rate(row[2]),
                )
            if key.max_channels is not None:
                (held,) = self._conn.execute("SELECT COUNT(*) FROM channels WHERE key_name = ?", (key.name,)).fetchone()
                if held >= key.max_channels:
                    raise QuotaExceeded
            while True:
                channel_id = "".join(secrets.choice(_CHANNEL_ALPHABET) for _ in range(12))
                taken = self._conn.execute("SELECT 1 FROM channels WHERE channel_id = ?", (channel_id,)).fetchone()
                if taken is None:
                    break
            self._conn.execute(
                "INSERT INTO channels (channel_id, public_key, secret_sha256, created_at, last_call_at, key_name,"
                " retention_days) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (channel_id, public_key, secret_sha256, now, now, key.name, retention_days),
            )
            return Registration(
                channel_id=channel_id, created=True, retention_days=retention_days, key_channel_rate=key.channel_rate
            )

    def channel_secret_sha256(self, channel_id: str) -> str | None:
        row = self._conn.execute("SELECT secret_sha256 FROM channels WHERE channel_id = ?", (channel_id,)).fetchone()
        return None if row is None else str(row[0])

    def touch(self, channel_id: str, now: str) -> None:
        self._conn.execute("UPDATE channels SET last_call_at = ? WHERE channel_id = ?", (now, channel_id))

    def channel_status(self, channel_id: str) -> ChannelStatus | None:
        row = self._conn.execute(
            "SELECT c.last_seq, c.dropped_total, c.retention_days, k.channel_rate FROM channels c"
            " LEFT JOIN api_keys k ON k.name = c.key_name WHERE c.channel_id = ?",
            (channel_id,),
        ).fetchone()
        if row is None:
            return None
        (held,) = self._conn.execute("SELECT COUNT(*) FROM records WHERE channel_id = ?", (channel_id,)).fetchone()
        return ChannelStatus(
            last_seq=row[0], held_records=held, dropped_total=row[1], retention_days=row[2], key_channel_rate=row[3]
        )

    def delete_channel(self, channel_id: str) -> bool:
        """Delete the channel and, through the foreign key, all its records."""
        return self._conn.execute("DELETE FROM channels WHERE channel_id = ?", (channel_id,)).rowcount > 0

    def store_bytes(self) -> int:
        (page_count,) = self._conn.execute("PRAGMA page_count").fetchone()
        (free_pages,) = self._conn.execute("PRAGMA freelist_count").fetchone()
        (page_size,) = self._conn.execute("PRAGMA page_size").fetchone()
        return int((page_count - free_pages) * page_size)

    def store_full(self) -> bool:
        return self.store_bytes() >= self._store_max_bytes

    def insert(self, channel_id: str, received_at: str, plaintext: bytes) -> StoreOutcome:
        with self._transaction():
            row = self._conn.execute(
                "SELECT public_key, last_seq FROM channels WHERE channel_id = ?", (channel_id,)
            ).fetchone()
            if row is None:
                return StoreOutcome.NO_CHANNEL
            sealed = seal(row[0], plaintext)
            held_records, held_bytes = self._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM records WHERE channel_id = ?", (channel_id,)
            ).fetchone()
            if (
                held_records >= self._limits.channel_max_records
                or held_bytes + len(sealed) > self._limits.channel_max_bytes
                or self.store_full()
            ):
                self._conn.execute(
                    "UPDATE channels SET dropped_total = dropped_total + 1 WHERE channel_id = ?", (channel_id,)
                )
                return StoreOutcome.DROPPED
            seq = row[1] + 1
            self._conn.execute(
                "INSERT INTO records (channel_id, seq, received_at, size, sealed) VALUES (?, ?, ?, ?, ?)",
                (channel_id, seq, received_at, len(sealed), sealed),
            )
            self._conn.execute("UPDATE channels SET last_seq = ? WHERE channel_id = ?", (seq, channel_id))
            return StoreOutcome.STORED

    def add_drops(self, drops: Mapping[str, int]) -> None:
        with self._transaction():
            self._conn.executemany(
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

    def retain(self, now: datetime, instance_days: int) -> RetentionResult:
        """For each channel, with its retention (its own, capped at `instance_days`): delete its
        records received at or before the cutoff, then the channel itself when its last call is at
        or before the cutoff and no record is left."""
        deleted = 0
        channels: list[str] = []
        with self._transaction():
            groups = [
                row[0]
                for row in self._conn.execute(
                    f"SELECT DISTINCT {_EFFECTIVE_RETENTION} FROM channels", {"instance": instance_days}
                )
            ]
            for days in groups:
                params = {"instance": instance_days, "days": days, "cutoff": format_time(now - timedelta(days=days))}
                deleted += self._conn.execute(
                    "DELETE FROM records WHERE received_at <= :cutoff AND channel_id IN"
                    f" (SELECT channel_id FROM channels WHERE {_EFFECTIVE_RETENTION} = :days)",
                    params,
                ).rowcount
                channels.extend(
                    row[0]
                    for row in self._conn.execute(
                        f"SELECT channel_id FROM channels c WHERE {_EFFECTIVE_RETENTION} = :days"
                        " AND last_call_at <= :cutoff"
                        " AND NOT EXISTS (SELECT 1 FROM records r WHERE r.channel_id = c.channel_id)",
                        params,
                    )
                )
            self._conn.executemany("DELETE FROM channels WHERE channel_id = ?", [(c,) for c in channels])
        return RetentionResult(records_deleted=deleted, channels_deleted=tuple(sorted(channels)))

    def challenge_values(self) -> dict[str, tuple[str, ...]]:
        return schema.challenge_values(self._conn)


class Database:
    """Async face of the Store: one thread owns the connection. A map of known channel ids (with
    their key's channel_rate quota) lets the listeners skip unknown channels without a query."""

    def __init__(self, executor: ThreadPoolExecutor, store: Store, known: dict[str, int | None]) -> None:
        self._executor = executor
        self._store = store
        self._known = known

    @classmethod
    async def open(cls, data_dir: Path, limits: Limits, store_max_bytes: int) -> "Database":
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="outpost-sqlite")
        loop = asyncio.get_running_loop()
        try:
            store = await loop.run_in_executor(executor, Store, data_dir, limits, store_max_bytes)
            known = await loop.run_in_executor(executor, store.channel_quotas)
        except BaseException:
            executor.shutdown(wait=False)
            raise
        return cls(executor, store, known)

    async def close(self) -> None:
        await self._run(self._store.close)
        self._executor.shutdown(wait=True)

    def knows(self, channel_id: str) -> bool:
        return channel_id in self._known

    def key_channel_rate(self, channel_id: str) -> int | None:
        return self._known.get(channel_id)

    async def _run[T](self, call: Callable[[], T]) -> T:
        return await asyncio.get_running_loop().run_in_executor(self._executor, call)

    async def refresh_known(self) -> None:
        """Take up channels another process deleted (`outpost-admin key revoke --delete-channels`)."""
        self._known = await self._run(self._store.channel_quotas)

    async def api_key(self, key_sha256: str) -> ApiKey | None:
        return await self._run(partial(self._store.api_key, key_sha256))

    async def has_active_keys(self) -> bool:
        return await self._run(self._store.has_active_keys)

    async def register(
        self, public_key: bytes, secret_sha256: str, now: datetime, key: ApiKey, retention_days: int | None
    ) -> Registration:
        registration = await self._run(
            partial(self._store.register, public_key, secret_sha256, format_time(now), key, retention_days)
        )
        self._known[registration.channel_id] = registration.key_channel_rate
        return registration

    async def channel_secret_sha256(self, channel_id: str) -> str | None:
        return await self._run(partial(self._store.channel_secret_sha256, channel_id))

    async def touch(self, channel_id: str, now: datetime) -> None:
        await self._run(partial(self._store.touch, channel_id, format_time(now)))

    async def channel_status(self, channel_id: str) -> ChannelStatus | None:
        return await self._run(partial(self._store.channel_status, channel_id))

    async def delete_channel(self, channel_id: str) -> bool:
        self._known.pop(channel_id, None)
        return await self._run(partial(self._store.delete_channel, channel_id))

    async def store_full(self) -> bool:
        return await self._run(self._store.store_full)

    async def insert(self, channel_id: str, received_at: str, plaintext: bytes) -> StoreOutcome:
        return await self._run(partial(self._store.insert, channel_id, received_at, plaintext))

    async def add_drops(self, drops: Mapping[str, int]) -> None:
        await self._run(partial(self._store.add_drops, dict(drops)))

    async def page(self, channel_id: str, after: int, limit: int, max_bytes: int) -> Page | None:
        return await self._run(partial(self._store.page, channel_id, after, limit, max_bytes))

    async def retain(self, now: datetime, retention_days: int) -> RetentionResult:
        result = await self._run(partial(self._store.retain, now, retention_days))
        for channel_id in result.channels_deleted:
            self._known.pop(channel_id, None)
        return result

    async def challenge_values(self) -> dict[str, tuple[str, ...]]:
        return await self._run(self._store.challenge_values)


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
