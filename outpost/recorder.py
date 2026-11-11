"""The recorder: one task that applies the rate limits and writes each interaction, sealed."""

import asyncio
import logging
from collections import Counter
from dataclasses import dataclass

from outpost.config import Limits
from outpost.rates import RateWindow
from outpost.store import Database, StoreOutcome

log = logging.getLogger("outpost.recorder")

QUEUE_SIZE = 10_000
_DROP_FLUSH_THRESHOLD = 100


@dataclass(frozen=True, slots=True)
class Capture:
    """One interaction that named a channel: the record JSON (CONTRACT section 6) to seal."""

    channel_id: str
    source_ip: str
    received_at: str
    plaintext: bytes


class Notifier:
    """Wakes pulls waiting on a channel when a record is stored for it."""

    def __init__(self) -> None:
        self._events: dict[str, asyncio.Event] = {}

    def event(self, channel_id: str) -> asyncio.Event:
        """Take the event before reading the store, then wait on it."""
        return self._events.setdefault(channel_id, asyncio.Event())

    def stored(self, channel_id: str) -> None:
        event = self._events.pop(channel_id, None)
        if event is not None:
            event.set()


class Recorder:
    def __init__(self, db: Database, limits: Limits, notifier: Notifier) -> None:
        self._db = db
        self._notifier = notifier
        self._queue: asyncio.Queue[Capture] = asyncio.Queue(QUEUE_SIZE)
        self._source_rate = RateWindow(limits.source_rate, 60.0)
        self._channel_rate = RateWindow(limits.channel_rate, 60.0)
        self._pending_drops: Counter[str] = Counter()

    def knows(self, channel_id: str) -> bool:
        """Listeners ask first, so an interaction for an unknown channel builds no record."""
        return self._db.knows(channel_id)

    def submit(self, capture: Capture) -> None:
        """Called by the listeners; never blocks."""
        try:
            self._queue.put_nowait(capture)
        except asyncio.QueueFull:
            self._pending_drops[capture.channel_id] += 1

    async def idle(self) -> None:
        """Return once every submitted capture is written and its drops are counted."""
        await self._queue.join()

    async def run(self) -> None:
        while True:
            capture = await self._queue.get()
            try:
                await self._record(capture)
                if self._pending_drops and (
                    self._queue.empty() or self._pending_drops.total() >= _DROP_FLUSH_THRESHOLD
                ):
                    await self._flush_drops()
            finally:
                self._queue.task_done()

    async def _record(self, capture: Capture) -> None:
        source_key = (capture.source_ip, capture.channel_id)
        if not (self._source_rate.allows(source_key) and self._channel_rate.allows(capture.channel_id)):
            self._pending_drops[capture.channel_id] += 1
            return
        outcome = await self._db.insert(capture.channel_id, capture.received_at, capture.plaintext)
        if outcome is StoreOutcome.STORED:
            self._source_rate.add(source_key)
            self._channel_rate.add(capture.channel_id)
            self._notifier.stored(capture.channel_id)

    async def _flush_drops(self) -> None:
        drops = dict(self._pending_drops)
        self._pending_drops.clear()
        await self._db.add_drops(drops)
        log.info("dropped by limits: %s", drops)
