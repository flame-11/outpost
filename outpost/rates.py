"""Sliding-window rate counters, in memory (they may reset on restart; CONTRACT section 3)."""

import time
from collections import deque
from collections.abc import Hashable


class RateWindow:
    """At most `limit` events per `window_seconds` for each key."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self._limit = limit
        self._window = window_seconds
        self._events: dict[Hashable, deque[float]] = {}
        self._next_sweep = 0.0

    def allows(self, key: Hashable, now: float | None = None) -> bool:
        return len(self._live(key, self._now(now))) < self._limit

    def add(self, key: Hashable, now: float | None = None) -> None:
        moment = self._now(now)
        self._live(key, moment).append(moment)

    def seconds_until_allowed(self, key: Hashable, now: float | None = None) -> float:
        moment = self._now(now)
        events = self._live(key, moment)
        if len(events) < self._limit:
            return 0.0
        return events[len(events) - self._limit] + self._window - moment

    def _live(self, key: Hashable, moment: float) -> deque[float]:
        if moment >= self._next_sweep:
            self._sweep(moment)
        events = self._events.setdefault(key, deque())
        while events and events[0] <= moment - self._window:
            events.popleft()
        return events

    def _sweep(self, moment: float) -> None:
        cutoff = moment - self._window
        for key in [key for key, events in self._events.items() if not events or events[-1] <= cutoff]:
            del self._events[key]
        self._next_sweep = moment + self._window

    @staticmethod
    def _now(now: float | None) -> float:
        return time.monotonic() if now is None else now
