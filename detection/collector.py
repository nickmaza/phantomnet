"""Event collector: tail decoy log files, normalize, redact, correlate, alert.

Sources (JSON lines in PN_EVENTS_DIR):
  opencanary.log  — OpenCanary SSH/MySQL simulations
  web.log         — PhantomNet rotating web decoy
  controller.log  — profile rotations, rollbacks, health checks

Offsets are persisted so restarts neither lose nor duplicate events; a file
that shrinks (rotated or truncated) is re-read from the start.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Callable

from .alerts import AlertDispatcher
from .correlator import Correlator
from .schema import normalize_native, normalize_opencanary, parse_ts
from .store import Store

log = logging.getLogger("phantomnet.collector")

MAX_LINE = 64 * 1024

SOURCES: dict[str, tuple[str, Callable[[dict], dict | None]]] = {
    "opencanary.log": ("opencanary", normalize_opencanary),
    "web.log": ("web", lambda r: normalize_native(r, "web")),
    "controller.log": ("controller", lambda r: normalize_native(r, "controller")),
}


class Collector:
    def __init__(self, events_dir: str | Path, store: Store, correlator: Correlator,
                 dispatcher: AlertDispatcher | None = None):
        self.events_dir = Path(events_dir)
        self.store, self.correlator, self.dispatcher = store, correlator, dispatcher

    def read_new(self) -> list[dict]:
        """Read and normalize all new lines from every source file."""
        batch: list[dict] = []
        for name, (source, normalize) in SOURCES.items():
            path = self.events_dir / name
            if not path.exists():
                continue
            key = str(path)
            size = path.stat().st_size
            offset, _ = self.store.get_offset(key)
            if size < offset:
                log.info("%s shrank (rotated/truncated); re-reading from start", name)
                offset = 0
            if size == offset:
                continue
            with path.open("rb") as fh:
                fh.seek(offset)
                data = fh.read(size - offset)
            # Only consume complete lines; a partial trailing line is read next pass.
            end = data.rfind(b"\n")
            if end < 0:
                continue
            for raw in data[: end + 1].splitlines():
                ev = self._parse_line(raw, normalize, name)
                if ev:
                    batch.append(ev)
            self.store.set_offset(key, offset + end + 1, size)
        # Correlate in time order across sources.
        batch.sort(key=lambda e: parse_ts(e["timestamp"]))
        return batch

    @staticmethod
    def _parse_line(raw: bytes, normalize, name: str) -> dict | None:
        if not raw.strip() or len(raw) > MAX_LINE:
            return None
        try:
            rec = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            log.debug("skipping non-JSON line in %s", name)
            return None
        if not isinstance(rec, dict):
            return None
        try:
            return normalize(rec)
        except (ValueError, TypeError) as exc:
            log.debug("skipping malformed record in %s: %s", name, exc)
            return None

    def run_once(self) -> int:
        events = self.read_new()
        touched: dict[int, dict] = {}
        for ev in events:
            _, inc = self.correlator.process(ev)
            if inc:
                touched[inc["id"]] = inc
        if self.dispatcher:
            for inc_id in touched:
                inc = self.store.incident(inc_id)
                if inc:
                    self.dispatcher.maybe_alert(inc)
        return len(events)


def default_events_dir() -> str:
    return os.environ.get("PN_EVENTS_DIR", "data/events")
