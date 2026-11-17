"""SQLite storage for events, incidents, alerts, and collector offsets."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from .schema import parse_ts

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    timestamp TEXT NOT NULL,
    sensor_id TEXT,
    source TEXT,
    source_ip TEXT,
    source_port INTEGER,
    destination_service TEXT,
    destination_port INTEGER,
    decoy_profile TEXT,
    event_type TEXT NOT NULL,
    username TEXT,
    high_value INTEGER DEFAULT 0,
    details TEXT,
    risk_score INTEGER DEFAULT 0,
    action TEXT,
    simulation INTEGER DEFAULT 1,
    incident_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_src_ts ON events(source_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'low',
    flags TEXT NOT NULL DEFAULT '[]',
    services TEXT NOT NULL DEFAULT '[]',
    event_count INTEGER NOT NULL DEFAULT 0,
    alerted_severity TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_src ON incidents(source_ip, last_seen);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    created REAL NOT NULL,
    severity TEXT NOT NULL,
    channel TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    payload TEXT
);

CREATE TABLE IF NOT EXISTS offsets (
    path TEXT PRIMARY KEY,
    offset INTEGER NOT NULL,
    size INTEGER NOT NULL
);
"""

EVENT_COLUMNS = ["ts", "timestamp", "sensor_id", "source", "source_ip", "source_port",
                 "destination_service", "destination_port", "decoy_profile", "event_type",
                 "username", "high_value", "details", "risk_score", "action", "simulation",
                 "incident_id"]


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- events ---------------------------------------------------------
    def insert_event(self, ev: dict[str, Any]) -> int:
        row = dict(ev)
        row["ts"] = parse_ts(ev["timestamp"]).timestamp()
        row["details"] = json.dumps(ev.get("details") or {}, sort_keys=True)
        row["high_value"] = int(bool(ev.get("high_value")))
        row["simulation"] = int(bool(ev.get("simulation", True)))
        values = [row.get(c) for c in EVENT_COLUMNS]
        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO events ({','.join(EVENT_COLUMNS)}) VALUES ({','.join('?' * len(EVENT_COLUMNS))})",
                values)
            self._conn.commit()
            return int(cur.lastrowid)

    def update_event(self, event_id: int, **fields: Any) -> None:
        if not fields:
            return
        sets = ", ".join(f"{k}=?" for k in fields)
        with self._lock:
            self._conn.execute(f"UPDATE events SET {sets} WHERE id=?", [*fields.values(), event_id])
            self._conn.commit()

    def distinct_services_since(self, source_ip: str, since_ts: float) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT destination_service FROM events WHERE source_ip=? AND ts>=? "
                "AND destination_service IS NOT NULL", (source_ip, since_ts)).fetchall()
        return {r[0] for r in rows}

    def auth_services_for_incident(self, incident_id: int) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT destination_service FROM events WHERE incident_id=? "
                "AND event_type='authentication_attempt' AND destination_service IS NOT NULL",
                (incident_id,)).fetchall()
        return {r[0] for r in rows}

    def events(self, limit: int = 200, incident_id: int | None = None,
               since_ts: float | None = None, until_ts: float | None = None,
               with_source_only: bool = False, event_types: Iterable[str] | None = None) -> list[dict]:
        q, args = "SELECT * FROM events WHERE 1=1", []
        if incident_id is not None:
            q += " AND incident_id=?"; args.append(incident_id)
        if since_ts is not None:
            q += " AND ts>=?"; args.append(since_ts)
        if until_ts is not None:
            q += " AND ts<=?"; args.append(until_ts)
        if with_source_only:
            q += " AND source_ip IS NOT NULL"
        if event_types:
            et = list(event_types)
            q += f" AND event_type IN ({','.join('?' * len(et))})"; args.extend(et)
        q += " ORDER BY ts DESC, id DESC LIMIT ?"; args.append(limit)
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [_event_row(r) for r in rows]

    def count_events(self, since_ts: float, with_source_only: bool = True) -> int:
        q = "SELECT COUNT(*) FROM events WHERE ts>=?" + (" AND source_ip IS NOT NULL" if with_source_only else "")
        with self._lock:
            return int(self._conn.execute(q, (since_ts,)).fetchone()[0])

    def last_event_by_source(self) -> dict[str, dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT source, MAX(ts) AS ts FROM events GROUP BY source").fetchall()
        return {r["source"]: {"ts": r["ts"]} for r in rows}

    # -- incidents ------------------------------------------------------
    def open_incident_for(self, source_ip: str, not_before_ts: float) -> dict | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM incidents WHERE source_ip=? AND last_seen>=? ORDER BY last_seen DESC LIMIT 1",
                (source_ip, not_before_ts)).fetchone()
        return _incident_row(r) if r else None

    def create_incident(self, source_ip: str, ts: float) -> dict:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO incidents (source_ip, first_seen, last_seen) VALUES (?,?,?)",
                (source_ip, ts, ts))
            self._conn.commit()
        return self.incident(int(cur.lastrowid))  # type: ignore[return-value]

    def save_incident(self, inc: dict) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE incidents SET last_seen=?, first_seen=?, score=?, severity=?, flags=?, services=?, "
                "event_count=?, alerted_severity=? WHERE id=?",
                (inc["last_seen"], inc["first_seen"], inc["score"], inc["severity"],
                 json.dumps(sorted(inc["flags"])), json.dumps(sorted(inc["services"])),
                 inc["event_count"], inc.get("alerted_severity"), inc["id"]))
            self._conn.commit()

    def incident(self, incident_id: int) -> dict | None:
        with self._lock:
            r = self._conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return _incident_row(r) if r else None

    def incidents(self, limit: int = 100, min_severity: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM incidents", []
        if min_severity == "high":
            q += " WHERE severity='high'"
        elif min_severity == "medium":
            q += " WHERE severity IN ('medium','high')"
        q += " ORDER BY last_seen DESC LIMIT ?"; args.append(limit)
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [_incident_row(r) for r in rows]

    # -- alerts ---------------------------------------------------------
    def insert_alert(self, incident_id: int, created: float, severity: str, channel: str,
                     status: str, error: str | None, payload: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO alerts (incident_id, created, severity, channel, status, error, payload) "
                "VALUES (?,?,?,?,?,?,?)",
                (incident_id, created, severity, channel, status, error, json.dumps(payload)))
            self._conn.commit()

    def alerts(self, limit: int = 100, incident_id: int | None = None) -> list[dict]:
        q, args = "SELECT * FROM alerts", []
        if incident_id is not None:
            q += " WHERE incident_id=?"; args.append(incident_id)
        q += " ORDER BY created DESC, id DESC LIMIT ?"; args.append(limit)
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d["payload"] or "{}")
            out.append(d)
        return out

    # -- collector offsets ---------------------------------------------
    def get_offset(self, path: str) -> tuple[int, int]:
        with self._lock:
            r = self._conn.execute("SELECT offset, size FROM offsets WHERE path=?", (path,)).fetchone()
        return (int(r[0]), int(r[1])) if r else (0, 0)

    def set_offset(self, path: str, offset: int, size: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO offsets (path, offset, size) VALUES (?,?,?) "
                "ON CONFLICT(path) DO UPDATE SET offset=excluded.offset, size=excluded.size",
                (path, offset, size))
            self._conn.commit()


def _event_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["details"] = json.loads(d["details"] or "{}")
    d["high_value"] = bool(d["high_value"])
    d["simulation"] = bool(d["simulation"])
    return d


def _incident_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["flags"] = set(json.loads(d["flags"]))
    d["services"] = set(json.loads(d["services"]))
    return d
