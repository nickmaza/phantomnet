"""Console data access.

``SupabaseStore`` talks to Supabase's REST API (PostgREST) with the
service-role key — server side only, never sent to browsers. ``MemoryStore``
implements the same methods in memory for tests and local development.
Ownership checks live in the command layer; every lookup here is keyed by
owner or by a hashed secret.
"""
from __future__ import annotations

import itertools
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


INCIDENT_SYNC_FIELDS = ("source_ip", "severity", "score", "flags", "services", "event_count",
                        "first_seen", "last_seen", "summary", "findings", "guidance", "evidence")


class MemoryStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.sensors: dict[str, dict] = {}
        self.configs: dict[str, dict] = {}
        self.incidents: dict[int, dict] = {}
        self.actions: dict[int, dict] = {}
        self.audit: list[dict] = []
        self._ids = itertools.count(1)
        self._aids = itertools.count(1)

    # sensors
    def create_sensor(self, owner_id: str, name: str, enroll_code_hash: str, enroll_expires_at: str) -> dict:
        with self._lock:
            if any(s["owner_id"] == owner_id and s["name"] == name for s in self.sensors.values()):
                raise ValueError("duplicate")
            s = {"id": str(uuid.uuid4()), "owner_id": owner_id, "name": name, "created_at": now_iso(),
                 "enroll_code_hash": enroll_code_hash, "enroll_expires_at": enroll_expires_at,
                 "token_hash": None, "enrolled_at": None, "last_seen": None, "status": {}}
            self.sensors[s["id"]] = s
            self.configs[s["id"]] = {"sensor_id": s["id"], "config": {}, "version": 1, "updated_at": now_iso()}
            return dict(s)

    def list_sensors(self, owner_id: str) -> list[dict]:
        with self._lock:
            return sorted((dict(s) for s in self.sensors.values() if s["owner_id"] == owner_id),
                          key=lambda s: s["name"])

    def sensor_by_name(self, owner_id: str, name: str) -> dict | None:
        return next((s for s in self.list_sensors(owner_id) if s["name"] == name), None)

    def sensor_by(self, field: str, value: str) -> dict | None:
        with self._lock:
            return next((dict(s) for s in self.sensors.values() if s.get(field) == value), None)

    def update_sensor(self, sensor_id: str, **fields: Any) -> None:
        with self._lock:
            self.sensors[sensor_id].update(fields)

    def delete_sensor(self, sensor_id: str) -> None:
        with self._lock:
            self.sensors.pop(sensor_id, None)
            self.configs.pop(sensor_id, None)
            for d in (self.incidents, self.actions):
                for k in [k for k, v in d.items() if v["sensor_id"] == sensor_id]:
                    d.pop(k)

    # config
    def get_config(self, sensor_id: str) -> tuple[dict, int]:
        with self._lock:
            c = self.configs[sensor_id]
            return dict(c["config"]), c["version"]

    def set_config(self, sensor_id: str, config: dict) -> int:
        with self._lock:
            c = self.configs[sensor_id]
            c.update(config=dict(config), version=c["version"] + 1, updated_at=now_iso())
            return c["version"]

    # incidents
    def upsert_incidents(self, sensor_id: str, rows: list[dict]) -> None:
        with self._lock:
            for r in rows:
                existing = next((i for i in self.incidents.values()
                                 if i["sensor_id"] == sensor_id and i["local_id"] == r["local_id"]), None)
                if existing:
                    existing.update({k: r[k] for k in INCIDENT_SYNC_FIELDS if k in r}, updated_at=now_iso())
                else:
                    iid = next(self._ids)
                    self.incidents[iid] = {"id": iid, "sensor_id": sensor_id, "status": "open", "note": None,
                                           "updated_at": now_iso(), **{k: r.get(k) for k in ("local_id", *INCIDENT_SYNC_FIELDS)}}

    def list_incidents(self, sensor_ids: list[str], statuses: list[str] | None = None,
                       min_severity: str | None = None, limit: int = 50) -> list[dict]:
        sev = {"high": ["high"], "medium": ["medium", "high"]}.get(min_severity or "", None)
        with self._lock:
            rows = [dict(i) for i in self.incidents.values() if i["sensor_id"] in sensor_ids
                    and (not statuses or i["status"] in statuses) and (not sev or i["severity"] in sev)]
        return sorted(rows, key=lambda i: i["last_seen"], reverse=True)[:limit]

    def get_incident(self, incident_id: int) -> dict | None:
        with self._lock:
            i = self.incidents.get(incident_id)
            return dict(i) if i else None

    def update_incident(self, incident_id: int, **fields: Any) -> None:
        with self._lock:
            self.incidents[incident_id].update(fields, updated_at=now_iso())

    # actions
    def create_action(self, sensor_id: str, kind: str, args: dict) -> dict:
        with self._lock:
            aid = next(self._aids)
            a = {"id": aid, "sensor_id": sensor_id, "kind": kind, "args": args, "status": "queued",
                 "result": None, "created_at": now_iso(), "updated_at": now_iso()}
            self.actions[aid] = a
            return dict(a)

    def actions_for(self, sensor_id: str, statuses: list[str] | None = None, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = [dict(a) for a in self.actions.values() if a["sensor_id"] == sensor_id
                    and (not statuses or a["status"] in statuses)]
        return sorted(rows, key=lambda a: a["id"], reverse=True)[:limit]

    def update_action(self, action_id: int, sensor_id: str, **fields: Any) -> None:
        with self._lock:
            a = self.actions.get(action_id)
            if a and a["sensor_id"] == sensor_id:
                a.update(fields, updated_at=now_iso())

    # audit
    def add_audit(self, owner_id: str, sensor_id: str | None, command: str) -> None:
        with self._lock:
            self.audit.append({"owner_id": owner_id, "sensor_id": sensor_id, "command": command,
                               "created_at": now_iso()})

    def list_audit(self, owner_id: str, limit: int = 20) -> list[dict]:
        with self._lock:
            return [dict(a) for a in reversed(self.audit) if a["owner_id"] == owner_id][:limit]


class SupabaseStore:
    """Same interface as MemoryStore, backed by Supabase PostgREST."""

    def __init__(self, url: str, service_key: str, client: httpx.Client | None = None):
        self.base = url.rstrip("/") + "/rest/v1"
        self.http = client or httpx.Client(timeout=10, headers={
            "apikey": service_key, "Authorization": f"Bearer {service_key}",
            "Content-Type": "application/json"})

    def _req(self, method: str, table: str, params: dict | None = None, json: Any = None,
             prefer: str | None = None) -> list[dict]:
        headers = {"Prefer": prefer} if prefer else {}
        r = self.http.request(method, f"{self.base}/{table}", params=params, json=json, headers=headers)
        if r.status_code >= 400:
            raise RuntimeError(f"database error {r.status_code}: {r.text[:300]}")
        return r.json() if r.content else []

    # sensors
    def create_sensor(self, owner_id, name, enroll_code_hash, enroll_expires_at):
        try:
            [s] = self._req("POST", "sensors", json={
                "owner_id": owner_id, "name": name, "enroll_code_hash": enroll_code_hash,
                "enroll_expires_at": enroll_expires_at}, prefer="return=representation")
        except RuntimeError as e:
            if "23505" in str(e):
                raise ValueError("duplicate") from None
            raise
        self._req("POST", "sensor_config", json={"sensor_id": s["id"]})
        return s

    def list_sensors(self, owner_id):
        return self._req("GET", "sensors", {"owner_id": f"eq.{owner_id}", "order": "name"})

    def sensor_by_name(self, owner_id, name):
        rows = self._req("GET", "sensors", {"owner_id": f"eq.{owner_id}", "name": f"eq.{name}"})
        return rows[0] if rows else None

    def sensor_by(self, field, value):
        if field not in ("id", "token_hash", "enroll_code_hash"):
            raise ValueError("unsupported lookup")
        rows = self._req("GET", "sensors", {field: f"eq.{value}"})
        return rows[0] if rows else None

    def update_sensor(self, sensor_id, **fields):
        self._req("PATCH", "sensors", {"id": f"eq.{sensor_id}"}, json=fields)

    def delete_sensor(self, sensor_id):
        self._req("DELETE", "sensors", {"id": f"eq.{sensor_id}"})

    # config
    def get_config(self, sensor_id):
        rows = self._req("GET", "sensor_config", {"sensor_id": f"eq.{sensor_id}"})
        return (rows[0]["config"], rows[0]["version"]) if rows else ({}, 1)

    def set_config(self, sensor_id, config):
        _, version = self.get_config(sensor_id)
        self._req("PATCH", "sensor_config", {"sensor_id": f"eq.{sensor_id}"},
                  json={"config": config, "version": version + 1, "updated_at": now_iso()})
        return version + 1

    # incidents
    def upsert_incidents(self, sensor_id, rows):
        if not rows:
            return
        payload = [{"sensor_id": sensor_id, "local_id": r["local_id"], "updated_at": now_iso(),
                    **{k: r.get(k) for k in INCIDENT_SYNC_FIELDS}} for r in rows]
        # merge-duplicates only touches the columns we send, so status/note set
        # in the console are preserved.
        self._req("POST", "incidents", {"on_conflict": "sensor_id,local_id"}, json=payload,
                  prefer="resolution=merge-duplicates,return=minimal")

    def list_incidents(self, sensor_ids, statuses=None, min_severity=None, limit=50):
        if not sensor_ids:
            return []
        params = {"sensor_id": f"in.({','.join(sensor_ids)})", "order": "last_seen.desc", "limit": str(limit)}
        if statuses:
            params["status"] = f"in.({','.join(statuses)})"
        sev = {"high": "high", "medium": "medium,high"}.get(min_severity or "")
        if sev:
            params["severity"] = f"in.({sev})"
        return self._req("GET", "incidents", params)

    def get_incident(self, incident_id):
        rows = self._req("GET", "incidents", {"id": f"eq.{int(incident_id)}"})
        return rows[0] if rows else None

    def update_incident(self, incident_id, **fields):
        self._req("PATCH", "incidents", {"id": f"eq.{int(incident_id)}"}, json={**fields, "updated_at": now_iso()})

    # actions
    def create_action(self, sensor_id, kind, args):
        [a] = self._req("POST", "actions", json={"sensor_id": sensor_id, "kind": kind, "args": args},
                        prefer="return=representation")
        return a

    def actions_for(self, sensor_id, statuses=None, limit=20):
        params = {"sensor_id": f"eq.{sensor_id}", "order": "id.desc", "limit": str(limit)}
        if statuses:
            params["status"] = f"in.({','.join(statuses)})"
        return self._req("GET", "actions", params)

    def update_action(self, action_id, sensor_id, **fields):
        self._req("PATCH", "actions", {"id": f"eq.{int(action_id)}", "sensor_id": f"eq.{sensor_id}"},
                  json={**fields, "updated_at": now_iso()})

    # audit
    def add_audit(self, owner_id, sensor_id, command):
        self._req("POST", "audit_log", json={"owner_id": owner_id, "sensor_id": sensor_id, "command": command})

    def list_audit(self, owner_id, limit=20):
        return self._req("GET", "audit_log", {"owner_id": f"eq.{owner_id}", "order": "id.desc",
                                              "limit": str(limit)})
