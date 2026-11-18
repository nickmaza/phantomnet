"""Cloud Firestore backend (same interface as MemoryStore / SupabaseStore).

Collections:
  sensors/{uuid}                 owner_id, name, hashes, status, timestamps
  sensor_config/{sensor_id}      config (dict), version
  incidents/{sensor_id}_{local}  number (console-wide id shown to users), fields
  actions/{number}               sensor_id, kind, args, status, result
  audit_log/{auto}               owner_id, command, created_at
  counters/{incidents|actions}   next number

Only the server (Admin SDK, service account) touches Firestore; the deployed
security rules deny every client read/write (see console/firestore.rules).
Queries use equality filters only and sort in Python, so no composite indexes
are needed.
"""
from __future__ import annotations

import json
import uuid
from typing import Any

from .store import INCIDENT_SYNC_FIELDS, now_iso


def _db_from_env(service_account_json: str):
    import firebase_admin
    from firebase_admin import credentials, firestore

    info = json.loads(service_account_json)
    name = f"phantomnet-{info.get('project_id', 'default')}"
    try:
        app = firebase_admin.get_app(name)
    except ValueError:
        app = firebase_admin.initialize_app(credentials.Certificate(info), name=name)
    return firestore.client(app)


class FirestoreStore:
    def __init__(self, service_account_json: str | None = None, db: Any = None):
        self.db = db or _db_from_env(service_account_json or "{}")

    # -- helpers ----------------------------------------------------------
    def _where(self, coll: str, **eq) -> list:
        from google.cloud.firestore_v1.base_query import FieldFilter
        q = self.db.collection(coll)
        for k, v in eq.items():
            q = q.where(filter=FieldFilter(k, "==", v))
        return list(q.stream())

    def _next(self, counter: str) -> int:
        from google.cloud import firestore as gcf
        ref = self.db.collection("counters").document(counter)

        @gcf.transactional
        def bump(tx):
            snap = ref.get(transaction=tx)
            n = (snap.get("next") if snap.exists else 1) or 1
            tx.set(ref, {"next": n + 1})
            return n

        return bump(self.db.transaction())

    @staticmethod
    def _doc(snap) -> dict:
        d = snap.to_dict() or {}
        d.setdefault("id", snap.id)
        return d

    # -- sensors ----------------------------------------------------------
    def create_sensor(self, owner_id, name, enroll_code_hash, enroll_expires_at):
        if self._where("sensors", owner_id=owner_id, name=name):
            raise ValueError("duplicate")
        sid = str(uuid.uuid4())
        s = {"id": sid, "owner_id": owner_id, "name": name, "created_at": now_iso(),
             "enroll_code_hash": enroll_code_hash, "enroll_expires_at": enroll_expires_at,
             "token_hash": None, "enrolled_at": None, "last_seen": None, "status": {}}
        self.db.collection("sensors").document(sid).set(s)
        self.db.collection("sensor_config").document(sid).set(
            {"sensor_id": sid, "config": {}, "version": 1, "updated_at": now_iso()})
        return s

    def list_sensors(self, owner_id):
        return sorted((self._doc(s) for s in self._where("sensors", owner_id=owner_id)), key=lambda s: s["name"])

    def sensor_by_name(self, owner_id, name):
        rows = self._where("sensors", owner_id=owner_id, name=name)
        return self._doc(rows[0]) if rows else None

    def sensor_by(self, field, value):
        if field not in ("id", "token_hash", "enroll_code_hash"):
            raise ValueError("unsupported lookup")
        if field == "id":
            snap = self.db.collection("sensors").document(value).get()
            return self._doc(snap) if snap.exists else None
        rows = self._where("sensors", **{field: value})
        return self._doc(rows[0]) if rows else None

    def update_sensor(self, sensor_id, **fields):
        self.db.collection("sensors").document(sensor_id).update(fields)

    def delete_sensor(self, sensor_id):
        batch = self.db.batch()
        for coll in ("incidents", "actions"):
            for snap in self._where(coll, sensor_id=sensor_id):
                batch.delete(snap.reference)
        batch.delete(self.db.collection("sensor_config").document(sensor_id))
        batch.delete(self.db.collection("sensors").document(sensor_id))
        batch.commit()

    # -- config -----------------------------------------------------------
    def get_config(self, sensor_id):
        snap = self.db.collection("sensor_config").document(sensor_id).get()
        if not snap.exists:
            return {}, 1
        d = snap.to_dict()
        return dict(d.get("config") or {}), int(d.get("version", 1))

    def set_config(self, sensor_id, config):
        from google.cloud import firestore as gcf
        ref = self.db.collection("sensor_config").document(sensor_id)

        @gcf.transactional
        def write(tx):
            snap = ref.get(transaction=tx)
            v = int((snap.to_dict() or {}).get("version", 1)) + 1 if snap.exists else 2
            tx.set(ref, {"sensor_id": sensor_id, "config": dict(config), "version": v, "updated_at": now_iso()})
            return v

        return write(self.db.transaction())

    # -- incidents --------------------------------------------------------
    def upsert_incidents(self, sensor_id, rows):
        for r in rows:
            ref = self.db.collection("incidents").document(f"{sensor_id}_{int(r['local_id'])}")
            fields = {k: r.get(k) for k in INCIDENT_SYNC_FIELDS if k in r}
            snap = ref.get()
            if snap.exists:
                ref.update({**fields, "updated_at": now_iso()})  # keeps console status/note
            else:
                ref.set({"number": self._next("incidents"), "sensor_id": sensor_id,
                         "local_id": int(r["local_id"]), "status": "open", "note": None,
                         "updated_at": now_iso(), **{k: r.get(k) for k in INCIDENT_SYNC_FIELDS}})

    def _incident(self, snap) -> dict:
        d = snap.to_dict() or {}
        d["id"] = d.get("number")
        return d

    def list_incidents(self, sensor_ids, statuses=None, min_severity=None, limit=50):
        from google.cloud.firestore_v1.base_query import FieldFilter
        sev = {"high": {"high"}, "medium": {"medium", "high"}}.get(min_severity or "")
        out = []
        for i in range(0, len(sensor_ids), 30):  # Firestore 'in' takes up to 30 values
            q = self.db.collection("incidents").where(filter=FieldFilter("sensor_id", "in", sensor_ids[i:i + 30]))
            for snap in q.stream():
                d = self._incident(snap)
                if (not statuses or d.get("status") in statuses) and (not sev or d.get("severity") in sev):
                    out.append(d)
        return sorted(out, key=lambda d: d.get("last_seen") or "", reverse=True)[:limit]

    def _incident_ref(self, number):
        rows = self._where("incidents", number=int(number))
        return rows[0] if rows else None

    def get_incident(self, incident_id):
        snap = self._incident_ref(incident_id)
        return self._incident(snap) if snap else None

    def update_incident(self, incident_id, **fields):
        snap = self._incident_ref(incident_id)
        if snap:
            snap.reference.update({**fields, "updated_at": now_iso()})

    # -- actions ----------------------------------------------------------
    def create_action(self, sensor_id, kind, args):
        n = self._next("actions")
        a = {"id": n, "sensor_id": sensor_id, "kind": kind, "args": args, "status": "queued",
             "result": None, "created_at": now_iso(), "updated_at": now_iso()}
        self.db.collection("actions").document(str(n)).set(a)
        return a

    def actions_for(self, sensor_id, statuses=None, limit=20):
        rows = [s.to_dict() for s in self._where("actions", sensor_id=sensor_id)]
        rows = [a for a in rows if not statuses or a.get("status") in statuses]
        return sorted(rows, key=lambda a: a["id"], reverse=True)[:limit]

    def update_action(self, action_id, sensor_id, **fields):
        ref = self.db.collection("actions").document(str(int(action_id)))
        snap = ref.get()
        if snap.exists and (snap.to_dict() or {}).get("sensor_id") == sensor_id:
            ref.update({**fields, "updated_at": now_iso()})

    # -- audit ------------------------------------------------------------
    def add_audit(self, owner_id, sensor_id, command):
        self.db.collection("audit_log").add({"owner_id": owner_id, "sensor_id": sensor_id,
                                             "command": command, "created_at": now_iso()})

    def list_audit(self, owner_id, limit=20):
        rows = [s.to_dict() for s in self._where("audit_log", owner_id=owner_id)]
        return sorted(rows, key=lambda a: a["created_at"], reverse=True)[:limit]
