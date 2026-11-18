"""Cloud console sync — runs inside phantomnet-core.

Outbound HTTPS only: the sensor never accepts connections from the console.

  1. Enroll once with PN_ENROLL_CODE -> receive a sensor token (saved to
     PN_MANAGED_DIR/cloud.json, mode 600).
  2. Every PN_CLOUD_INTERVAL seconds POST /api/sensor/sync with:
       status     health, active persona, isolation result, config version
       incidents  new or changed incidents (already redacted)
       results    outcomes of actions run since the last sync
     and receive the desired settings + queued actions.
  3. Settings are written atomically to PN_MANAGED_DIR/config.json, where the
     correlator, alert dispatcher and rotation controller pick them up.
  4. Actions: 'rotate' is handed to the controller through
     PN_MANAGED_DIR/requests/; 'alert_test' and 'isolation_report' run here.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx

from .alerts import AlertDispatcher, build_alert
from .policy import managed_dir
from .store import Store

log = logging.getLogger("phantomnet.cloud")
VERSION = "0.2.0"
MAX_PUSH = 100


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _atomic_write(path: Path, data: Any, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    os.replace(tmp, path)


class CloudSync:
    def __init__(self, url: str, store: Store, dispatcher: AlertDispatcher | None,
                 state_dir: str | Path, enroll_code: str = "", managed: str | Path | None = None,
                 client: httpx.Client | None = None, on_config: Callable[[dict], None] | None = None):
        insecure_ok = (url.startswith(("http://127.0.0.1", "http://localhost", "http://testserver"))
                       or os.environ.get("PN_CLOUD_ALLOW_INSECURE") == "1")  # local development only
        if not url.startswith("https://") and not insecure_ok:
            raise ValueError("PN_CLOUD_URL must be https://")
        self.url = url.rstrip("/")
        self.store, self.dispatcher = store, dispatcher
        self.state_dir = Path(state_dir)
        self.managed = Path(managed or managed_dir())
        self.enroll_code = enroll_code.strip()
        self.http = client or httpx.Client(timeout=15, headers={"User-Agent": f"PhantomNet-Sensor/{VERSION}"})
        self.on_config = on_config
        self.results: list[dict] = []
        self.managed.mkdir(parents=True, exist_ok=True)

    # -- credentials ----------------------------------------------------
    @property
    def cred_path(self) -> Path:
        return self.managed / "cloud.json"

    def token(self) -> str | None:
        data = _read_json(self.cred_path) or {}
        return data.get("token") if data.get("url") == self.url else None

    def enroll(self) -> bool:
        if not self.enroll_code:
            log.warning("cloud console configured but no PN_ENROLL_CODE and no saved token")
            return False
        r = self.http.post(f"{self.url}/api/sensor/enroll", json={"code": self.enroll_code, "version": VERSION})
        if r.status_code != 200:
            log.error("enrollment failed: %s", r.json().get("error", r.text[:200]) if r.content else r.status_code)
            return False
        d = r.json()
        _atomic_write(self.cred_path, {"url": self.url, "token": d["token"], "sensor_id": d["sensor_id"],
                                       "name": d["name"], "enrolled_at": _iso(time.time())}, mode=0o600)
        log.info("enrolled with console as sensor '%s'", d["name"])
        return True

    # -- payload ----------------------------------------------------------
    def status(self) -> dict:
        active = _read_json(self.state_dir / "active_profile.json") or {}
        ctrl = _read_json(self.state_dir / "controller_status.json") or {}
        iso = _read_json(self.state_dir / "isolation_check.json")
        local_cfg = _read_json(self.managed / "config.json") or {}
        last = self.store.last_event_by_source()
        wh = ctrl.get("web_health") or {}
        components = {
            "web decoy": {"ok": bool(wh.get("ok")) if ctrl else None,
                          "detail": f"persona {wh.get('profile_id')}" if wh.get("ok") else wh.get("error", "no data")},
            "ssh/mysql decoys": {"ok": True if "opencanary" in last else None,
                                 "detail": "reporting" if "opencanary" in last else "no events yet"},
            "rotation controller": {"ok": bool(ctrl) or None,
                                    "detail": f"heartbeat {ctrl.get('heartbeat', '')[:19]}" if ctrl else "no heartbeat"},
        }
        nxt = ctrl.get("next_rotation_at")
        return {"version": VERSION, "active_persona": active.get("profile_id"),
                "next_rotation_at": _iso(nxt) if isinstance(nxt, (int, float)) else None,
                "components": components, "isolation": iso, "config_version": local_cfg.get("version"),
                "events_24h": self.store.count_events(time.time() - 86400)}

    @property
    def pushed_path(self) -> Path:
        return self.managed / "pushed.json"

    def changed_incidents(self) -> tuple[list[dict], dict]:
        pushed = _read_json(self.pushed_path) or {}
        out, marks = [], {}
        for inc in sorted(self.store.incidents(1000), key=lambda i: i["last_seen"]):
            mark = f"{inc['last_seen']}:{inc['score']}:{inc['event_count']}"
            if pushed.get(str(inc["id"])) == mark:
                continue
            events = self.store.events(limit=20, incident_id=inc["id"])
            a = build_alert(inc, events, "")
            out.append({"local_id": inc["id"], "source_ip": inc["source_ip"], "severity": inc["severity"],
                        "score": inc["score"], "flags": sorted(inc["flags"]), "services": sorted(inc["services"]),
                        "event_count": inc["event_count"], "first_seen": _iso(inc["first_seen"]),
                        "last_seen": _iso(inc["last_seen"]), "summary": a["summary"], "findings": a["findings"],
                        "guidance": a["guidance"], "evidence": a["evidence"]})
            marks[str(inc["id"])] = mark
            if len(out) >= MAX_PUSH:
                break
        return out, marks

    # -- actions ----------------------------------------------------------
    def handle_actions(self, actions: list[dict]) -> None:
        for a in actions:
            kind, aid = a.get("kind"), int(a.get("id", 0))
            try:
                if kind == "rotate":
                    profile = (a.get("args") or {}).get("profile")
                    _atomic_write(self.managed / "requests" / f"rotate-{aid}.json",
                                  {"id": aid, "kind": "rotate", "profile": profile})
                    continue  # result arrives from the controller
                if kind == "alert_test":
                    self.results.append({"id": aid, "status": "done", "result": self.send_test_alert()})
                elif kind == "isolation_report":
                    iso = _read_json(self.state_dir / "isolation_check.json")
                    self.results.append({"id": aid, "status": "done", "result": {"isolation": iso}})
                else:
                    self.results.append({"id": aid, "status": "failed", "result": {"error": f"unknown action {kind}"}})
            except Exception as exc:
                self.results.append({"id": aid, "status": "failed", "result": {"error": str(exc)[:300]}})

    def collect_controller_results(self) -> None:
        req_dir, res_dir = self.managed / "requests", self.state_dir / "action_results"
        if not res_dir.exists():
            return
        for res in res_dir.glob("*.json"):
            data = _read_json(res)
            if not data or "id" not in data:
                continue
            req = req_dir / f"rotate-{data['id']}.json"
            if req.exists():
                self.results.append({"id": int(data["id"]), "status": data.get("status", "done"),
                                     "result": data.get("result")})
                req.unlink(missing_ok=True)

    def send_test_alert(self) -> dict:
        if not self.dispatcher:
            return {"error": "alerts not configured"}
        s = self.dispatcher.settings
        payload = {"type": "phantomnet.test", "severity": "info", "summary":
                   "[TEST] PhantomNet test alert — alert delivery works.", "incident_id": 0,
                   "findings": [], "guidance": ["No action needed. This was requested from the console."],
                   "evidence": [], "sensor_id": s.sensor_id}
        result = {}
        if s.webhook_url:
            try:
                self.dispatcher._send_webhook(payload)
                result["webhook"] = "sent"
            except Exception as exc:
                result["webhook"] = f"failed: {exc}"[:200]
        if s.smtp_host and s.smtp_to:
            try:
                self.dispatcher._send_email({**payload, "severity": "test"})
                result["email"] = "sent"
            except Exception as exc:
                result["email"] = f"failed: {exc}"[:200]
        return result or {"error": "no webhook or email configured"}

    # -- main -------------------------------------------------------------
    def sync_once(self) -> bool:
        token = self.token()
        if not token:
            if not self.enroll():
                return False
            token = self.token()
        self.collect_controller_results()
        incidents, marks = self.changed_incidents()
        body = {"status": self.status(), "incidents": incidents, "action_results": self.results}
        r = self.http.post(f"{self.url}/api/sensor/sync", json=body, headers={"Authorization": f"Bearer {token}"})
        if r.status_code == 401:
            log.error("console rejected the sensor token (sensor removed?). Re-enroll with a new code.")
            self.cred_path.unlink(missing_ok=True)
            return False
        r.raise_for_status()
        self.results = []
        pushed = _read_json(self.pushed_path) or {}
        pushed.update(marks)
        _atomic_write(self.pushed_path, pushed)
        d = r.json()
        current = _read_json(self.managed / "config.json") or {}
        if d.get("config_version") != current.get("version"):
            _atomic_write(self.managed / "config.json", {"version": d.get("config_version"), "config": d.get("config") or {},
                                                         "received_at": _iso(time.time())})
            log.info("applied console config v%s", d.get("config_version"))
            if self.on_config:
                self.on_config(d.get("config") or {})
        self.handle_actions(d.get("actions") or [])
        return True

    def run(self, stop: threading.Event, interval: float = 15.0) -> None:
        backoff = interval
        while not stop.is_set():
            try:
                ok = self.sync_once()
                backoff = interval if ok else min(backoff * 2, 300)
            except Exception as exc:
                log.warning("console sync failed: %s", exc)
                backoff = min(backoff * 2, 300)
            stop.wait(backoff)


def from_env(store: Store, dispatcher: AlertDispatcher | None, on_config=None) -> CloudSync | None:
    url = os.environ.get("PN_CLOUD_URL", "").strip()
    if not url:
        return None
    return CloudSync(url, store, dispatcher, os.environ.get("PN_STATE_DIR", "data/state"),
                     os.environ.get("PN_ENROLL_CODE", ""), on_config=on_config)
