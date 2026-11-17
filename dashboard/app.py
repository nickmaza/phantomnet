"""PhantomNet Security Console (FastAPI).

Bound to loopback by compose; reach it over an SSH tunnel or VPN. Every route
requires HTTP Basic credentials from PN_ADMIN_USER / PN_ADMIN_PASSWORD.
"""
from __future__ import annotations

import json
import os
import secrets
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from detection.alerts import build_alert
from detection.correlator import FLAG_LABELS
from detection.store import Store

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@dataclass
class DashboardSettings:
    admin_user: str
    admin_password: str
    state_dir: str = "data/state"
    web_health_url: str = ""
    sensor_id: str = "phantomnet-01"

    @classmethod
    def from_env(cls) -> "DashboardSettings":
        pw = os.environ.get("PN_ADMIN_PASSWORD", "")
        if len(pw) < 12:
            raise SystemExit("PN_ADMIN_PASSWORD must be set to at least 12 characters")
        return cls(admin_user=os.environ.get("PN_ADMIN_USER", "admin"), admin_password=pw,
                   state_dir=os.environ.get("PN_STATE_DIR", "data/state"),
                   web_health_url=os.environ.get("PN_WEB_HEALTH_URL", ""),
                   sensor_id=os.environ.get("PN_NODE_ID", "phantomnet-01"))


def fmt_ts(ts: float | None) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def create_app(store: Store, settings: DashboardSettings) -> FastAPI:
    app = FastAPI(title="PhantomNet Security Console", docs_url=None, redoc_url=None, openapi_url=None)
    security = HTTPBasic(realm="PhantomNet")
    TEMPLATES.env.filters["ts"] = fmt_ts
    TEMPLATES.env.globals["flag_labels"] = FLAG_LABELS

    def require_admin(creds: HTTPBasicCredentials = Depends(security)) -> str:
        ok_user = secrets.compare_digest(creds.username.encode(), settings.admin_user.encode())
        ok_pw = secrets.compare_digest(creds.password.encode(), settings.admin_password.encode())
        if not (ok_user and ok_pw):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized",
                                headers={"WWW-Authenticate": 'Basic realm="PhantomNet"'})
        return creds.username

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'"
        return resp

    def web_health(ctrl: dict) -> dict | None:
        if not settings.web_health_url:
            # Normal deployment: the controller relays the decoy's health.
            hb = ctrl.get("heartbeat")
            if not hb:
                return None
            try:
                age = time.time() - datetime.fromisoformat(hb.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return None
            return ctrl.get("web_health") if age < 120 else {"ok": False, "error": "controller heartbeat stale"}
        try:
            with urllib.request.urlopen(settings.web_health_url, timeout=2) as r:  # noqa: S310
                return json.loads(r.read().decode())
        except Exception:
            return {"ok": False, "error": "unreachable"}

    def summary() -> dict:
        now = time.time()
        state_dir = Path(settings.state_dir)
        active = _read_json(state_dir / "active_profile.json") or {}
        ctrl = _read_json(state_dir / "controller_status.json") or {}
        iso = _read_json(state_dir / "isolation_check.json")
        last = store.last_event_by_source()
        wh = web_health(ctrl)
        components = [
            {"name": "Web decoy (rotating HTTP)", "status": ("healthy" if wh and wh.get("ok") else
                                                             "unknown" if wh is None else "unhealthy"),
             "detail": f"profile {wh.get('profile_id')}" if wh and wh.get("ok") else (wh or {}).get("error", ""),
             "last_event": last.get("web", {}).get("ts")},
            {"name": "Protocol decoys (SSH, MySQL)", "status": "reporting" if "opencanary" in last else "no events yet",
             "detail": "OpenCanary", "last_event": last.get("opencanary", {}).get("ts")},
            {"name": "Rotation controller", "status": "running" if ctrl else "no heartbeat",
             "detail": f"last result: {ctrl.get('last_result', '—')}" if ctrl else "",
             "last_event": last.get("controller", {}).get("ts")},
        ]
        return {
            "sensor_id": settings.sensor_id,
            "decoys_configured": 3,
            "events_24h": store.count_events(now - 86400),
            "high_risk_incidents": len([i for i in store.incidents(500, "high") if i["last_seen"] >= now - 86400]),
            "active_profile": active.get("profile_id"),
            "active_profile_name": (active.get("profile") or {}).get("display_name"),
            "next_rotation_at": ctrl.get("next_rotation_at"),
            "isolation_check": iso,
            "components": components,
        }

    def timeline(limit: int = 40) -> list[dict]:
        items = []
        for inc in store.incidents(limit):
            items.append({"ts": inc["last_seen"], "kind": "incident", "severity": inc["severity"],
                          "title": f"Source {inc['source_ip']} contacted {len(inc['services'])} decoy service(s)",
                          "detail": ", ".join(sorted(inc["services"])) + f" · score {inc['score']}",
                          "link": f"/incidents/{inc['id']}"})
        for ev in store.events(limit, event_types=["profile_rotation", "rotation_rollback", "profile_applied"]):
            d = ev["details"]
            if ev["event_type"] == "rotation_rollback":
                title, sev = "Profile rotation failed — rolled back", "medium"
                detail = f"{d.get('attempted_profile')} → kept {d.get('new_profile')}: {d.get('reason', '')}"
            else:
                title, sev = "Decoy profile rotated", "info"
                detail = f"{d.get('previous_profile') or '—'} → {d.get('new_profile')}"
            items.append({"ts": ev["ts"], "kind": "rotation", "severity": sev, "title": title,
                          "detail": detail, "link": None})
        return sorted(items, key=lambda x: x["ts"], reverse=True)[:limit]

    # -- HTML ----------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, _: str = Depends(require_admin)):
        return TEMPLATES.TemplateResponse(request, "index.html", {
            "s": summary(), "timeline": timeline(), "incidents": store.incidents(50)})

    @app.get("/incidents/{incident_id}", response_class=HTMLResponse)
    def incident_page(incident_id: int, request: Request, _: str = Depends(require_admin)):
        inc = store.incident(incident_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        events = list(reversed(store.events(500, incident_id=incident_id)))
        rotations = store.events(50, since_ts=inc["first_seen"] - 3600, until_ts=inc["last_seen"],
                                 event_types=["profile_rotation", "rotation_rollback", "profile_applied"])
        merged = sorted(events + rotations, key=lambda e: (e["ts"], e["id"]))
        alert = build_alert(inc, list(reversed(events)), settings.sensor_id)
        return TEMPLATES.TemplateResponse(request, "incident.html", {
            "inc": inc, "events": merged, "alert": alert, "alerts": store.alerts(20, incident_id)})

    # -- JSON API --------------------------------------------------------
    def _inc_json(i: dict) -> dict:
        return {**i, "flags": sorted(i["flags"]), "services": sorted(i["services"])}

    @app.get("/api/summary")
    def api_summary(_: str = Depends(require_admin)):
        return summary()

    @app.get("/api/incidents")
    def api_incidents(limit: int = 100, min_severity: str | None = None, _: str = Depends(require_admin)):
        return [_inc_json(i) for i in store.incidents(min(limit, 1000), min_severity)]

    @app.get("/api/incidents/{incident_id}")
    def api_incident(incident_id: int, _: str = Depends(require_admin)):
        inc = store.incident(incident_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        return {"incident": _inc_json(inc), "events": store.events(500, incident_id=incident_id)}

    @app.get("/api/incidents/{incident_id}/export")
    def api_export(incident_id: int, _: str = Depends(require_admin)):
        inc = store.incident(incident_id)
        if not inc:
            raise HTTPException(404, "incident not found")
        payload = build_alert(inc, store.events(500, incident_id=incident_id), settings.sensor_id)
        return JSONResponse(payload, headers={
            "Content-Disposition": f'attachment; filename="phantomnet-incident-{incident_id}.json"'})

    @app.get("/api/events")
    def api_events(limit: int = 200, _: str = Depends(require_admin)):
        return store.events(min(limit, 2000))

    @app.get("/api/alerts")
    def api_alerts(limit: int = 100, _: str = Depends(require_admin)):
        return store.alerts(min(limit, 1000))

    return app
