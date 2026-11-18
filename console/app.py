"""PhantomNet cloud console — FastAPI app (Vercel entrypoint: `app`).

Browser  -> /api/auth/*, /api/command      (user access token)
Sensor   -> /api/sensor/enroll, /sync      (enrollment code, then sensor token)

Environment (one backend):
  FIREBASE_SERVICE_ACCOUNT (JSON), FIREBASE_API_KEY             Firebase (Firestore + Auth)
  SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY   Supabase
  PN_CONSOLE_DEV=1                                              in-memory store/auth (local only)
  PN_CONSOLE_URL                                                public URL shown in enrollment help
"""
# No `from __future__ import annotations` here: the request models are defined
# inside create_app() and FastAPI must resolve their annotations eagerly.
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from pnconsole import __version__
from pnconsole import commands as C
from pnconsole import settings_schema as S
from pnconsole.auth import AuthError, MemoryAuth, SupabaseAuth, User
from pnconsole.store import MemoryStore, SupabaseStore, now_iso

ROOT = Path(__file__).parent
MAX_INCIDENTS_PER_SYNC = 100
MAX_EVIDENCE = 20


def build_backends():
    if os.environ.get("PN_CONSOLE_DEV") == "1":
        return MemoryStore(), MemoryAuth()
    # Tolerate copy-paste slips in the dashboard: surrounding whitespace/quotes.
    clean = lambda v: v.strip().strip('"').strip("'").strip()
    sa = os.environ.get("FIREBASE_SERVICE_ACCOUNT", "").strip()
    api_key = clean(os.environ.get("FIREBASE_API_KEY", ""))
    if sa and api_key:
        from pnconsole.auth import FirebaseAuth
        from pnconsole.firestore_store import FirestoreStore
        return FirestoreStore(sa), FirebaseAuth(api_key)
    url = os.environ.get("SUPABASE_URL", "")
    anon = os.environ.get("SUPABASE_ANON_KEY", "")
    service = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if not (url and anon and service):
        return None, None
    return SupabaseStore(url, service), SupabaseAuth(url, anon)


def create_app(store=None, auth=None) -> FastAPI:
    if store is None and auth is None:
        store, auth = build_backends()
    app = FastAPI(title="PhantomNet Console", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        return resp

    def backends():
        if store is None:
            raise HTTPException(503, "console is not configured: set FIREBASE_SERVICE_ACCOUNT and "
                                     "FIREBASE_API_KEY (or the SUPABASE_* variables)")
        return store, auth

    def console_url(request: Request) -> str:
        return os.environ.get("PN_CONSOLE_URL") or str(request.base_url).rstrip("/")

    def current_user(authorization: str = Header(default="")) -> User:
        _, a = backends()
        token = authorization.removeprefix("Bearer ").strip()
        if not token:
            raise HTTPException(401, "not signed in — run 'login'")
        try:
            return a.user(token)
        except AuthError as e:
            raise HTTPException(401, str(e)) from None

    def current_sensor(authorization: str = Header(default="")) -> dict:
        st, _ = backends()
        token = authorization.removeprefix("Bearer ").strip()
        s = st.sensor_by("token_hash", C.hash_secret(token)) if token.startswith("pns_") else None
        if not s:
            raise HTTPException(401, "invalid sensor token")
        return s

    # -- pages ----------------------------------------------------------
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(ROOT / "public" / "index.html")

    @app.get("/api/health")
    def health():
        return {"ok": store is not None, "version": __version__}

    # -- auth -----------------------------------------------------------
    class Credentials(BaseModel):
        email: str = Field(max_length=254)
        password: str = Field(min_length=1, max_length=256)

    class Refresh(BaseModel):
        refresh_token: str = Field(max_length=4096)

    def _auth_call(fn, *a):
        try:
            return fn(*a)
        except AuthError as e:
            raise HTTPException(e.status, str(e)) from None

    @app.post("/api/auth/signup")
    def signup(body: Credentials):
        _, a = backends()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", body.email):
            raise HTTPException(400, "enter a valid email address")
        return _auth_call(a.signup, body.email.strip(), body.password)

    @app.post("/api/auth/login")
    def login(body: Credentials):
        _, a = backends()
        return _auth_call(a.login, body.email.strip(), body.password)

    @app.post("/api/auth/refresh")
    def refresh(body: Refresh):
        _, a = backends()
        return _auth_call(a.refresh, body.refresh_token)

    # -- terminal commands ---------------------------------------------
    class CommandIn(BaseModel):
        line: str = Field(max_length=2000)
        sensor: str | None = Field(default=None, max_length=40)

    @app.post("/api/command")
    def command(body: CommandIn, request: Request, user: User = Depends(current_user)):
        st, _ = backends()
        ctx = C.Ctx(user=user, store=st, sensor_name=(body.sensor or None), console_url=console_url(request))
        try:
            r = C.run(ctx, body.line)
        except RuntimeError:
            raise HTTPException(502, "database unavailable, try again") from None
        return {"output": r.output, "sensor": r.sensor, "download": r.download, "ok": r.ok}

    @app.get("/api/completions")
    def completions(user: User = Depends(current_user)):
        st, _ = backends()
        data = C.completions()
        data["sensors"] = [s["name"] for s in st.list_sensors(user.id)]
        return data

    # -- sensor protocol -----------------------------------------------
    class EnrollIn(BaseModel):
        code: str = Field(max_length=64)
        version: str | None = Field(default=None, max_length=32)

    @app.post("/api/sensor/enroll")
    def enroll(body: EnrollIn):
        st, _ = backends()
        s = st.sensor_by("enroll_code_hash", C.hash_secret(body.code.strip().upper()))
        if not s or s.get("enrolled_at"):
            raise HTTPException(401, "invalid or already-used enrollment code")
        exp = C.parse_ts(s.get("enroll_expires_at"))
        if not exp or exp < datetime.now(timezone.utc):
            raise HTTPException(401, "enrollment code expired — run 'sensor code <name>' in the console")
        token = "pns_" + secrets.token_urlsafe(32)
        st.update_sensor(s["id"], token_hash=C.hash_secret(token), enroll_code_hash=None,
                         enroll_expires_at=None, enrolled_at=now_iso(), last_seen=now_iso())
        return {"sensor_id": s["id"], "name": s["name"], "token": token}

    class IncidentIn(BaseModel):
        local_id: int
        source_ip: str = Field(max_length=64)
        severity: str
        score: int = Field(ge=0, le=1000)
        flags: list[str] = Field(default_factory=list, max_length=20)
        services: list[str] = Field(default_factory=list, max_length=20)
        event_count: int = Field(ge=0)
        first_seen: str
        last_seen: str
        summary: str = Field(default="", max_length=2000)
        findings: list[str] = Field(default_factory=list, max_length=20)
        guidance: list[str] = Field(default_factory=list, max_length=20)
        evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=200)

    class ActionResult(BaseModel):
        id: int
        status: str
        result: dict[str, Any] | None = None

    class SyncIn(BaseModel):
        status: dict[str, Any] = Field(default_factory=dict)
        incidents: list[IncidentIn] = Field(default_factory=list, max_length=MAX_INCIDENTS_PER_SYNC)
        action_results: list[ActionResult] = Field(default_factory=list, max_length=50)

    @app.post("/api/sensor/sync")
    def sync(body: SyncIn, sensor: dict = Depends(current_sensor)):
        st, _ = backends()
        rows = []
        for inc in body.incidents:
            if inc.severity not in S.SEVERITIES:
                continue
            d = inc.model_dump()
            d["evidence"] = d["evidence"][:MAX_EVIDENCE]
            rows.append(d)
        st.upsert_incidents(sensor["id"], rows)
        for r in body.action_results:
            if r.status in ("done", "failed"):
                st.update_action(r.id, sensor["id"], status=r.status, result=r.result)
        status = {k: v for k, v in body.status.items() if k in (
            "version", "active_persona", "next_rotation_at", "components", "isolation", "config_version",
            "events_24h")}
        st.update_sensor(sensor["id"], last_seen=now_iso(), status=status)
        stored, version = st.get_config(sensor["id"])
        actions = st.actions_for(sensor["id"], ["queued"], limit=10)
        for a in actions:
            st.update_action(a["id"], sensor["id"], status="sent")
        return {"config": S.effective(stored), "config_version": version,
                "actions": [{"id": a["id"], "kind": a["kind"], "args": a["args"]} for a in actions]}

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    return app


app = create_app()
