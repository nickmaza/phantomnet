"""PhantomNet rotating web decoy.

Serves a simulated administrative login portal whose identity (title, branding,
Server header, robots.txt, HTML breadcrumbs) comes from the active profile in
PN_STATE_DIR/active_profile.json. No login ever succeeds and nothing real sits
behind it. Every request is logged as a JSON line to PN_EVENTS_DIR/web.log;
passwords are never written — only their length.

Two listeners:
  PN_WEB_PORT    (decoy-facing)  — the fake portal
  PN_HEALTH_PORT (backend only)  — /health for the controller
"""
from __future__ import annotations

import html
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from controller.profiles import ProfileError, load_profiles, validate_profile

log = logging.getLogger("phantomnet.web")

MAX_BODY = 16 * 1024
SCAN_PATHS = ("/wp-admin", "/wp-login", "/.env", "/.git", "/phpmyadmin", "/admin", "/config",
              "/server-status", "/actuator", "/cgi-bin", "/backup", "/api/internal", "/webman", "/volume1")

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
 body{{margin:0;font-family:Segoe UI,Helvetica,Arial,sans-serif;background:#f3f4f6;color:#1f2937}}
 header{{background:{color};color:#fff;padding:14px 24px;font-weight:600;letter-spacing:.3px}}
 main{{max-width:360px;margin:72px auto;background:#fff;border-radius:8px;padding:28px 32px;
      box-shadow:0 1px 3px rgba(0,0,0,.12)}}
 h1{{font-size:20px;margin:0 0 20px}} label{{display:block;font-size:13px;margin:12px 0 4px}}
 input{{width:100%;box-sizing:border-box;padding:9px;border:1px solid #cbd5e1;border-radius:4px}}
 button{{margin-top:20px;width:100%;padding:10px;border:0;border-radius:4px;background:{color};
        color:#fff;font-weight:600;cursor:pointer}}
 .err{{background:#fef2f2;color:#991b1b;padding:8px 10px;border-radius:4px;font-size:13px}}
 footer{{text-align:center;font-size:12px;color:#6b7280;margin-top:24px}}
</style></head>
<body><header>{product} &middot; {hostname}</header>
<main><h1>{heading}</h1>{error}
<form method="post" action="/login" autocomplete="off">
<label for="u">{username_label}</label><input id="u" name="username" required>
<label for="p">Password</label><input id="p" name="password" type="password" required>
<button type="submit">Sign in</button></form></main>
<footer>{footer}</footer>
<!-- {breadcrumb} -->
</body></html>"""

NOT_FOUND = """<!DOCTYPE html><html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>
<hr><address>{server}</address></body></html>"""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ProfileState:
    """Holds the active profile; reloads atomically when the state file changes.

    If a new state file is invalid or fails to render, the last good profile
    stays active and the error is reported via /health so the controller rolls
    back.
    """

    def __init__(self, state_dir: Path, profiles_dir: Path):
        self.state_path = state_dir / "active_profile.json"
        self.profiles_dir = profiles_dir
        self._lock = threading.Lock()
        self._mtime: float | None = None
        self.error: str | None = None
        self.generation = 0
        self.profile = self._fallback()

    def _fallback(self) -> dict:
        try:
            profiles = load_profiles(self.profiles_dir)
            return profiles.get("linux-server") or next(iter(profiles.values()))
        except (ProfileError, OSError, ValueError) as exc:
            self.error = f"no usable profiles: {exc}"
            return {"id": "fallback", "high_value": False, "http": {
                "server_header": "nginx", "title": "Login", "product": "Portal", "version": "1",
                "hostname": "portal", "brand_color": "#334155", "login_heading": "Sign in",
                "username_label": "Username", "footer": "", "robots_disallow": [], "extra_headers": {}}}

    def current(self) -> tuple[dict, int]:
        try:
            mtime = self.state_path.stat().st_mtime_ns
        except OSError:
            return self.profile, self.generation
        with self._lock:
            if mtime != self._mtime:
                self._mtime = mtime
                self._reload()
            return self.profile, self.generation

    def _reload(self) -> None:
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            profile = validate_profile(state["profile"])
            render_login(profile)  # must render before going live
            self.profile, self.generation, self.error = profile, int(state["generation"]), None
            log.info("activated profile %s (generation %s)", profile["id"], self.generation)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.error = f"rejected state file: {exc}"
            log.error(self.error)


def render_login(profile: dict, error: bool = False) -> str:
    h = profile["http"]
    e = html.escape
    return LOGIN_PAGE.format(
        title=e(h["title"]), color=e(h["brand_color"]), product=e(h["product"]),
        hostname=e(h["hostname"]), heading=e(h["login_heading"]),
        username_label=e(h["username_label"]), footer=e(h["footer"]),
        breadcrumb=e(h.get("breadcrumb_comment", "")).replace("--", "- -"),
        error='<p class="err">Invalid credentials. This attempt has been recorded.</p>' if error else "",
    )


class EventLog:
    def __init__(self, path: Path, node_id: str):
        self.path, self.node_id = path, node_id
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, **rec) -> None:
        rec = {"timestamp": utc_now(), "sensor_id": self.node_id, "destination_service": "http", **rec}
        line = json.dumps(rec, separators=(",", ":")) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)


def make_decoy_handler(state: ProfileState, events: EventLog, port: int):
    class DecoyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "nginx"
        sys_version = ""

        def log_message(self, fmt, *args):  # silence default stderr logging
            pass

        def version_string(self) -> str:
            profile = getattr(self, "_profile", None) or state.current()[0]
            return profile["http"]["server_header"]

        # -- helpers ----------------------------------------------------
        def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8",
                  extra: dict | None = None) -> None:
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            h = self._profile["http"]
            if h.get("powered_by"):
                self.send_header("X-Powered-By", h["powered_by"])
            for k, v in (h.get("extra_headers") or {}).items():
                self.send_header(k, v)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _record(self, event_type: str, **details) -> None:
            path = urlsplit(self.path).path
            details.update(method=self.command, path=self.path[:512],
                           user_agent=(self.headers.get("User-Agent") or "")[:256])
            if any(path.lower().startswith(p) for p in SCAN_PATHS) and event_type == "http_request":
                details["suspicious_path"] = True
            events.write(event_type=event_type, source_ip=self.client_address[0],
                         source_port=self.client_address[1], destination_port=port,
                         decoy_profile=self._profile["id"],
                         high_value=bool(self._profile.get("high_value")),
                         username=details.pop("username", None), details=details)

        # -- verbs ------------------------------------------------------
        def do_GET(self) -> None:
            self._profile, _ = state.current()
            path = urlsplit(self.path).path
            self._record("http_request")
            if path in ("/", "/login", "/index.html", "/index.php"):
                self._send(200, render_login(self._profile))
            elif path == "/robots.txt":
                lines = ["User-agent: *"] + [f"Disallow: {d}" for d in self._profile["http"].get("robots_disallow", [])]
                self._send(200, "\n".join(lines) + "\n", "text/plain; charset=utf-8")
            else:
                self._send(404, NOT_FOUND.format(server=html.escape(self._profile["http"]["server_header"])))

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_POST(self) -> None:
            self._profile, _ = state.current()
            length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
            form = parse_qs(body, keep_blank_values=True)
            username = (form.get("username") or form.get("user") or form.get("email") or [""])[0][:128]
            password = (form.get("password") or form.get("pass") or [""])[0]
            if urlsplit(self.path).path == "/login":
                # Never store the password itself — only how long it was.
                self._record("authentication_attempt", username=username or None,
                             password_length=len(password), field_names=sorted(form)[:20])
                time.sleep(0.6)  # plausible auth latency, slows brute force
                self._send(401, render_login(self._profile, error=True))
            else:
                self._record("http_request", body_length=length)
                self._send(404, NOT_FOUND.format(server=html.escape(self._profile["http"]["server_header"])))

        def _method_not_allowed(self) -> None:
            self._profile, _ = state.current()
            self._record("http_request")
            self._send(405, "Method Not Allowed\n", "text/plain", {"Allow": "GET, HEAD, POST"})

        do_PUT = do_DELETE = do_OPTIONS = do_PATCH = _method_not_allowed

    return DecoyHandler


def make_health_handler(state: ProfileState):
    class HealthHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_GET(self) -> None:
            if self.path != "/health":
                self.send_error(404)
                return
            profile, gen = state.current()
            try:
                render_login(profile)
                ok = state.error is None
            except Exception as exc:  # pragma: no cover - defensive
                ok, state.error = False, str(exc)
            body = json.dumps({"ok": ok, "profile_id": profile["id"], "generation": gen,
                               "error": state.error}).encode()
            self.send_response(200 if ok else 503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return HealthHandler


def build_servers(host: str = "0.0.0.0") -> tuple[ThreadingHTTPServer, ThreadingHTTPServer]:
    e = os.environ.get
    state = ProfileState(Path(e("PN_STATE_DIR", "data/state")), Path(e("PN_PROFILES_DIR", "config/profiles")))
    events = EventLog(Path(e("PN_EVENTS_DIR", "data/events")) / "web.log", e("PN_NODE_ID", "phantomnet-01"))
    web_port, health_port = int(e("PN_WEB_PORT", "8080")), int(e("PN_HEALTH_PORT", "9090"))
    web = ThreadingHTTPServer((host, web_port), make_decoy_handler(state, events, web_port))
    health = ThreadingHTTPServer((host, health_port), make_health_handler(state))
    web.daemon_threads = health.daemon_threads = True
    return web, health


def main() -> None:
    logging.basicConfig(level=os.environ.get("PN_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    web, health = build_servers()
    threading.Thread(target=health.serve_forever, daemon=True, name="health").start()
    log.info("web decoy listening on %s, health on %s", web.server_address, health.server_address)
    web.serve_forever()


if __name__ == "__main__":
    main()
