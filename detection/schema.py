"""PhantomNet normalized event schema, normalization of source logs, and redaction.

Every event that reaches storage, the dashboard, or an alert passes through
``redact`` so that passwords and other secrets typed into a decoy never leave
the sensor.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_STR = 256
SENSITIVE_KEY = re.compile(r"pass|pwd|secret|token|key|auth|cookie|session|credential|hash", re.I)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# OpenCanary logtype codes (opencanary/logger.py) -> (service, event_type)
OPENCANARY_LOGTYPES: dict[int, tuple[str | None, str]] = {
    1000: (None, "sensor_boot"),
    1001: (None, "sensor_message"),
    1002: (None, "sensor_debug"),
    1003: (None, "sensor_error"),
    1004: (None, "sensor_ping"),
    1005: (None, "sensor_config_saved"),
    2000: ("ftp", "authentication_attempt"),
    3000: ("http", "http_request"),
    3001: ("http", "authentication_attempt"),
    4000: ("ssh", "connection"),
    4001: ("ssh", "client_banner"),
    4002: ("ssh", "authentication_attempt"),
    5001: (None, "recon_probe"),
    8001: ("mysql", "authentication_attempt"),
}

SOURCE_EVENT_TYPES = {"connection", "client_banner", "authentication_attempt",
                      "http_request", "recon_probe"}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(value: Any) -> datetime:
    """Parse ISO-8601 or OpenCanary 'YYYY-MM-DD HH:MM:SS.ffffff' (UTC) timestamps."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    s = str(value).strip().replace(" ", "T")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def clean_str(value: Any, limit: int = MAX_STR) -> str:
    s = CONTROL_CHARS.sub("?", str(value))
    return s if len(s) <= limit else s[: limit - 3] + "..."


def redact_url(path: str) -> str:
    try:
        parts = urlsplit(path)
    except ValueError:
        return clean_str(path)
    if not parts.query:
        return clean_str(path)
    q = [(k, "[REDACTED]" if SENSITIVE_KEY.search(k) else v)
         for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return clean_str(urlunsplit(parts._replace(query=urlencode(q))))


def redact(details: Any, depth: int = 0) -> Any:
    """Recursively remove secrets from event details.

    Password-like keys are replaced by their length only. Strings are truncated
    and stripped of control characters. Unknown nesting is bounded.
    """
    if depth > 4:
        return "[TRUNCATED]"
    if isinstance(details, dict):
        out: dict[str, Any] = {}
        for k, v in list(details.items())[:50]:
            key = clean_str(k, 64)
            if SENSITIVE_KEY.search(key) and not key.lower().endswith("_length"):
                if isinstance(v, str) and re.search(r"pass|pwd", key, re.I):
                    out[f"{key.lower()}_length"] = len(v)
                else:
                    out[key] = "[REDACTED]"
            elif key.lower() in ("path", "url", "uri"):
                out[key] = redact_url(str(v))
            else:
                out[key] = redact(v, depth + 1)
        return out
    if isinstance(details, list):
        return [redact(v, depth + 1) for v in details[:50]]
    if isinstance(details, str):
        return clean_str(details)
    if isinstance(details, (int, float, bool)) or details is None:
        return details
    return clean_str(details)


def make_event(**kw: Any) -> dict[str, Any]:
    """Build a normalized event with defaults; always redacts details."""
    ts = kw.get("timestamp") or utc_now_iso()
    details = redact(kw.get("details") or {})
    username = kw.get("username")
    if username is None and isinstance(kw.get("details"), dict):
        raw = kw["details"]
        username = raw.get("username") or raw.get("USERNAME")
    return {
        "timestamp": iso(parse_ts(ts)),
        "sensor_id": clean_str(kw.get("sensor_id") or "phantomnet-01", 64),
        "source": kw.get("source", "unknown"),
        "source_ip": kw.get("source_ip") or None,
        "source_port": int(kw["source_port"]) if kw.get("source_port") not in (None, "", -1) else None,
        "destination_service": kw.get("destination_service"),
        "destination_port": int(kw["destination_port"]) if kw.get("destination_port") not in (None, "", -1) else None,
        "decoy_profile": kw.get("decoy_profile"),
        "event_type": kw.get("event_type", "other"),
        "username": clean_str(username, 64) if username else None,
        "high_value": bool(kw.get("high_value", False)),
        "details": details,
        "risk_score": int(kw.get("risk_score", 0)),
        "action": kw.get("action", "log"),
        # True: the targeted service is a simulation (always the case for decoys).
        "simulation": True,
    }


# Map of OpenCanary service -> PhantomNet decoy persona name.
OPENCANARY_PROFILES = {"ssh": "linux-admin-ssh", "mysql": "database-server",
                       "ftp": "file-server", "http": "opencanary-http"}


def normalize_opencanary(rec: dict[str, Any]) -> dict[str, Any] | None:
    try:
        logtype = int(rec.get("logtype", -1))
    except (TypeError, ValueError):
        return None
    service, event_type = OPENCANARY_LOGTYPES.get(logtype, (None, "other"))
    logdata = rec.get("logdata") if isinstance(rec.get("logdata"), dict) else {"msg": rec.get("logdata")}
    details = {k.lower(): v for k, v in logdata.items()}
    details["opencanary_logtype"] = logtype
    src = rec.get("src_host") or None
    return make_event(
        timestamp=rec.get("utc_time") or rec.get("local_time") or utc_now_iso(),
        sensor_id=rec.get("node_id"),
        source="opencanary",
        source_ip=src,
        source_port=rec.get("src_port"),
        destination_service=service,
        destination_port=rec.get("dst_port"),
        decoy_profile=OPENCANARY_PROFILES.get(service or ""),
        event_type=event_type,
        username=logdata.get("USERNAME") or logdata.get("username"),
        details=details,
    )


def normalize_native(rec: dict[str, Any], source: str) -> dict[str, Any] | None:
    """Events written by PhantomNet's own web decoy and controller."""
    if "event_type" not in rec:
        return None
    return make_event(source=source, **{k: v for k, v in rec.items() if k != "source"})
