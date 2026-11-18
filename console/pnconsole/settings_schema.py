"""Sensor settings the console can manage: keys, types, defaults, validation.

Settings are stored as a flat dict of dotted keys. ``HOST_APPLIED`` keys change
container ports/bindings and are applied on the sensor host by
scripts/apply-managed-config.sh rather than live by the containers.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

PERSONAS = ("linux-server", "storage-server", "admin-portal")
SEVERITIES = ("low", "medium", "high")
DECOYS = ("ssh", "mysql", "http")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class SettingError(ValueError):
    pass


def _bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "on", "yes", "1", "enabled", "enable"):
        return True
    if s in ("false", "off", "no", "0", "disabled", "disable"):
        return False
    raise SettingError("expected on/off")


def _int(lo: int, hi: int) -> Callable[[Any], int]:
    def conv(v: Any) -> int:
        s = str(v).strip().lower()
        mult = 1
        if s.endswith("m") and s[:-1].isdigit():
            s = s[:-1]
        elif s.endswith("h") and s[:-1].isdigit():
            s, mult = s[:-1], 60
        try:
            n = int(s) * mult
        except ValueError:
            raise SettingError("expected a whole number") from None
        if not lo <= n <= hi:
            raise SettingError(f"must be between {lo} and {hi}")
        return n
    return conv


def _port(v: Any) -> int:
    return _int(1, 65535)(v)


def _ip(v: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        raise SettingError("expected an IP address") from None


def _choice(options: tuple[str, ...]) -> Callable[[Any], str]:
    def conv(v: Any) -> str:
        s = str(v).strip().lower()
        if s not in options:
            raise SettingError(f"must be one of: {', '.join(options)}")
        return s
    return conv


def _list(item: Callable[[Any], str]) -> Callable[[Any], list[str]]:
    def conv(v: Any) -> list[str]:
        raw = v if isinstance(v, list) else [x for x in re.split(r"[,\s]+", str(v)) if x]
        out: list[str] = []
        for x in raw:
            x = item(x)
            if x not in out:
                out.append(x)
        if len(out) > 50:
            raise SettingError("at most 50 entries")
        return out
    return conv


def _name(v: Any) -> str:
    s = str(v).strip()
    if not NAME_RE.match(s):
        raise SettingError(f"invalid name {s!r} (letters, digits, . _ - only)")
    return s.lower()


def _cidr(v: Any) -> str:
    try:
        return str(ipaddress.ip_network(str(v).strip(), strict=False))
    except ValueError:
        raise SettingError(f"invalid address/range {v!r}") from None


def _webhook(v: Any) -> str:
    s = str(v).strip()
    if s.lower() in ("", "off", "none"):
        return ""
    u = urlsplit(s)
    if u.scheme != "https" or not u.hostname:
        raise SettingError("webhook must be an https:// URL")
    if len(s) > 500:
        raise SettingError("URL too long")
    return s


def _email(v: Any) -> str:
    s = str(v).strip()
    if s and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", s):
        raise SettingError("expected an email address")
    return s


def _host(v: Any) -> str:
    s = str(v).strip()
    if s and not re.match(r"^[A-Za-z0-9.-]{1,253}$", s):
        raise SettingError("expected a hostname")
    return s


def _secret(v: Any) -> str:
    s = str(v)
    if len(s) > 256:
        raise SettingError("too long")
    return s


@dataclass(frozen=True)
class Setting:
    key: str
    default: Any
    convert: Callable[[Any], Any]
    help: str
    secret: bool = False
    host_applied: bool = False


SETTINGS: dict[str, Setting] = {s.key: s for s in [
    Setting("rotation.enabled", True, _bool, "Rotate the web decoy's persona automatically"),
    Setting("rotation.interval_min_minutes", 30, _int(5, 1440), "Shortest time between rotations (e.g. 30m, 2h)"),
    Setting("rotation.interval_max_minutes", 60, _int(5, 1440), "Longest time between rotations"),
    Setting("rotation.profiles", list(PERSONAS), _list(_choice(PERSONAS)), "Personas eligible for rotation"),
    Setting("decoys.ssh", True, _bool, "Run the fake SSH server", host_applied=True),
    Setting("decoys.mysql", True, _bool, "Run the fake MySQL server", host_applied=True),
    Setting("decoys.http", True, _bool, "Run the fake web portal", host_applied=True),
    Setting("decoys.bind_ip", "127.0.0.1", _ip, "Address the decoys listen on", host_applied=True),
    Setting("decoys.ssh_port", 2222, _port, "Port for the fake SSH server", host_applied=True),
    Setting("decoys.http_port", 8080, _port, "Port for the fake web portal", host_applied=True),
    Setting("decoys.mysql_port", 33060, _port, "Port for the fake MySQL server", host_applied=True),
    Setting("honeytokens", ["svc_deploy", "backup_admin"], _list(_name), "Fake usernames planted as bait"),
    Setting("scanners", [], _list(_cidr), "Authorized scanners: recorded but never alerted on"),
    Setting("alerts.min_severity", "medium", _choice(SEVERITIES), "Lowest severity that sends a notification"),
    Setting("alerts.webhook_url", "", _webhook, "Slack/Teams/Discord incoming webhook URL", secret=True),
    Setting("alerts.email.host", "", _host, "SMTP server"),
    Setting("alerts.email.port", 587, _port, "SMTP port"),
    Setting("alerts.email.user", "", _secret, "SMTP username"),
    Setting("alerts.email.password", "", _secret, "SMTP password", secret=True),
    Setting("alerts.email.from", "", _email, "Sender address"),
    Setting("alerts.email.to", "", _email, "Recipient address"),
    Setting("scoring.high_value_connection", 25, _int(0, 100), "Points: touched a high-value decoy"),
    Setting("scoring.authentication_attempt", 40, _int(0, 100), "Points: login attempt"),
    Setting("scoring.multi_decoy", 20, _int(0, 100), "Points: several decoys within 2 minutes"),
    Setting("scoring.cross_service_attempts", 15, _int(0, 100), "Points: logins on several services"),
    Setting("scoring.honeytoken", 50, _int(0, 100), "Points: used a planted fake username"),
]}


def defaults() -> dict[str, Any]:
    return {k: (list(s.default) if isinstance(s.default, list) else s.default) for k, s in SETTINGS.items()}


def effective(stored: dict[str, Any]) -> dict[str, Any]:
    out = defaults()
    out.update({k: v for k, v in (stored or {}).items() if k in SETTINGS})
    return out


def validate(key: str, value: Any, current: dict[str, Any] | None = None) -> Any:
    setting = SETTINGS.get(key)
    if not setting:
        close = [k for k in SETTINGS if key.split(".")[-1] in k]
        hint = f" (did you mean {', '.join(close[:3])}?)" if close else ""
        raise SettingError(f"unknown setting '{key}'{hint}")
    v = setting.convert(value)
    cur = effective(current or {})
    if key == "rotation.interval_min_minutes" and v > cur["rotation.interval_max_minutes"]:
        raise SettingError("minimum can't exceed rotation.interval_max_minutes")
    if key == "rotation.interval_max_minutes" and v < cur["rotation.interval_min_minutes"]:
        raise SettingError("maximum can't be below rotation.interval_min_minutes")
    if key == "rotation.profiles" and not v:
        raise SettingError("need at least one persona")
    return v


def display(key: str, value: Any) -> str:
    s = SETTINGS[key]
    if s.secret and value:
        text = str(value)
        return "•••••••• (set)" if len(text) < 16 else text[:12] + "…" + "•••••"
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, list):
        return ", ".join(map(str, value)) or "(none)"
    return str(value) if value != "" else "(not set)"
