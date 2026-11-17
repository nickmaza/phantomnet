"""Load and validate config/policies.yaml with safe defaults."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Policy:
    rotation_enabled: bool = True
    interval_min_minutes: float = 30
    interval_max_minutes: float = 60
    web_profiles: list[str] = field(default_factory=list)
    health_timeout_seconds: float = 15

    incident_idle_minutes: float = 30
    multi_decoy_window_seconds: float = 120
    multi_decoy_threshold: int = 3

    scoring: dict[str, int] = field(default_factory=lambda: {
        "high_value_connection": 25,
        "authentication_attempt": 40,
        "multi_decoy": 20,
        "cross_service_attempts": 15,
        "honeytoken": 50,
        "max_score": 100,
    })
    severity_medium: int = 40
    severity_high: int = 70
    alert_min_severity: str = "medium"

    authorized_scanners: list[ipaddress._BaseNetwork] = field(default_factory=list)
    honeytoken_usernames: set[str] = field(default_factory=set)
    high_value_services: set[str] = field(default_factory=lambda: {"ssh", "mysql"})

    def severity_for(self, score: int) -> str:
        if score >= self.severity_high:
            return "high"
        if score >= self.severity_medium:
            return "medium"
        return "low"

    def is_authorized_scanner(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.authorized_scanners)


def load_policy(path: str | os.PathLike | None = None) -> Policy:
    path = Path(path or os.environ.get("PN_POLICIES", "config/policies.yaml"))
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    raw = raw or {}
    p = Policy()

    rot = raw.get("rotation") or {}
    p.rotation_enabled = bool(rot.get("enabled", p.rotation_enabled))
    p.interval_min_minutes = float(rot.get("interval_min_minutes", p.interval_min_minutes))
    p.interval_max_minutes = float(rot.get("interval_max_minutes", p.interval_max_minutes))
    if p.interval_min_minutes <= 0 or p.interval_max_minutes < p.interval_min_minutes:
        raise ValueError("rotation interval must satisfy 0 < min <= max")
    p.web_profiles = [str(x) for x in rot.get("web_profiles", [])]
    p.health_timeout_seconds = float(rot.get("health_timeout_seconds", p.health_timeout_seconds))

    cor = raw.get("correlation") or {}
    p.incident_idle_minutes = float(cor.get("incident_idle_minutes", p.incident_idle_minutes))
    p.multi_decoy_window_seconds = float(cor.get("multi_decoy_window_seconds", p.multi_decoy_window_seconds))
    p.multi_decoy_threshold = int(cor.get("multi_decoy_threshold", p.multi_decoy_threshold))

    p.scoring.update({k: int(v) for k, v in (raw.get("scoring") or {}).items()})
    sev = raw.get("severity") or {}
    p.severity_medium = int(sev.get("medium", p.severity_medium))
    p.severity_high = int(sev.get("high", p.severity_high))

    alerts = raw.get("alerts") or {}
    p.alert_min_severity = str(alerts.get("min_severity", p.alert_min_severity)).lower()
    if p.alert_min_severity not in SEVERITY_RANK:
        raise ValueError(f"alerts.min_severity must be one of {list(SEVERITY_RANK)}")

    p.authorized_scanners = [ipaddress.ip_network(str(n), strict=False)
                             for n in (raw.get("authorized_scanners") or [])]
    p.honeytoken_usernames = {str(u).lower() for u in
                              ((raw.get("honeytokens") or {}).get("usernames") or [])}
    if "high_value_services" in raw:
        p.high_value_services = {str(s).lower() for s in raw["high_value_services"] or []}
    return p
