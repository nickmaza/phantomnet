"""Decoy persona profiles: load from JSON and validate.

Profiles describe *simulated* identities only. Validation rejects anything that
looks like it carries real secrets.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")
COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
REQUIRED_HTTP = ("server_header", "title", "product", "version", "hostname", "brand_color",
                 "login_heading", "username_label", "footer")
# Profiles may mention honeytoken *usernames* but must never embed secrets.
FORBIDDEN = re.compile(r"(password|passwd|secret|api[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)\s*[:=]", re.I)


class ProfileError(ValueError):
    pass


def validate_profile(p: Any) -> dict:
    if not isinstance(p, dict):
        raise ProfileError("profile must be a JSON object")
    pid = p.get("id")
    if not isinstance(pid, str) or not ID_RE.match(pid):
        raise ProfileError(f"invalid profile id: {pid!r}")
    http = p.get("http")
    if not isinstance(http, dict):
        raise ProfileError(f"{pid}: missing 'http' section")
    for key in REQUIRED_HTTP:
        v = http.get(key)
        if not isinstance(v, str) or not v.strip() or len(v) > 200:
            raise ProfileError(f"{pid}: http.{key} must be a non-empty string (<=200 chars)")
        if "\r" in v or "\n" in v:
            raise ProfileError(f"{pid}: http.{key} must not contain newlines")
    if not COLOR_RE.match(http["brand_color"]):
        raise ProfileError(f"{pid}: http.brand_color must be #rrggbb")
    for k, v in (http.get("extra_headers") or {}).items():
        if not HEADER_RE.match(str(k)) or not isinstance(v, str) or "\r" in v or "\n" in v:
            raise ProfileError(f"{pid}: invalid extra header {k!r}")
    if not isinstance(http.get("robots_disallow", []), list):
        raise ProfileError(f"{pid}: http.robots_disallow must be a list")
    if FORBIDDEN.search(json.dumps(p)):
        raise ProfileError(f"{pid}: profile appears to contain a secret; decoys must hold none")
    return p


def load_profiles(directory: str | Path) -> dict[str, dict]:
    profiles: dict[str, dict] = {}
    for path in sorted(Path(directory).glob("*.json")):
        p = validate_profile(json.loads(path.read_text(encoding="utf-8")))
        if p["id"] in profiles:
            raise ProfileError(f"duplicate profile id {p['id']} in {path.name}")
        profiles[p["id"]] = p
    if not profiles:
        raise ProfileError(f"no profiles found in {directory}")
    return profiles
