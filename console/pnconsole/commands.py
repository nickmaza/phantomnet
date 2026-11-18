"""Terminal command engine for the PhantomNet console.

Every command is a function taking (ctx, args) and returning a Result. Output
uses a small subset of ANSI colors that the web terminal renders.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from . import settings_schema as S
from .auth import User

RESET, BOLD, DIM = "\x1b[0m", "\x1b[1m", "\x1b[2m"
RED, GREEN, YELLOW, CYAN = "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[36m"
SEV_COLOR = {"high": RED + BOLD, "medium": YELLOW, "low": CYAN}
ONLINE_SECONDS = 90
ENROLL_HOURS = 24


def c(text: Any, color: str) -> str:
    return f"{color}{text}{RESET}"


def hash_secret(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


class CommandError(Exception):
    pass


@dataclass
class Result:
    output: str = ""
    sensor: str | None = None          # newly selected sensor (for the prompt)
    download: dict | None = None       # {"filename":..., "content":...}
    ok: bool = True


@dataclass
class Ctx:
    user: User
    store: Any
    sensor_name: str | None
    console_url: str
    line: str = ""
    _sensor: dict | None = field(default=None, repr=False)

    def sensors(self) -> list[dict]:
        return self.store.list_sensors(self.user.id)

    def sensor(self, name: str | None = None) -> dict:
        """Resolve the target sensor: explicit name, the selected one, or the only one."""
        name = name or self.sensor_name
        if name:
            s = self.store.sensor_by_name(self.user.id, name)
            if not s:
                raise CommandError(f"no sensor named '{name}'. Run 'sensors' to list them.")
            return s
        all_s = self.sensors()
        if len(all_s) == 1:
            return all_s[0]
        if not all_s:
            raise CommandError("you have no sensors yet. Run 'sensor add <name>' to create one.")
        raise CommandError("several sensors: pick one with 'use <name>' first.")


# ---------------------------------------------------------------------------
# helpers

def parse_ts(v: str | None) -> datetime | None:
    if not v:
        return None
    return datetime.fromisoformat(str(v).replace("Z", "+00:00"))


def ago(v: str | None) -> str:
    t = parse_ts(v)
    if not t:
        return "never"
    s = int((datetime.now(timezone.utc) - t).total_seconds())
    if s < 60:
        return f"{max(s, 0)}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def fmt_time(v: str | None) -> str:
    t = parse_ts(v)
    return t.strftime("%Y-%m-%d %H:%M UTC") if t else "-"


def online(s: dict) -> bool:
    t = parse_ts(s.get("last_seen"))
    return bool(t and (datetime.now(timezone.utc) - t).total_seconds() < ONLINE_SECONDS)


def state_label(s: dict) -> str:
    if not s.get("enrolled_at"):
        return c("awaiting enrollment", YELLOW)
    return c("online", GREEN) if online(s) else c("offline", RED)


def table(headers: list[str], rows: list[list[Any]]) -> str:
    plain = re.compile(r"\x1b\[[0-9;]*m")
    cells = [[str(x) for x in r] for r in rows]
    widths = [max([len(h)] + [len(plain.sub("", r[i])) for r in cells]) for i, h in enumerate(headers)]
    out = ["  ".join(c(h.ljust(widths[i]), DIM) for i, h in enumerate(headers))]
    for r in cells:
        out.append("  ".join(x + " " * (widths[i] - len(plain.sub("", x))) for i, x in enumerate(r)))
    return "\n".join(out)


def need(args: list[str], n: int, usage: str) -> None:
    if len(args) < n:
        raise CommandError(f"usage: {usage}")


def get_incident(ctx: Ctx, ref: str) -> dict:
    if not ref.lstrip("#").isdigit():
        raise CommandError("incident id must be a number, e.g. 'incident 12'")
    inc = ctx.store.get_incident(int(ref.lstrip("#")))
    owned = {s["id"]: s for s in ctx.sensors()}
    if not inc or inc["sensor_id"] not in owned:
        raise CommandError(f"no incident #{ref.lstrip('#')}")
    inc["_sensor_name"] = owned[inc["sensor_id"]]["name"]
    return inc


def change_setting(ctx: Ctx, key: str, value: Any, sensor: dict | None = None) -> str:
    s = sensor or ctx.sensor()
    stored, _ = ctx.store.get_config(s["id"])
    try:
        v = S.validate(key, value, stored)
    except S.SettingError as e:
        raise CommandError(str(e)) from None
    stored[key] = v
    version = ctx.store.set_config(s["id"], stored)
    note = ""
    if S.SETTINGS[key].host_applied:
        note = "\n" + c("note:", YELLOW) + " this changes ports/bindings; it takes effect when the sensor host runs scripts/apply-managed-config.sh"
    return f"{c('✓', GREEN)} {key} = {S.display(key, v)}  {c(f'[{s['name']} config v{version}]', DIM)}{note}"


# ---------------------------------------------------------------------------
# commands

COMMANDS: dict[str, tuple[Callable[[Ctx, list[str]], Result | str], str, str]] = {}


def command(name: str, usage: str, summary: str):
    def deco(fn):
        COMMANDS[name] = (fn, usage, summary)
        return fn
    return deco


@command("help", "help [command]", "list commands or explain one")
def cmd_help(ctx, args):
    if args:
        entry = COMMANDS.get(args[0])
        if not entry:
            raise CommandError(f"unknown command '{args[0]}'")
        return f"{c(entry[1], BOLD)}\n  {entry[2]}" + (HELP_EXTRA.get(args[0], ""))
    groups = [
        ("account", ["whoami", "logout", "clear"]),
        ("sensors", ["sensors", "sensor", "use", "status"]),
        ("incidents", ["incidents", "incident", "ack", "close", "reopen", "export"]),
        ("configure", ["setup", "config", "decoys", "persona", "honeytokens", "scanners", "alerts"]),
        ("operate", ["isolation", "actions", "audit"]),
    ]
    out = [c("PhantomNet console — type a command, Tab completes, ↑/↓ history", DIM), ""]
    for g, names in groups:
        out.append(c(g.upper(), GREEN))
        for n in names:
            u, s = (COMMANDS[n][1], COMMANDS[n][2]) if n in COMMANDS else (CLIENT_COMMANDS[n], "")
            s = s or CLIENT_HELP.get(n, "")
            out.append(f"  {u:<34} {c(s, DIM)}")
    out.append("")
    out.append(c("try: help config", DIM))
    return "\n".join(out)


CLIENT_COMMANDS = {"logout": "logout", "clear": "clear", "setup": "setup"}
CLIENT_HELP = {"logout": "sign out", "clear": "clear the screen", "setup": "guided setup wizard"}
HELP_EXTRA = {
    "config": "\n\n  config show            all settings for the selected sensor\n"
              "  config show alerts     settings starting with 'alerts'\n"
              "  config set <key> <v>   change one setting\n"
              "  config reset <key>     back to the default\n"
              "  config keys            every setting with a description",
    "sensor": "\n\n  sensor add <name>      create a sensor and get its enrollment code\n"
              "  sensor remove <name> --yes\n  sensor code <name>     new enrollment code (if not enrolled)",
}


@command("whoami", "whoami", "show the signed-in account")
def cmd_whoami(ctx, args):
    n = len(ctx.sensors())
    return f"{ctx.user.email}  {c(f'({n} sensor{'s' if n != 1 else ''})', DIM)}"


@command("sensors", "sensors", "list your sensors")
def cmd_sensors(ctx, args):
    rows = ctx.sensors()
    if not rows:
        return "no sensors yet. Create one with: " + c("sensor add <name>", BOLD)
    data = []
    for s in rows:
        st = s.get("status") or {}
        mark = c("*", GREEN) if s["name"] == ctx.sensor_name else " "
        data.append([mark + s["name"], state_label(s), ago(s.get("last_seen")),
                     st.get("active_persona", "-"), st.get("version", "-")])
    return table(["NAME", "STATE", "LAST SEEN", "PERSONA", "VERSION"], data)


def _new_code() -> str:
    raw = secrets.token_hex(10).upper()
    return "PN-" + "-".join(raw[i:i + 5] for i in range(0, 20, 5))


@command("sensor", "sensor add|remove|code <name>", "manage sensors")
def cmd_sensor(ctx, args):
    need(args, 2, "sensor add|remove|code <name>")
    sub, name = args[0], args[1].lower()
    if sub == "add":
        if not re.match(r"^[a-z0-9][a-z0-9-]{0,39}$", name):
            raise CommandError("name: lowercase letters, digits and dashes, up to 40 chars")
        code = _new_code()
        expires = (datetime.now(timezone.utc) + timedelta(hours=ENROLL_HOURS)).isoformat()
        try:
            ctx.store.create_sensor(ctx.user.id, name, hash_secret(code), expires)
        except ValueError:
            raise CommandError(f"you already have a sensor named '{name}'") from None
        return Result(_enroll_text(ctx, name, code), sensor=name)
    s = ctx.sensor(name)
    if sub == "code":
        if s.get("enrolled_at"):
            raise CommandError(f"'{name}' is already enrolled")
        code = _new_code()
        ctx.store.update_sensor(s["id"], enroll_code_hash=hash_secret(code), enroll_expires_at=(
            datetime.now(timezone.utc) + timedelta(hours=ENROLL_HOURS)).isoformat())
        return _enroll_text(ctx, name, code)
    if sub == "remove":
        if "--yes" not in args:
            return (f"this deletes '{name}' and all its incidents from the console.\n"
                    f"run {c(f'sensor remove {name} --yes', BOLD)} to confirm.")
        ctx.store.delete_sensor(s["id"])
        return Result(f"{c('✓', GREEN)} removed {name}", sensor="")
    raise CommandError("usage: sensor add|remove|code <name>")


def _enroll_text(ctx: Ctx, name: str, code: str) -> str:
    return "\n".join([
        f"{c('✓', GREEN)} sensor {c(name, BOLD)} created and selected.",
        "",
        f"enrollment code: {c(code, YELLOW + BOLD)}   {c(f'(single use, expires in {ENROLL_HOURS}h)', DIM)}",
        "",
        "on the sensor host, add these two lines to /opt/phantomnet/.env:",
        c(f"  PN_CLOUD_URL={ctx.console_url}", CYAN),
        c(f"  PN_ENROLL_CODE={code}", CYAN),
        "then restart it:",
        c("  sudo docker compose up -d", CYAN),
        "",
        f"it shows as {c('online', GREEN)} here within ~30 seconds. Check with: {c('sensors', BOLD)}",
    ])


@command("use", "use <sensor>", "select the sensor that commands act on")
def cmd_use(ctx, args):
    need(args, 1, "use <sensor>")
    s = ctx.sensor(args[0].lower())
    return Result(f"now using {c(s['name'], BOLD)}", sensor=s["name"])


@command("status", "status [sensor]", "health of a sensor")
def cmd_status(ctx, args):
    s = ctx.sensor(args[0].lower() if args else None)
    st = s.get("status") or {}
    cfg = S.effective(ctx.store.get_config(s["id"])[0])
    open_inc = ctx.store.list_incidents([s["id"]], ["open"], limit=500)
    high = [i for i in open_inc if i["severity"] == "high"]
    comps = st.get("components") or {}
    lines = [f"{c(s['name'], BOLD)}  {state_label(s)}  {c('last seen ' + ago(s.get('last_seen')), DIM)}", ""]
    rows = [
        ["open incidents", c(len(open_inc), RED if open_inc else GREEN) + (f"  ({c(len(high), RED)} high)" if high else "")],
        ["active persona", st.get("active_persona", "-")],
        ["next rotation", fmt_time(st.get("next_rotation_at")) if cfg["rotation.enabled"] else "rotation off"],
        ["decoys", ", ".join(d for d in S.DECOYS if cfg[f"decoys.{d}"]) or "none"],
        ["alerts", f"≥ {cfg['alerts.min_severity']} via " + (", ".join(
            x for x, on in (("webhook", cfg["alerts.webhook_url"]), ("email", cfg["alerts.email.host"])) if on) or "dashboard only")],
        ["config", f"v{ctx.store.get_config(s['id'])[1]}" + (
            f" {c('(sensor has v' + str(st.get('config_version')) + ')', YELLOW)}"
            if st.get("config_version") and st.get("config_version") != ctx.store.get_config(s['id'])[1] else "")],
    ]
    lines.append(table(["", ""], rows).split("\n", 1)[1])
    if comps:
        lines += ["", c("components", DIM)]
        for name, info in comps.items():
            okv = info.get("ok")
            tag = c("[ OK ]", GREEN) if okv else c("[WARN]", YELLOW) if okv is None else c("[FAIL]", RED)
            lines.append(f"  {tag} {name:<22} {c(info.get('detail', ''), DIM)}")
    iso = st.get("isolation")
    if iso is not None:
        tag = c("[ OK ]", GREEN) if iso.get("passed") else c("[FAIL]", RED)
        lines.append(f"  {tag} {'isolation check':<22} {c('checked ' + str(iso.get('checked_at')), DIM)}")
    return "\n".join(lines)


@command("incidents", "incidents [--all|--high] [sensor]", "list incidents (open ones by default)")
def cmd_incidents(ctx, args):
    flags = {a for a in args if a.startswith("--")}
    names = [a for a in args if not a.startswith("--")]
    sensors = [ctx.sensor(names[0].lower())] if names else (
        [ctx.sensor()] if ctx.sensor_name else ctx.sensors())
    by_id = {s["id"]: s["name"] for s in sensors}
    statuses = None if "--all" in flags else ["open", "acknowledged"]
    rows = ctx.store.list_incidents(list(by_id), statuses, "high" if "--high" in flags else None, limit=50)
    if not rows:
        return c("no incidents. ", GREEN) + c("(decoys are quiet)", DIM)
    data = [[c(f"#{i['id']}", CYAN), c(i["severity"].upper(), SEV_COLOR[i["severity"]]), i["score"],
             i["source_ip"], ",".join(i.get("services") or []), i["status"], by_id[i["sensor_id"]],
             ago(i["last_seen"])] for i in rows]
    return table(["ID", "SEV", "SCORE", "SOURCE", "DECOYS", "STATUS", "SENSOR", "LAST SEEN"], data) + \
        "\n" + c("details: incident <id>", DIM)


@command("incident", "incident <id>", "full details of one incident")
def cmd_incident(ctx, args):
    need(args, 1, "incident <id>")
    i = get_incident(ctx, args[0])
    out = [f"{c('INCIDENT #' + str(i['id']), BOLD)}  {c(i['severity'].upper(), SEV_COLOR[i['severity']])}  "
           f"score {i['score']}/100  status {c(i['status'], CYAN)}", ""]
    out.append(table(["", ""], [
        ["sensor", i["_sensor_name"]], ["source", i["source_ip"]],
        ["decoys", ", ".join(i.get("services") or [])], ["events", i["event_count"]],
        ["first seen", fmt_time(i["first_seen"])], ["last seen", fmt_time(i["last_seen"])],
    ]).split("\n", 1)[1])
    if i.get("note"):
        out += ["", c("note: ", DIM) + i["note"]]
    out += ["", c("WHAT HAPPENED", GREEN), i.get("summary") or ""]
    out += [f"  - {f}" for f in i.get("findings") or []]
    out += ["", c("SUGGESTED RESPONSE", GREEN)] + [f"  - {g}" for g in i.get("guidance") or []]
    ev = i.get("evidence") or []
    if ev:
        out += ["", c(f"EVIDENCE (latest {min(len(ev), 10)} of {i['event_count']}, redacted)", GREEN)]
        for e in ev[:10]:
            user = f" user={e.get('username')}" if e.get("username") else ""
            out.append(f"  {c(str(e.get('timestamp', ''))[:19], DIM)} {e.get('destination_service') or '-':<6} "
                       f"{e.get('event_type', ''):<24}{user}")
    out += ["", c(f"next: ack {i['id']} · close {i['id']} · export {i['id']}", DIM)]
    return "\n".join(out)


def _set_status(ctx, args, status, verb):
    need(args, 1, f"{verb} <id> [note]")
    i = get_incident(ctx, args[0])
    note = " ".join(args[1:])[:500] or i.get("note")
    ctx.store.update_incident(i["id"], status=status, note=note)
    return f"{c('✓', GREEN)} incident #{i['id']} {status}" + (f" — {note}" if note else "")


@command("ack", "ack <id> [note]", "acknowledge an incident (you're on it)")
def cmd_ack(ctx, args):
    return _set_status(ctx, args, "acknowledged", "ack")


@command("close", "close <id> [note]", "close a resolved incident")
def cmd_close(ctx, args):
    return _set_status(ctx, args, "closed", "close")


@command("reopen", "reopen <id>", "reopen a closed incident")
def cmd_reopen(ctx, args):
    return _set_status(ctx, args, "open", "reopen")


@command("export", "export <id>", "download an incident's redacted evidence as JSON")
def cmd_export(ctx, args):
    need(args, 1, "export <id>")
    i = get_incident(ctx, args[0])
    payload = {k: v for k, v in i.items() if not k.startswith("_")}
    payload["sensor"] = i["_sensor_name"]
    return Result(f"{c('✓', GREEN)} downloading phantomnet-incident-{i['id']}.json",
                  download={"filename": f"phantomnet-incident-{i['id']}.json",
                            "content": json.dumps(payload, indent=2, default=str)})


@command("config", "config show|set|reset|keys", "view or change sensor settings")
def cmd_config(ctx, args):
    sub = args[0] if args else "show"
    if sub == "keys":
        return "\n".join(f"  {k:<34} {c(s.help, DIM)}" + (c("  [host]", YELLOW) if s.host_applied else "")
                         for k, s in S.SETTINGS.items())
    s = ctx.sensor()
    stored, version = ctx.store.get_config(s["id"])
    if sub == "show":
        prefix = args[1] if len(args) > 1 else ""
        eff = S.effective(stored)
        rows = [[k, S.display(k, v) if k in stored else c(S.display(k, v), DIM)]
                for k, v in eff.items() if k.startswith(prefix)]
        if not rows:
            raise CommandError(f"no settings start with '{prefix}'. Try 'config keys'.")
        return f"{c(s['name'], BOLD)} config v{version}  {c('(dim = default)', DIM)}\n" + table(["KEY", "VALUE"], rows)
    if sub == "set":
        need(args, 3, "config set <key> <value>")
        return change_setting(ctx, args[1], " ".join(args[2:]) if len(args) > 3 else args[2], s)
    if sub == "reset":
        need(args, 2, "config reset <key>")
        if args[1] not in S.SETTINGS:
            raise CommandError(f"unknown setting '{args[1]}'")
        stored.pop(args[1], None)
        v = ctx.store.set_config(s["id"], stored)
        return f"{c('✓', GREEN)} {args[1]} reset to {S.display(args[1], S.SETTINGS[args[1]].default)} {c(f'[v{v}]', DIM)}"
    raise CommandError("usage: config show [prefix] | set <key> <value> | reset <key> | keys")


@command("decoys", "decoys [enable|disable <ssh|mysql|http>]", "which fake services run")
def cmd_decoys(ctx, args):
    if args and args[0] in ("enable", "disable"):
        need(args, 2, "decoys enable|disable <ssh|mysql|http>")
        if args[1] not in S.DECOYS:
            raise CommandError("decoy must be ssh, mysql or http")
        return change_setting(ctx, f"decoys.{args[1]}", args[0] == "enable")
    s = ctx.sensor()
    cfg = S.effective(ctx.store.get_config(s["id"])[0])
    rows = [[d, c("on", GREEN) if cfg[f"decoys.{d}"] else c("off", DIM),
             f"{cfg['decoys.bind_ip']}:{cfg[f'decoys.{d}_port']}"] for d in S.DECOYS]
    return table(["DECOY", "STATE", "LISTENS ON"], rows)


@command("persona", "persona list|rotate [name]", "web decoy identities")
def cmd_persona(ctx, args):
    sub = args[0] if args else "list"
    s = ctx.sensor()
    if sub == "list":
        cfg = S.effective(ctx.store.get_config(s["id"])[0])
        active = (s.get("status") or {}).get("active_persona")
        rows = [[(c("* ", GREEN) if p == active else "  ") + p,
                 "yes" if p in cfg["rotation.profiles"] else c("no", DIM)] for p in S.PERSONAS]
        return table(["PERSONA", "IN ROTATION"], rows)
    if sub == "rotate":
        target = args[1] if len(args) > 1 else None
        if target and target not in S.PERSONAS:
            raise CommandError(f"unknown persona. Choose: {', '.join(S.PERSONAS)}")
        a = ctx.store.create_action(s["id"], "rotate", {"profile": target} if target else {})
        return f"{c('✓', GREEN)} rotation queued (action #{a['id']}); the sensor picks it up within ~15s. Check: actions"
    raise CommandError("usage: persona list | persona rotate [name]")


def _list_cmd(ctx, args, key, label, verbs=("add", "remove")):
    s = ctx.sensor()
    stored, _ = ctx.store.get_config(s["id"])
    current = list(S.effective(stored)[key])
    if not args or args[0] == "list":
        return f"{label}: " + (", ".join(current) or "(none)")
    need(args, 2, f"{key} {'|'.join(verbs)} <value>")
    item = S.SETTINGS[key].convert([args[1]])[0]
    if args[0] == verbs[0]:
        new = current + [item] if item not in current else current
    elif args[0] == verbs[1]:
        if item not in current:
            raise CommandError(f"'{item}' isn't in the list")
        new = [x for x in current if x != item]
    else:
        raise CommandError(f"usage: {key} {'|'.join(verbs)} <value>")
    return change_setting(ctx, key, new, s)


@command("honeytokens", "honeytokens [add|remove <username>]", "fake usernames planted as bait")
def cmd_honeytokens(ctx, args):
    return _list_cmd(ctx, args, "honeytokens", "honeytokens")


@command("scanners", "scanners [allow|remove <ip/range>]", "authorized scanners (never alerted)")
def cmd_scanners(ctx, args):
    return _list_cmd(ctx, args, "scanners", "authorized scanners", ("allow", "remove"))


@command("alerts", "alerts [webhook|email|level|test ...]", "notification settings")
def cmd_alerts(ctx, args):
    s = ctx.sensor()
    if not args:
        cfg = S.effective(ctx.store.get_config(s["id"])[0])
        keys = [k for k in S.SETTINGS if k.startswith("alerts.")]
        return table(["KEY", "VALUE"], [[k, S.display(k, cfg[k])] for k in keys]) + "\n" + c(
            "alerts webhook <url|off> · alerts level <low|medium|high> · alerts email <field> <value> · alerts test", DIM)
    sub = args[0]
    if sub == "webhook":
        need(args, 2, "alerts webhook <https-url|off>")
        return change_setting(ctx, "alerts.webhook_url", args[1], s)
    if sub == "level":
        need(args, 2, "alerts level <low|medium|high>")
        return change_setting(ctx, "alerts.min_severity", args[1], s)
    if sub == "email":
        need(args, 3, "alerts email <host|port|user|password|from|to> <value>")
        return change_setting(ctx, f"alerts.email.{args[1]}", args[2], s)
    if sub == "test":
        a = ctx.store.create_action(s["id"], "alert_test", {})
        return f"{c('✓', GREEN)} test alert queued (action #{a['id']}). The sensor sends it within ~15s; check: actions"
    raise CommandError("usage: alerts [webhook|level|email|test]")


@command("isolation", "isolation", "last isolation check reported by the sensor")
def cmd_isolation(ctx, args):
    s = ctx.sensor()
    iso = (s.get("status") or {}).get("isolation")
    if not iso:
        return (c("no isolation check reported yet.", YELLOW) + "\nrun on the sensor host: " +
                c("sudo scripts/verify-isolation.sh", CYAN) + c("  (needs host firewall access, so it can't run remotely)", DIM))
    out = [f"{c('PASSED', GREEN) if iso.get('passed') else c('FAILED', RED)} at {iso.get('checked_at')}"]
    out += [f"  {r.get('target')}: {r.get('result')}" for r in iso.get("results", [])]
    return "\n".join(out)


@command("actions", "actions", "recent remote actions and their results")
def cmd_actions(ctx, args):
    s = ctx.sensor()
    rows = ctx.store.actions_for(s["id"], limit=15)
    if not rows:
        return "no actions yet."
    color = {"queued": YELLOW, "sent": CYAN, "done": GREEN, "failed": RED}
    data = [[f"#{a['id']}", a["kind"], c(a["status"], color[a["status"]]), ago(a["created_at"]),
             json.dumps(a.get("result"))[:60] if a.get("result") else ""] for a in rows]
    return table(["ID", "ACTION", "STATUS", "QUEUED", "RESULT"], data)


@command("audit", "audit", "your recent console commands")
def cmd_audit(ctx, args):
    rows = ctx.store.list_audit(ctx.user.id, 20)
    return table(["WHEN", "COMMAND"], [[ago(a["created_at"]), a["command"]] for a in rows]) if rows else "no history."


# ---------------------------------------------------------------------------

READ_ONLY = {"help", "whoami", "sensors", "status", "incidents", "incident", "export", "isolation",
             "actions", "audit"}


def run(ctx: Ctx, line: str) -> Result:
    ctx.line = line.strip()
    try:
        parts = shlex.split(ctx.line)
    except ValueError as e:
        return Result(c(f"parse error: {e}", RED), ok=False)
    if not parts:
        return Result("")
    name, args = parts[0].lower(), parts[1:]
    entry = COMMANDS.get(name)
    if not entry:
        if name in CLIENT_COMMANDS:
            return Result(c(f"'{name}' runs in your browser terminal", DIM))
        close = [n for n in COMMANDS if n.startswith(name[:3])]
        hint = f" — did you mean {c(close[0], BOLD)}?" if close else " — type 'help'"
        return Result(c(f"unknown command '{name}'", RED) + hint, ok=False)
    try:
        res = entry[0](ctx, args)
        res = res if isinstance(res, Result) else Result(res)
    except CommandError as e:
        return Result(c("error: ", RED) + str(e), ok=False)
    if name not in READ_ONLY:
        redacted = re.sub(r"(webhook|password)\s+\S+", r"\1 [redacted]", ctx.line)[:300]
        try:
            ctx.store.add_audit(ctx.user.id, None, redacted)
        except Exception:
            pass
    return res


def completions() -> dict:
    return {
        "commands": sorted(list(COMMANDS) + list(CLIENT_COMMANDS) + ["login", "signup"]),
        "sub": {"sensor": ["add", "remove", "code"], "config": ["show", "set", "reset", "keys"],
                "decoys": ["enable", "disable"], "persona": ["list", "rotate"],
                "honeytokens": ["add", "remove", "list"], "scanners": ["allow", "remove", "list"],
                "alerts": ["webhook", "email", "level", "test"], "incidents": ["--all", "--high"]},
        "keys": list(S.SETTINGS),
        "personas": list(S.PERSONAS),
    }
