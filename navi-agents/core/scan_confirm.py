"""Scan Confirmation (build 514) — a deterministic confirmation-scan agent. No model anywhere.

Input: plugin IDs + assets. Output: one VERDICT per (asset, plugin) — confirmed fixed, still
vulnerable, not vulnerable, … — proven from Tenable's own scan of exactly those plugins on
exactly those assets, synced back into navi.db. Every decision is a pure function of the
request, the navi.db snapshot and navi's parsed output; what can't be decided from data says
so (INCONCLUSIVE_AUTH / PENDING_INGESTION / NOT_ASSESSED) instead of guessing.

Facts about `navi scan` this module is built on (navi/plugins/scan.py — the source wins over
the navi-scan skill text; each one has a test in tests/test_scan_confirm.py):

  F1  `navi scan create` creates AND launches. Never `start` after `create` (double launch).
  F2  `create` without --scanner calls input() — under a pty that hangs. --scanner is mandatory
      and the child's stdin is /dev/null, so a stray prompt gets EOF and fails fast.
  F3  no --name (unless detected): the scan is found by the ID navi prints, never by name.
  F4  --plugin takes ONE id (Advanced template) — one scan per plugin, unless detection says
      the installed navi takes several (multi_plugin).
  F5  --plugin replaces the policy → plugin + policy is refused (preflight P10).
  F6  success line "I started your scan, your scan ID is: <id>"; create print()s the payload
      dict first (credential uuid inside) → masked before it reaches the audit log.
  F7  start/stop/pause/resume/status swallow errors and exit 0 → every control is proven by a
      read afterwards (a NEW history id for a start, a terminal status for a stop).
  F8  `start <id> --targets X` splits X into characters → never used; reuse needs identical
      targets.
  F10 `navi explore api <url> -raw` prints a Python dict repr (or None) → ast.literal_eval.
  F11 run identity + timing come from GET /scans/<id>/history (id, uuid, status, time_start).

Flow:  plan (read) → ⚡ Launch (gated: writes + NAVI_SCAN_LAUNCH + confirm) → one cli_jobs task
that streams every navi command into the same live CLI window Settings uses → launch proof →
poll → scoped syncs (both `--since` and `--days 1`: `since` only returns state CHANGES) →
ingestion check → verdicts. Runs, scans, verdicts and an append-only, hash-chained event log
live in tag_jobs.db (beside the Tagging / ACR / C2 logs).
"""
from core.errors import swallowed as _swallowed  # no silent excepts
import ast
from core import crown as _crown   # the one crown-jewel definition (Settings, default 8)
import datetime
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
import uuid as _uuid

from core import credstate, db, navi_cli, tagq

# ── limits / constants (each has a test) ─────────────────────────────────────────────────
MAX_PLUGINS = 25
CHUNK_DEFAULT, CHUNK_MAX = 256, 1024
MAX_SCANS_DEFAULT, MAX_SCANS_CAP = 20, 100
TIMEOUT_MIN_DEFAULT, TIMEOUT_MIN_MAX = 360, 24 * 60
SYNC_ATTEMPTS_DEFAULT, SYNC_INTERVAL_DEFAULT = 6, 300
CREATE_TIMEOUT_S = 120
STATUS_TIMEOUT_S = 60
SYNC_TIMEOUT_S = 2 * 3600              # a scoped vulns sync at 150K assets can run long — never under 2 hours
LIST_TIMEOUT_S = 600                   # one-shot reads that return big lists (/scans, /scans/<id>)
LAUNCH_PROOF_S = 120
POLL_FIRST_S, POLL_MAX_S, POLL_BACKOFF = 30, 300, 1.5
MAX_SCAN_LIST = 5000                   # existing scans offered in the one-off pickers (enabled first, newest first)
MAX_TARGETS = 50000                    # resolved targets per run (chunked into scans)

TERMINAL = frozenset({"completed", "canceled", "cancelled", "aborted", "stopped"})
OK_TERMINAL = frozenset({"completed"})
# plugin families that are LOCAL checks — they need credentials to mean anything (P4)
LOCAL_FAMILIES = ("Local Security Checks", "Windows : Microsoft Bulletins", "Windows", "Misc.")
# local-check login proof: 117887 OS Security Patch Assessment Available = the local checks ran;
# 21745 Patch Assessment Failed / 117886 Not Available = they didn't
LOCAL_OK_PLUGINS = ("117887",)
LOCAL_FAIL_PLUGINS = ("21745", "117886")
PROOF_PLUGINS = tuple(sorted({int(credstate.SCAN_INFO)} | {int(p) for p in credstate.FAIL_PLUGINS}
                             | {int(p) for p in credstate.CRED_OK_PLUGINS}
                             | {int(p) for p in LOCAL_OK_PLUGINS + LOCAL_FAIL_PLUGINS}))

STATES = ("PLANNED", "PREFLIGHT", "REFUSED", "LAUNCHING", "LAUNCH_FAILED", "RUNNING", "SCANS_DONE",
          "SYNCING", "VERIFIED", "ABORTED")
TERMINAL_STATES = frozenset({"REFUSED", "LAUNCH_FAILED", "VERIFIED", "ABORTED"})

VERDICTS = ("NOT_ASSESSED", "INCONCLUSIVE_AUTH", "PENDING_INGESTION", "STILL_VULNERABLE", "CONFIRMED_FIXED",
            "NEWLY_FOUND", "NOT_VULNERABLE", "UNCHANGED_UNKNOWN")

_DIGITS = re.compile(r"^\d{1,12}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SCANNER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")
_SCAN_ID_LINE = re.compile(r"^\s*I started your scan, your scan ID is:\s*(\d+)\s*$")
_STATUS_LINE = re.compile(r"Last Status update\s*:\s*([A-Za-z_]+)")


# ══ pure: normalisation ══════════════════════════════════════════════════════════════════
def _int_in(v, lo, hi, default):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def valid_scan_target(t) -> bool:
    """A plain IP, a CIDR (ip_network, strict=False) or a hostname. Never something that starts
    with '-', carries whitespace / shell characters, or a comma (commas separate targets)."""
    s = str(t or "")
    if not s or s != s.strip() or s.startswith("-") or "," in s or re.search(r"[\s;|&$`<>()'\"\\{}\[\]*?!#]", s):
        return False
    try:
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
        return True
    except ValueError:
        pass
    return "/" not in s and bool(_HOST_RE.match(s))


def normalize(req):
    """(normalized request, [errors]). Pure: same input in any order → same output + sha."""
    req = req if isinstance(req, dict) else {}
    errs = []
    plugins = []
    for p in (req.get("plugins") or []):
        try:
            n = int(str(p).strip())
        except (TypeError, ValueError):
            errs.append(f"plugin id {p!r} is not a number")
            continue
        if not 1 <= n <= 9999999:
            errs.append(f"plugin id {n} is out of range")
            continue
        plugins.append(n)
    plugins = sorted(set(plugins))
    if len(plugins) > MAX_PLUGINS:
        errs.append(f"at most {MAX_PLUGINS} plugins per run ({len(plugins)} given)")
    policy = str(req.get("policy_id") or "").strip() or None
    if policy and not _DIGITS.match(policy):
        errs.append("policy id must be a number")
    mode = "oneoff" if req.get("mode") == "oneoff" else "confirm"
    rerun = str(req.get("rerun_scan_id") or "").strip() or None
    if rerun and (mode != "oneoff" or not _DIGITS.match(rerun)):
        errs.append("re-run takes an existing scan id (digits) in one-off mode")
        rerun = None
    if mode == "confirm" and not plugins:
        errs.append("give at least one plugin id to confirm (or switch to ⚡ One-off scan)")
    template = str(req.get("template") or "").strip() or None
    if template and template not in TEMPLATES:
        errs.append("template must be basic or discovery")
        template = None
    if mode == "oneoff" and not rerun and not plugins and not policy:
        template = template or "basic"           # no policy, no plugins → navi's Basic Network Scan
    elif template:
        errs.append("a template is only for a one-off scan without a policy or plugins")
        template = None
    via = str(req.get("via_scan_id") or "").strip() or None
    if via and not _DIGITS.match(via):
        errs.append("scan id must be digits")
        via = None
    if rerun:                                  # the scan's own targets / scanner / policy are used
        plugins, policy = [], None
    a = req.get("assets") if isinstance(req.get("assets"), dict) else {}
    sel = [k for k in ("ips", "uuids", "tag") if a.get(k)]
    assets = {}
    if rerun:
        pass
    elif len(sel) != 1:
        errs.append("choose exactly one asset selector: IPs, asset UUIDs or a tag")
    else:
        k = sel[0]
        if k == "ips":
            vals = a["ips"] if isinstance(a["ips"], list) else re.split(r"[\s,;]+", str(a["ips"]))
            ips = sorted({str(x).strip().lower() for x in vals if str(x).strip()})
            bad = [x for x in ips if not valid_scan_target(x)]
            if bad:
                errs.append("not a valid target: " + ", ".join(bad[:5]))
            assets = {"ips": [x for x in ips if x not in bad]}
        elif k == "uuids":
            vals = a["uuids"] if isinstance(a["uuids"], list) else re.split(r"[\s,;]+", str(a["uuids"]))
            us = sorted({str(x).strip().lower() for x in vals if str(x).strip()})
            bad = [x for x in us if not _UUID_RE.match(x)]
            if bad:
                errs.append("not an asset UUID: " + ", ".join(bad[:5]))
            assets = {"uuids": [x for x in us if x not in bad]}
        else:
            t = a["tag"] if isinstance(a["tag"], dict) else {}
            cat, val = str(t.get("category") or "").strip(), str(t.get("value") or "").strip()
            if not cat or not val:
                errs.append("a tag selector needs a category and a value")
            assets = {"tag": {"category": cat, "value": val}}
    scanner = str(req.get("scanner_id") or "").strip()
    if scanner and not _SCANNER_RE.match(scanner):
        errs.append("scanner id must be letters, digits or dashes")
    cred = (str(req.get("credential_uuid") or "").strip().lower() or None) if not rerun else None
    if cred and not _UUID_RE.match(cred):
        errs.append("credential must be a UUID")
    # a policy + plugins mix is reported by preflight P10 (all checks are reported, not just the first)
    norm = {
        "mode": mode, "verify": mode == "confirm", "rerun_scan_id": rerun,
        "template": template if not rerun else None, "via_scan_id": via if not rerun else None,
        "plugins": plugins, "policy_id": policy, "assets": assets, "scanner_id": (scanner or None) if not rerun else None,
        "credential_uuid": cred,
        "chunk_size": _int_in(req.get("chunk_size"), 1, CHUNK_MAX, CHUNK_DEFAULT),
        "max_scans": _int_in(req.get("max_scans"), 1, MAX_SCANS_CAP, MAX_SCANS_DEFAULT),
        "timeout_min": _int_in(req.get("timeout_min"), 10, TIMEOUT_MIN_MAX, TIMEOUT_MIN_DEFAULT),
        "sync_attempts": _int_in(req.get("sync_attempts"), 1, 20, SYNC_ATTEMPTS_DEFAULT),
        "sync_interval_s": _int_in(req.get("sync_interval_s"), 30, 3600, SYNC_INTERVAL_DEFAULT),
        "reuse": req.get("reuse", True) is not False,     # JSON false turns reuse off
    }
    norm["request_sha256"] = sha(norm)
    return norm, errs


def sha(obj) -> str:
    o = {k: v for k, v in obj.items() if k != "request_sha256"} if isinstance(obj, dict) else obj
    return hashlib.sha256(json.dumps(o, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ══ resolution (read-only navi.db) ═══════════════════════════════════════════════════════
def _cols(table, path=None):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}")', path=path)}
    except Exception:
        return set()


def _acr(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _info(r, ip, host):
    a = _acr(r.get("acr"))
    return {"ip": ip or "", "host": host or "", "agent": bool(r.get("agent_uuid")), "acr": a,
            "crown": _crown.is_crown(a)}


def public_targets(targets):
    """Targets that are public (globally routable) addresses — the confirm dialog calls them out."""
    out = []
    for t in targets or []:
        try:
            n = ipaddress.ip_network(t, strict=False)
        except ValueError:
            continue
        if n.is_global:
            out.append(t)
    return out


def _addr(row):
    for k in ("ip_address", "fqdn", "hostname"):
        v = str(row.get(k) or "").strip()
        if v:
            v = v.split(",")[0].strip().lower()
            if valid_scan_target(v):
                return v
    return ""


def resolve(norm, path=None):
    """{targets (sorted), asset_map (target → [asset uuid…]), excluded [{asset|target, reason}],
       assets (uuid → {ip, host, agent_only})}."""
    a = norm.get("assets") or {}
    acols = _cols("assets", path)
    want = [c for c in ("uuid", "ip_address", "fqdn", "hostname", "agent_uuid", "acr") if c in acols]
    sel = ", ".join(want) or "uuid"
    targets, amap, excluded, info = set(), {}, [], {}

    def _take(rows):
        for r in rows:
            u = str(r.get("uuid") or "").lower()
            ad = _addr(r)
            info[u] = _info(r, r.get("ip_address") or "", r.get("hostname") or r.get("fqdn") or "")
            if not ad:
                excluded.append({"asset": u, "reason": "no_address"})
                continue
            targets.add(ad)
            amap.setdefault(ad, []).append(u)

    if "uuids" in a:
        found = set()
        us = a["uuids"]
        for i in range(0, len(us), 500):
            part = us[i:i + 500]
            rows = db.query(f"SELECT {sel} FROM assets WHERE lower(uuid) IN ({','.join('?' * len(part))})",
                            tuple(part), path=path)
            found |= {str(r.get("uuid") or "").lower() for r in rows}
            _take(rows)
        for u in us:
            if u not in found:
                excluded.append({"asset": u, "reason": "not_in_navi_db"})
    elif "tag" in a:
        from core import tagname
        cats = tagname.names(a["tag"]["category"]) or [a["tag"]["category"]]
        rows = db.query(f"SELECT {sel} FROM assets WHERE uuid IN (SELECT asset_uuid FROM tags WHERE tag_key IN "
                        f"({','.join('?' * len(cats))}) AND tag_value=?) LIMIT {MAX_TARGETS + 1}",
                        tuple(cats) + (a["tag"]["value"],), path=path)
        _take(rows)
    elif "ips" in a:
        ips = a["ips"]
        nets = [x for x in ips if "/" in x]
        plain = [x for x in ips if "/" not in x]
        for t in ips:
            targets.add(t)
        if plain and "ip_address" in acols:
            for i in range(0, len(plain), 500):
                part = plain[i:i + 500]
                for r in db.query(f"SELECT {sel} FROM assets WHERE lower(ip_address) IN ({','.join('?' * len(part))})",
                                  tuple(part), path=path):
                    u = str(r.get("uuid") or "").lower()
                    ip = str(r.get("ip_address") or "").lower()
                    amap.setdefault(ip, []).append(u)
                    info[u] = _info(r, ip, r.get("hostname") or "")
            for x in plain:                     # a hostname target: match fqdn / hostname too
                if x not in amap and not _is_ip(x):
                    for r in db.query(f"SELECT {sel} FROM assets WHERE lower(fqdn)=? OR lower(hostname)=? LIMIT 20",
                                      (x, x), path=path):
                        u = str(r.get("uuid") or "").lower()
                        amap.setdefault(x, []).append(u)
                        info[u] = _info(r, r.get("ip_address") or "", r.get("hostname") or "")
        if nets and "ip_address" in acols:
            ns = [ipaddress.ip_network(n, strict=False) for n in nets]
            for r in db.query(f"SELECT {sel} FROM assets WHERE ip_address IS NOT NULL AND ip_address<>''", path=path):
                try:
                    ipa = ipaddress.ip_address(str(r.get("ip_address")).split(",")[0].strip())
                except ValueError:
                    continue
                for n, raw in zip(ns, nets):
                    if ipa in n:
                        u = str(r.get("uuid") or "").lower()
                        amap.setdefault(raw, []).append(u)
                        info[u] = _info(r, str(ipa), r.get("hostname") or "")
    for k in amap:
        amap[k] = sorted(set(amap[k]))
    return {"targets": sorted(targets), "asset_map": dict(sorted(amap.items())),
            "excluded": sorted(excluded, key=lambda e: (e.get("reason", ""), e.get("asset", ""))), "assets": info}


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def baseline(asset_uuids, plugins, path=None):
    """{(asset_uuid, plugin_id): {state, last_found, scan_uuid}} for every in-scope pair present
    in navi.db (absent pairs are simply missing). Never SELECTs output."""
    vcols = _cols("vulns", path)
    if not vcols or not plugins:
        return {}
    want = set(asset_uuids)
    cols = ["asset_uuid", "plugin_id"] + [c for c in ("state", "last_found", "scan_uuid") if c in vcols]
    out = {}
    q = (f"SELECT {', '.join(cols)} FROM vulns{db.indexed_by('hx_v_plugin') if hasattr(db, 'indexed_by') else ''} "
         f"WHERE plugin_id IN ({','.join('?' * len(plugins))})")
    try:
        rows = db.query(q, tuple(str(p) for p in plugins), path=path)
    except Exception:
        rows = db.query(q.replace(db.indexed_by('hx_v_plugin') if hasattr(db, 'indexed_by') else '', ''),
                        tuple(str(p) for p in plugins), path=path)
    for r in rows:
        u = str(r.get("asset_uuid") or "").lower()
        if u in want:
            k = (u, int(r["plugin_id"]))
            cur = {"state": str(r.get("state") or "").lower(), "last_found": r.get("last_found"),
                   "scan_uuid": r.get("scan_uuid")}
            prev = out.get(k)
            if prev is None or str(cur["last_found"] or "") > str(prev["last_found"] or ""):
                out[k] = cur                      # several rows (ports) → the latest one
    return out


# ══ pure: argv + plan ════════════════════════════════════════════════════════════════════
TEMPLATES = ("basic", "discovery")       # navi's own: no flag = Basic Network Scan, -discovery = Host Discovery


def build_create_argv(chunk, scanner_id, plugins, cred=None, policy_id=None, name=None, multi=False, template=None):
    """The ONLY place a `navi scan create` argv is built (F1, F2, F4, F5). Refuses without a
    scanner (F2: navi would prompt), with a policy AND plugins (F5), with an invalid target, or
    with several plugins on a navi that takes one (F4)."""
    if not scanner_id or not _SCANNER_RE.match(str(scanner_id)):
        raise ValueError("a scanner is required — navi would otherwise stop and ask for one (F2)")
    chunk = list(chunk or [])
    if not chunk or not all(valid_scan_target(t) for t in chunk):
        raise ValueError("every target must be a valid IP, CIDR or hostname")
    plugins = [int(p) for p in (plugins or [])]
    if plugins and policy_id:
        raise ValueError("--plugin replaces the policy in navi (F5) — use one or the other")
    if len(plugins) > 1 and not multi:
        raise ValueError("this navi takes one --plugin per scan (F4)")
    if cred and not _UUID_RE.match(str(cred)):
        raise ValueError("credential must be a UUID")
    if template not in (None, "basic", "discovery"):
        raise ValueError("unknown scan template")
    if template == "discovery" and (plugins or policy_id):
        raise ValueError("host discovery is its own template — no plugins or policy with it")
    argv = ["scan", "create", ",".join(chunk), "--scanner", str(scanner_id)]
    if template == "discovery":
        argv.append("-discovery")
    for p in plugins:
        argv += ["--plugin", str(p)]
    if policy_id:
        if not _DIGITS.match(str(policy_id)):
            raise ValueError("policy id must be a number")
        argv += ["--policy", str(policy_id)]
    if cred:
        argv += ["--cred", str(cred)]
    if name:
        argv += ["--name", re.sub(r"[^A-Za-z0-9_.-]+", "-", str(name))[:80]]
    return argv


CONTROL = ("start", "stop", "pause", "resume", "status")


def build_control_argv(sub, scan_id):
    if sub not in CONTROL:
        raise ValueError("unknown scan control")
    if not _DIGITS.match(str(scan_id or "")):
        raise ValueError("scan id must be digits")
    return ["scan", sub, str(scan_id)]


def build_api_argv(path_):
    """`navi explore api <path> -raw` for a fixed set of read paths (digits-only ids)."""
    ok = re.match(r"^/(scanners|credentials|policies|scans|scans/\d+(/history|/latest-status)?(\?history_id=\d+)?)$",
                  str(path_ or ""))
    if not ok:
        raise ValueError("not an allowed read path")
    return ["explore", "api", path_, "-raw"]


def build_delete_argv(scan_id):
    if not _DIGITS.match(str(scan_id or "")):
        raise ValueError("scan id must be digits")
    return ["action", "delete", "scan", str(scan_id)]


def chunks(xs, n):
    return [xs[i:i + n] for i in range(0, len(xs), n)]


def reuse_key(chunk, plugins, scanner_id, cred):
    return hashlib.sha256(json.dumps([sorted(chunk), sorted(int(p) for p in plugins), str(scanner_id or ""),
                                      str(cred or "")], separators=(",", ":")).encode()).hexdigest()


def mask_argv(argv, cred=None):
    out = []
    for i, a in enumerate(argv):
        if cred and str(a).lower() == str(cred).lower():
            out.append("****")
        elif i > 0 and argv[i - 1] == "--cred":
            out.append("****")
        else:
            out.append(a)
    return out


def plan(norm, resolved, multi_plugin=False, named=False):
    """[{plan_index, targets, plugins, argv, reuse_key}] + plan_sha256. Pure."""
    if norm.get("rerun_scan_id"):               # one-off: start an existing scan on its own targets
        sid = str(norm["rerun_scan_id"])
        s0 = {"plan_index": 0, "targets": [], "plugins": [], "argv": build_control_argv("start", sid),
              "reuse_key": reuse_key([], [], "rerun:" + sid, None), "rerun": sid}
        body = {"request_sha256": norm.get("request_sha256"), "rerun": sid, "scans": [s0]}
        return {"scans": [s0], "multi_plugin": False, "plan_sha256": sha(body), "rerun": sid}
    targets = list(resolved.get("targets") or [])
    plugins = list(norm.get("plugins") or [])
    cs = chunks(targets, norm.get("chunk_size") or CHUNK_DEFAULT)
    scans = []
    if plugins and multi_plugin:
        groups = [sorted(set(plugins) | set(PROOF_PLUGINS))]
    elif plugins:
        groups = [[p] for p in plugins]
    else:
        groups = [[]]                              # Scan Now: full policy
    for g in groups:
        for c in cs:
            idx = len(scans)
            name = f"Ensemble-confirm-{idx + 1}" if named else None
            argv = build_create_argv(c, norm.get("scanner_id"), g, norm.get("credential_uuid"),
                                     norm.get("policy_id") if not g else None, name=name, multi=multi_plugin,
                                     template=norm.get("template") if not g else None) \
                if norm.get("scanner_id") else None
            scans.append({"plan_index": idx, "targets": c, "plugins": g,
                          "argv": argv, "reuse_key": reuse_key(c, g, "%s|%s|%s" % (
                              norm.get("scanner_id"), "" if g else (norm.get("policy_id") or ""),
                              "" if g else (norm.get("template") or "")), norm.get("credential_uuid"))})
    body = {"request_sha256": norm.get("request_sha256"), "multi_plugin": bool(multi_plugin),
            "scans": [{k: s[k] for k in ("plan_index", "targets", "plugins", "argv", "reuse_key")} for s in scans]}
    return {"scans": scans, "multi_plugin": bool(multi_plugin), "plan_sha256": sha(body)}


# ══ preflight (all checks reported) ══════════════════════════════════════════════════════
def plugin_families(plugins, path=None):
    """{plugin_id: family or None} — from hx_plugin when built, else one indexed vulns row."""
    out = {int(p): None for p in plugins}
    if not plugins:
        return out
    try:
        from core import hx_summary
        hc = _cols("hx_plugin", path)
        fcol = "family" if "family" in hc else ("plugin_family" if "plugin_family" in hc else None)
        if hx_summary.usable(path) and fcol:
            for r in db.query(f"SELECT plugin_id, {fcol} AS fam FROM hx_plugin WHERE plugin_id IN "
                              f"({','.join('?' * len(plugins))})", tuple(str(p) for p in plugins), path=path):
                out[int(r["plugin_id"])] = r.get("fam")
            if all(v is not None for v in out.values()):
                return out
    except Exception as _e:
        _swallowed(_e)
    if "plugin_family" in _cols("vulns", path):
        for p in plugins:
            r = db.query("SELECT plugin_family FROM vulns WHERE plugin_id=? LIMIT 1", (str(p),), path=path)
            if r:
                out[int(p)] = r[0].get("plugin_family")
    return out


def plugin_names(plugins, path=None):
    out = {}
    if not plugins:
        return out
    ph = ",".join("?" * len(plugins))
    try:
        if "name" in _cols("plugins", path):
            for r in db.query(f"SELECT plugin_id, name FROM plugins WHERE plugin_id IN ({ph})",
                              tuple(str(p) for p in plugins), path=path):
                out[int(r["plugin_id"])] = r.get("name")
    except Exception as _e:
        _swallowed(_e)
    missing = [p for p in plugins if int(p) not in out]
    for p in missing:
        try:
            r = db.query("SELECT plugin_name FROM vulns WHERE plugin_id=? LIMIT 1", (str(p),), path=path)
            if r:
                out[int(p)] = r[0].get("plugin_name")
        except Exception as _e:
            _swallowed(_e)
    return out


def is_local(family) -> bool:
    return bool(family) and any(str(family).strip() == f for f in LOCAL_FAMILIES)


def preflight(norm, resolved, pl, ctx):
    """[{id, level ok|warn|fail, msg}] for P1–P11. ctx: {write_gate, scan_gate, scanners (list or
    None when unreadable), credentials (list or None), families {pid: family}, plugins_known
    (set or None when the plugins table is empty), active_same (bool), hx_busy (bool),
    chain_locked (bool)} — injected, so this stays pure and testable."""
    out = []

    def add(i, ok, msg, warn=False):
        out.append({"id": i, "level": "ok" if ok else ("warn" if warn else "fail"), "msg": msg})
    add("P1", not ctx.get("write_gate"), ctx.get("write_gate") or "writes are on and navi was found")
    add("P2", not ctx.get("scan_gate"), ctx.get("scan_gate") or "scan launch is enabled (NAVI_SCAN_LAUNCH)")
    sc = norm.get("scanner_id")
    scanners = ctx.get("scanners")
    rr = norm.get("rerun_scan_id")
    if rr:
        add("P3", True, "re-run uses the scan's own scanner, targets and policy")
    elif not sc:
        add("P3", False, "pick a scanner — navi would stop and ask for one (F2)")
    elif scanners is None:
        add("P3", False, "could not read the scanner list from Tenable (navi explore api /scanners)")
    else:
        m = next((s for s in scanners if str(s.get("id")) == str(sc) or str(s.get("uuid")) == str(sc)), None)
        if not m:
            add("P3", False, f"scanner {sc} is not in Tenable's scanner list")
        else:
            st = str(m.get("status") or "").lower()
            add("P3", st in ("on", "online", "ready", ""), f"scanner {m.get('name') or sc} is {st or 'listed'}"
                + ("" if st in ("on", "online", "ready", "") else " — it must be on"))
    fams = ctx.get("families") or {}
    local = [p for p in norm.get("plugins") or [] if is_local(fams.get(int(p)))]
    unknown = [p for p in norm.get("plugins") or [] if fams.get(int(p)) is None]
    if local and not norm.get("credential_uuid"):
        add("P4", False, "local_check_needs_cred: plugin(s) %s are local checks — pick a credential"
            % ", ".join(str(p) for p in local))
    elif unknown and not norm.get("credential_uuid"):
        add("P4", False, "family unknown for %s (not in navi.db) — add a credential in case it is a local check"
            % ", ".join(str(p) for p in unknown), warn=True)
    else:
        add("P4", True, ("%d local-check plugin(s), credential set" % len(local)) if local
            else "no local-check plugins")
    cred = norm.get("credential_uuid")
    creds = ctx.get("credentials")
    if cred:
        if creds is None:
            add("P5", False, "could not read the credential list from Tenable")
        else:
            m = next((c for c in creds if str(c.get("uuid") or c.get("id") or "").lower() == cred), None)
            add("P5", bool(m), ("credential %s" % ((m or {}).get("name") or cred)) if m
                else "credential %s is not in Tenable's managed credentials" % cred)
    else:
        add("P5", True, "no credential (network checks only)")
    known = ctx.get("plugins_known")
    if known is None:
        add("P6", False, "plugins_table_empty: navi.db's plugins table is empty — plugin ids not checked", warn=True)
    else:
        miss = [p for p in norm.get("plugins") or [] if int(p) not in known]
        add("P6", not miss, ("unknown plugin id(s): " + ", ".join(str(p) for p in miss)) if miss
            else "every plugin id is known")
    n_t, n_s = len(resolved.get("targets") or []), len(pl.get("scans") or [])
    if rr:
        add("P7", True, "1 scan (re-run of #%s)" % rr)
    else:
        add("P7", 1 <= n_t <= MAX_TARGETS and n_s <= norm.get("max_scans", MAX_SCANS_DEFAULT),
            f"{n_t} target(s) → {n_s} scan(s) (cap {norm.get('max_scans')})" if n_t else "no scannable target")
    add("P8", not ctx.get("active_same"), "another run with the same request is still running"
        if ctx.get("active_same") else "no identical run in progress")
    busy = ctx.get("hx_busy") or ctx.get("chain_locked")
    add("P9", not busy, "navi.db is locked by ⚡ Optimize or an Automation Station chain — the post-scan sync "
        "would block" if busy else "navi.db is free for the post-scan sync")
    add("P10", not (norm.get("plugins") and norm.get("policy_id")),
        "a policy and plugins can't be combined — navi swaps --plugin onto the Advanced template (F5)"
        if (norm.get("plugins") and norm.get("policy_id")) else "no plugin + policy mix")
    infos = resolved.get("assets") or {}
    agent_only = [u for u, i in infos.items() if i.get("agent") and not i.get("ip")]
    add("P11", not agent_only, ("%d agent-only asset(s): a network scan may not reach them" % len(agent_only))
        if agent_only else "no agent-only assets", warn=True)
    pol = norm.get("policy_id")
    if pol:                                    # P12 — the policy is a saved policy or one an existing scan uses
        pols, scans_ = ctx.get("policies"), ctx.get("scans")
        if pols is None and scans_ is None:
            add("P12", False, "could not read policies / scans from Tenable — policy %s not checked" % pol, warn=True)
        else:
            m = next((x for x in pols or [] if str(x.get("id")) == pol), None)
            u = [x for x in scans_ or [] if str(x.get("policy_id")) == pol]
            add("P12", bool(m or u), ("policy %s · %s" % (pol, m.get("name"))) if m else
                ("policy %s — used by scan %s" % (pol, ", ".join("#%s %s" % (x["id"], x.get("name") or "") for x in u[:3])))
                if u else "policy %s is not a saved policy and no scan uses it" % pol)
    if rr:                                     # P13 — the scan to re-run exists and isn't running
        scans_ = ctx.get("scans")
        m = next((x for x in scans_ or [] if str(x.get("id")) == rr), None) if scans_ is not None else None
        m = m or ctx.get("scan_direct")           # not in the list (older than the newest MAX_SCAN_LIST) → read by id
        if scans_ is None and not m:
            add("P13", False, "could not read the scan list from Tenable (navi explore api /scans)")
        elif not m:
            add("P13", False, "scan #%s is not in Tenable's scan list" % rr)
        else:
            busy = str(m.get("status") or "").lower() in ("running", "pending", "processing", "paused", "resuming",
                                                           "initializing", "publishing")
            add("P13", not busy, "scan #%s %s is %s" % (rr, m.get("name") or "", m.get("status") or "?")
                + (" — wait for it to finish" if busy else ""))
    return out


def preflight_ok(checks):
    return all(c["level"] != "fail" for c in checks)


# ══ pure: navi output parsers ════════════════════════════════════════════════════════════
def parse_scan_id(text):
    """(scan_id or None, warning or None) — anchored to navi's exact success line (F6)."""
    ids = [m.group(1) for m in (_SCAN_ID_LINE.match(l) for l in str(text or "").splitlines()) if m]
    if not ids:
        return None, "navi did not print a scan ID"
    return ids[-1], ("navi printed %d scan IDs — using the last" % len(ids)) if len(ids) > 1 else None


def parse_raw(text):
    """`navi explore api … -raw` prints a Python dict repr (F10) — None on failure / garbage."""
    s = str(text or "").strip()
    if not s or s == "None":
        return None
    start = min([i for i in (s.find("{"), s.find("[")) if i >= 0] or [-1])
    if start < 0:
        return None
    try:
        v = ast.literal_eval(s[start:])
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return None
    return v if isinstance(v, (dict, list)) else None


def parse_status_line(text):
    m = _STATUS_LINE.search(str(text or ""))
    return m.group(1).lower() if m else None


def norm_status(s):
    s = str(s or "").strip().lower()
    return "canceled" if s == "cancelled" else s


def mask_line(line, secrets=()):
    """Hide the payload dict navi create print()s (F6) and any secret (credential uuid)."""
    s = str(line)
    t = s.strip()
    if t.startswith("{") and ("'settings'" in t or "'text_targets'" in t):
        return "[payload hidden]"                 # navi create's print(payload) — never in the window or log
    for x in secrets:
        if x:
            s = re.sub(re.escape(str(x)), "****", s, flags=re.I)
    return s


def history_entries(raw):
    if isinstance(raw, dict):
        h = raw.get("history")
        if isinstance(h, list):
            return [x for x in h if isinstance(x, dict)]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    return []


def _hid(e):
    return str(e.get("id") or e.get("history_id") or "")


def to_epoch(v):
    """navi.db times ('2026-06-15T00:00:00Z', '...000Z', epoch seconds/ms) → epoch seconds or None."""
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return float(v) / (1000.0 if v > 1e11 else 1.0)
    s = str(v).strip()
    if re.match(r"^\d+(\.\d+)?$", s):
        f = float(s)
        return f / (1000.0 if f > 1e11 else 1.0)
    s = s.replace("Z", "+00:00")
    try:
        d = datetime.datetime.fromisoformat(s)
    except ValueError:
        try:
            d = datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d.timestamp()


# ══ pure: verdicts ═══════════════════════════════════════════════════════════════════════
def verdict(base, fact, row):
    """One (asset, plugin) verdict. base = baseline row or None (absent); row = navi.db row now or
    None; fact = {excluded, scan_completed, host_seen, local, auth_ok (True/False/None),
    ingested (bool), time_start, fixed_date (epoch or None)}. → (verdict, rule id)."""
    f = fact or {}
    t0 = f.get("time_start")
    if f.get("excluded") or not f.get("scan_completed") or not f.get("host_seen"):
        return "NOT_ASSESSED", "R1"
    if f.get("local") and f.get("auth_ok") is False:      # evidence the scan did NOT log in
        return "INCONCLUSIVE_AUTH", "R2"
    if not f.get("ingested"):
        return "PENDING_INGESTION", "R3"
    st = str((row or {}).get("state") or "").lower()
    lf = to_epoch((row or {}).get("last_found"))
    after = lambda x: x is not None and t0 is not None and x >= t0 - 1
    b = str((base or {}).get("state") or "").lower()
    if base and row and st in ("open", "reopened") and after(lf):
        return "STILL_VULNERABLE", "R4"
    if base and b in ("open", "reopened") and row and st == "fixed" and (after(lf) or after(f.get("fixed_date"))):
        return "CONFIRMED_FIXED", "R5"
    if not base and row and st in ("open", "reopened") and after(lf):
        return "NEWLY_FOUND", "R6"
    if not base and not row and (not f.get("local") or f.get("auth_ok") is True):
        return "NOT_VULNERABLE", "R7"                       # a local check needs a proven login to say so
    return "UNCHANGED_UNKNOWN", "R8"


# ══ persistence (tag_jobs.db) ════════════════════════════════════════════════════════════
_LOCK = threading.Lock()
_READY = {"p": None}
GENESIS = "0" * 64


def _con():
    con = sqlite3.connect(tagq._DBPATH, timeout=10.0)
    con.execute("PRAGMA busy_timeout=10000")
    con.row_factory = sqlite3.Row
    if _READY["p"] != tagq._DBPATH:
        con.executescript(
            "CREATE TABLE IF NOT EXISTS scan_runs(run_id TEXT PRIMARY KEY, created REAL, updated REAL, state TEXT, "
            "  request_json TEXT, request_sha256 TEXT, resolved_json TEXT, plan_json TEXT, plan_sha256 TEXT, "
            "  preflight_json TEXT, baseline_json TEXT, job_id INTEGER, log TEXT, note TEXT, summary_json TEXT, "
            "  operator TEXT);"
            "CREATE INDEX IF NOT EXISTS scan_runs_sha ON scan_runs(request_sha256);"
            "CREATE TABLE IF NOT EXISTS scan_run_scans(run_id TEXT, plan_index INTEGER, scan_id TEXT, history_id TEXT, "
            "  history_uuid TEXT, time_start REAL, status TEXT, reuse_key TEXT, plugins TEXT, targets INTEGER, "
            "  launched REAL, ended REAL, deleted REAL, note TEXT, PRIMARY KEY(run_id, plan_index));"
            "CREATE INDEX IF NOT EXISTS scan_run_scans_reuse ON scan_run_scans(reuse_key);"
            "CREATE TABLE IF NOT EXISTS scan_run_verdicts(run_id TEXT, asset_uuid TEXT, plugin_id INTEGER, target TEXT, "
            "  verdict TEXT, rule TEXT, evidence_json TEXT, PRIMARY KEY(run_id, asset_uuid, plugin_id));"
            "CREATE TABLE IF NOT EXISTS scan_run_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, run_id TEXT, "
            "  kind TEXT, detail TEXT, prev_hash TEXT, row_hash TEXT);"
            "CREATE INDEX IF NOT EXISTS scan_run_events_run ON scan_run_events(run_id);"
            "CREATE TRIGGER IF NOT EXISTS scan_run_events_no_update BEFORE UPDATE ON scan_run_events "
            "  BEGIN SELECT RAISE(ABORT, 'scan_run_events is append-only'); END;"
            "CREATE TRIGGER IF NOT EXISTS scan_run_events_no_delete BEFORE DELETE ON scan_run_events "
            "  BEGIN SELECT RAISE(ABORT, 'scan_run_events is append-only'); END;")
        try:
            os.chmod(tagq._DBPATH, 0o600)
        except OSError:
            pass
        _READY["p"] = tagq._DBPATH
    return con


def event(run_id, kind, detail=None):
    """Append one hash-chained event (c2log's rule: row_hash = sha256(prev_hash + canonical row))."""
    d = json.dumps(detail or {}, sort_keys=True, default=str)[:4000]
    with _LOCK:
        con = _con()
        try:
            prev = con.execute("SELECT row_hash FROM scan_run_events ORDER BY id DESC LIMIT 1").fetchone()
            ph = prev["row_hash"] if prev else GENESIS
            ts = time.time()
            body = json.dumps({"ts": round(ts, 6), "run_id": run_id, "kind": kind, "detail": d}, sort_keys=True)
            rh = hashlib.sha256((ph + body).encode()).hexdigest()
            con.execute("INSERT INTO scan_run_events(ts, run_id, kind, detail, prev_hash, row_hash) VALUES (?,?,?,?,?,?)",
                        (round(ts, 6), run_id, kind, d, ph, rh))
            con.commit()
        finally:
            con.close()


def verify_chain():
    con = _con()
    try:
        ph = GENESIS
        n = 0
        for r in con.execute("SELECT * FROM scan_run_events ORDER BY id"):
            body = json.dumps({"ts": r["ts"], "run_id": r["run_id"], "kind": r["kind"], "detail": r["detail"]},
                              sort_keys=True)
            if r["prev_hash"] != ph or hashlib.sha256((ph + body).encode()).hexdigest() != r["row_hash"]:
                return {"ok": False, "rows": n, "broken_at": r["id"]}
            ph, n = r["row_hash"], n + 1
        return {"ok": True, "rows": n}
    finally:
        con.close()


def _j(v):
    return json.dumps(v, sort_keys=True, default=str)


def create_run(norm, resolved, pl, checks, base, operator=""):
    rid = time.strftime("%Y%m%d-%H%M%S") + "-" + _uuid.uuid4().hex[:6]
    now = time.time()
    with _LOCK:
        con = _con()
        try:
            con.execute("INSERT INTO scan_runs(run_id, created, updated, state, request_json, request_sha256, "
                        "resolved_json, plan_json, plan_sha256, preflight_json, baseline_json, operator) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (rid, now, now, "PLANNED", _j(norm), norm["request_sha256"], _j(resolved), _j(pl),
                         pl["plan_sha256"], _j(checks), _j({f"{u}|{p}": v for (u, p), v in base.items()}), operator))
            for s in pl["scans"]:
                con.execute("INSERT INTO scan_run_scans(run_id, plan_index, status, reuse_key, plugins, targets) "
                            "VALUES (?,?,?,?,?,?)", (rid, s["plan_index"], "planned", s["reuse_key"],
                                                     _j(s["plugins"]), len(s["targets"])))
            con.commit()
        finally:
            con.close()
    event(rid, "planned", {"request_sha256": norm["request_sha256"], "plan_sha256": pl["plan_sha256"],
                           "scans": len(pl["scans"]), "targets": len(resolved.get("targets") or [])})
    return rid


def set_state(run_id, state, **kw):
    if state not in STATES:
        raise ValueError(state)
    with _LOCK:
        con = _con()
        try:
            sets = ["state=?", "updated=?"]
            vals = [state, time.time()]
            for k, v in kw.items():
                if k in ("job_id", "log", "note", "summary_json", "preflight_json"):
                    sets.append(f"{k}=?")
                    vals.append(v if not isinstance(v, (dict, list)) else _j(v))
            con.execute(f"UPDATE scan_runs SET {', '.join(sets)} WHERE run_id=?", vals + [run_id])
            con.commit()
        finally:
            con.close()
    event(run_id, "state", {"state": state, **{k: v for k, v in kw.items() if k in ("note",)}})


def set_scan(run_id, plan_index, **kw):
    allowed = ("scan_id", "history_id", "history_uuid", "time_start", "status", "launched", "ended", "deleted", "note")
    with _LOCK:
        con = _con()
        try:
            sets = [f"{k}=?" for k in kw if k in allowed]
            if sets:
                con.execute(f"UPDATE scan_run_scans SET {', '.join(sets)} WHERE run_id=? AND plan_index=?",
                            [kw[k] for k in kw if k in allowed] + [run_id, plan_index])
                con.commit()
        finally:
            con.close()


def get_run(run_id):
    con = _con()
    try:
        r = con.execute("SELECT * FROM scan_runs WHERE run_id=?", (str(run_id or ""),)).fetchone()
        if not r:
            return None
        run = dict(r)
        for k in ("request_json", "resolved_json", "plan_json", "preflight_json", "baseline_json", "summary_json"):
            try:
                run[k[:-5]] = json.loads(run.pop(k) or "null")
            except ValueError:
                run[k[:-5]] = None
        run["scans"] = [dict(x) for x in con.execute(
            "SELECT * FROM scan_run_scans WHERE run_id=? ORDER BY plan_index", (run_id,))]
        return run
    finally:
        con.close()


def list_runs(limit=30):
    con = _con()
    try:
        out = []
        for r in con.execute("SELECT run_id, created, updated, state, request_json, job_id, summary_json "
                             "FROM scan_runs ORDER BY created DESC LIMIT ?", (int(limit),)):
            req = json.loads(r["request_json"] or "{}")
            out.append({"run_id": r["run_id"], "created": r["created"], "updated": r["updated"], "state": r["state"],
                        "plugins": req.get("plugins"), "selector": next(iter(req.get("assets") or {}), None),
                        "job_id": r["job_id"], "summary": json.loads(r["summary_json"] or "null")})
        return out
    finally:
        con.close()


def active_same(request_sha256, exclude=None):
    con = _con()
    try:
        rows = con.execute("SELECT run_id, state FROM scan_runs WHERE request_sha256=?", (request_sha256,)).fetchall()
        return any(r["state"] not in TERMINAL_STATES and r["state"] != "PLANNED" and r["run_id"] != exclude
                   for r in rows)
    finally:
        con.close()


def nonterminal_runs():
    con = _con()
    try:
        return [r["run_id"] for r in con.execute(
            "SELECT run_id FROM scan_runs WHERE state IN ('PREFLIGHT','LAUNCHING','RUNNING','SCANS_DONE','SYNCING')")]
    finally:
        con.close()


def reusable_scan(key):
    con = _con()
    try:
        r = con.execute("SELECT scan_id FROM scan_run_scans WHERE reuse_key=? AND scan_id IS NOT NULL AND deleted IS NULL "
                        "AND status IN ('completed') ORDER BY launched DESC LIMIT 1", (key,)).fetchone()
        return r["scan_id"] if r else None
    finally:
        con.close()


def save_verdicts(run_id, rows):
    with _LOCK:
        con = _con()
        try:
            con.execute("DELETE FROM scan_run_verdicts WHERE run_id=?", (run_id,))
            con.executemany("INSERT INTO scan_run_verdicts VALUES (?,?,?,?,?,?,?)",
                            [(run_id, r["asset_uuid"], r["plugin_id"], r.get("target"), r["verdict"], r["rule"],
                              _j(r.get("evidence") or {})) for r in rows])
            con.commit()
        finally:
            con.close()


def verdict_rows(run_id, verdict_filter=None, offset=0, limit=50):
    con = _con()
    try:
        w, args = "run_id=?", [run_id]
        if verdict_filter:
            w += " AND verdict=?"
            args.append(verdict_filter)
        total = con.execute(f"SELECT COUNT(*) FROM scan_run_verdicts WHERE {w}", args).fetchone()[0]
        counts = {r["verdict"]: r["n"] for r in con.execute(
            "SELECT verdict, COUNT(*) AS n FROM scan_run_verdicts WHERE run_id=? GROUP BY verdict", (run_id,))}
        rows = []
        for r in con.execute(f"SELECT * FROM scan_run_verdicts WHERE {w} ORDER BY verdict, target, plugin_id, asset_uuid "
                             f"LIMIT ? OFFSET ?", args + [int(limit), int(offset)]):
            d = dict(r)
            d["evidence"] = json.loads(d.pop("evidence_json") or "{}")
            rows.append(d)
        return {"rows": rows, "total": total, "counts": counts}
    finally:
        con.close()


def events(run_id, limit=200):
    con = _con()
    try:
        return [dict(r) for r in con.execute("SELECT id, ts, kind, detail FROM scan_run_events WHERE run_id=? "
                                             "ORDER BY id DESC LIMIT ?", (run_id, int(limit)))][::-1]
    finally:
        con.close()


# ══ feature detection (Phase 0 — cached per navi binary + mtime) ═════════════════════════
_FEAT = {}


def features(runner=None):
    """{multi_plugin, name, no_launch} from `navi scan create --help`. Never fatal."""
    navi = navi_cli._resolve_navi() or ""
    try:
        key = (navi, os.path.getmtime(navi)) if navi else ("", 0)
    except OSError:
        key = (navi, 0)
    if runner is None and key in _FEAT:
        return _feat_override(_FEAT[key])
    f = {"multi_plugin": False, "name": False, "no_launch": False, "help": ""}
    try:
        run = runner or _run_capture
        r = run(["scan", "create", "--help"], 30)
        txt = r.get("text") or ""
        f["help"] = txt[:2000]
        m = re.search(r"--plugin\b[^\n]*(?:\n\s{8,}[^\n]*)*", txt)
        seg = m.group(0).lower() if m else ""
        f["multi_plugin"] = bool(m) and ("multiple" in seg or "repeat" in seg or "one or more" in seg)
        f["name"] = bool(re.search(r"--name\b", txt))
        f["no_launch"] = bool(re.search(r"--no-launch\b", txt))
    except Exception as _e:
        _swallowed(_e)
    if runner is None:
        _FEAT[key] = f                        # an injected runner (tests) never fills the cache
    return _feat_override(f)


def _feat_override(f):
    """NAVI_SCAN_MULTI_PLUGIN=1: the operator vouches that this navi takes repeated --plugin flags into ONE
    scan (detection reads `--plugin`'s help for 'multiple' / 'repeat' / 'one or more'). =0 forces one plugin per scan."""
    v = os.environ.get("NAVI_SCAN_MULTI_PLUGIN")
    if v is None or str(v).strip() == "":
        return f
    return dict(f, multi_plugin=navi_cli._truthy(v), multi_source="NAVI_SCAN_MULTI_PLUGIN")


def _run_capture(sub_argv, timeout):
    """A short navi read with captured output (stdin /dev/null)."""
    import subprocess
    navi = navi_cli._resolve_navi()
    if not navi:
        return {"rc": 127, "text": ""}
    try:
        p = subprocess.run([navi] + list(sub_argv), cwd=navi_cli._navi_cwd(), capture_output=True, text=True,
                           timeout=timeout, stdin=subprocess.DEVNULL)
        return {"rc": p.returncode, "text": (p.stdout or "") + (p.stderr or "")}
    except Exception as e:
        return {"rc": 1, "text": str(e)}


def api_read(path_, runner=None, timeout=STATUS_TIMEOUT_S):
    """A Tenable read through `navi explore api <path> -raw` → parsed value or None (F10)."""
    r = (runner or _run_capture)(build_api_argv(path_), timeout)
    return parse_raw(r.get("text"))


_LOOKUP = {"t": 0, "v": None}


def lookups(force=False, runner=None):
    """Scanners, managed credentials, saved policies and existing scans from Tenable (5-minute cache) — for the
    pickers and P3 / P5 / P12 / P13. Scans: the most recent MAX_SCAN_LIST by last modification."""
    if not force and _LOOKUP["v"] and time.time() - _LOOKUP["t"] < 300:
        return _LOOKUP["v"]
    sc = api_read("/scanners", runner)
    cr = api_read("/credentials", runner)
    scanners = None if sc is None else [
        {"id": str(s.get("id") or ""), "uuid": s.get("uuid"), "name": s.get("name"), "status": s.get("status"),
         "type": s.get("type")} for s in (sc.get("scanners") if isinstance(sc, dict) else sc) or [] if isinstance(s, dict)]
    creds = None if cr is None else [
        {"uuid": str(c.get("uuid") or c.get("id") or "").lower(), "name": c.get("name"),
         "type": (c.get("type") or {}).get("name") if isinstance(c.get("type"), dict) else c.get("type"),
         "category": (c.get("category") or {}).get("name") if isinstance(c.get("category"), dict) else c.get("category")}
        for c in (cr.get("credentials") if isinstance(cr, dict) else cr) or [] if isinstance(c, dict)]
    po = api_read("/policies", runner)
    policies = None if po is None else sorted([
        {"id": str(x.get("id") or ""), "name": x.get("name"), "description": x.get("description"),
         "template_uuid": x.get("template_uuid")}
        for x in (po.get("policies") if isinstance(po, dict) else po) or [] if isinstance(x, dict)],
        key=lambda x: str(x.get("name") or "").lower())
    # the data behind `navi explore info scans` (name, id, status, uuid) — plus each scan's policy_id
    sl = api_read("/scans", runner, timeout=LIST_TIMEOUT_S)
    raw = (sl.get("scans") if isinstance(sl, dict) else sl) or [] if sl is not None else None
    scans = None if raw is None else [
        {"id": str(x.get("id") or ""), "name": x.get("name"), "status": x.get("status"), "uuid": x.get("uuid"),
         "policy_id": (str(x["policy_id"]) if x.get("policy_id") not in (None, "") else None), "type": x.get("type"),
         "enabled": bool(x.get("enabled")), "modified": x.get("last_modification_date") or 0}
        for x in sorted([y for y in raw if isinstance(y, dict)],
                        key=lambda y: (not y.get("enabled"), -(y.get("last_modification_date") or 0)))
        [:MAX_SCAN_LIST]]
    v = {"scanners": scanners, "credentials": creds, "policies": policies, "scans": scans,
         "scans_total": None if raw is None else len(raw), "at": time.time()}
    if scanners is not None or creds is not None:
        _LOOKUP.update(t=time.time(), v=v)
    return v


def plugins_known(plugins, path=None):
    try:
        if not db.query("SELECT 1 FROM plugins LIMIT 1", path=path):
            return None
        rows = db.query(f"SELECT plugin_id FROM plugins WHERE plugin_id IN ({','.join('?' * len(plugins))})",
                        tuple(str(p) for p in plugins), path=path) if plugins else []
        return {int(r["plugin_id"]) for r in rows}
    except Exception:
        return None


# ══ verdict computation (reads navi.db after the sync) ═══════════════════════════════════
def _in_chunks(path, sql_head, col, keys, tail="", params=()):
    keys = list(keys)
    for i in range(0, len(keys), 500):
        part = keys[i:i + 500]
        yield from db.query(f"{sql_head} WHERE {col} IN ({','.join('?' * len(part))}){tail}",
                            tuple(part) + tuple(params), path=path)


def _proof_rows(assets, path=None):
    """{asset: [{plugin_id, state, t (epoch), cred_yes}]} for the scan-information / credential
    plugins — cred_yes is computed in SQL (19506 output LIKE), the output itself is never read."""
    vcols = _cols("vulns", path)
    if not vcols or not assets:
        return {}
    pids = ",".join("'%s'" % p for p in credstate.SCANNED_PLUGINS + LOCAL_OK_PLUGINS + LOCAL_FAIL_PLUGINS)
    st = "state" if "state" in vcols else "'open' AS state"
    yes = ("(plugin_id='19506' AND output LIKE '%Credentialed checks : yes%')" if "output" in vcols else "0")
    out = {}
    for r in _in_chunks(path, f"SELECT asset_uuid, plugin_id, {st}, last_found, {yes} AS cred_yes FROM vulns",
                        "asset_uuid", sorted(assets), f" AND plugin_id IN ({pids})"):
        out.setdefault(str(r.get("asset_uuid") or "").lower(), []).append(
            {"plugin_id": str(r.get("plugin_id")), "state": str(r.get("state") or "open").lower(),
             "t": to_epoch(r.get("last_found")), "cred_yes": bool(r.get("cred_yes"))})
    return out


def _fixed_dates(assets, plugins, path=None):
    """{(asset, plugin): epoch} from the `fixed` table's last_fixed (when navi keeps one)."""
    fc = _cols("fixed", path)
    if not {"asset_uuid", "plugin_id", "last_fixed"} <= fc or not plugins:
        return {}
    want, out = set(assets), {}
    for r in db.query(f"SELECT asset_uuid, plugin_id, last_fixed FROM fixed WHERE plugin_id IN "
                      f"({','.join('?' * len(plugins))})", tuple(str(p) for p in plugins), path=path):
        u = str(r.get("asset_uuid") or "").lower()
        if u in want:
            t = to_epoch(r.get("last_fixed"))
            k = (u, int(r["plugin_id"]))
            if t is not None and t > (out.get(k) or 0):
                out[k] = t
    return out


def auth_fact(proof, t0, row_changed):
    """(auth_ok True|False|None, auth_evidence this_run|prior_scan|none) — credstate's rules,
    this run's rows first. A local-check row that changed in this run is itself proof of login."""
    if row_changed:
        return True, "this_run"
    now = [x for x in proof if x["t"] is not None and t0 is not None and x["t"] >= t0 - 1]
    if any(x["plugin_id"] in credstate.CRED_OK_PLUGINS + LOCAL_OK_PLUGINS or x["cred_yes"] for x in now):
        return True, "this_run"
    if any(x["plugin_id"] in credstate.FAIL_PLUGINS or x["plugin_id"] in credstate.NOCRED_PLUGINS
           or x["plugin_id"] in LOCAL_FAIL_PLUGINS or x["plugin_id"] == credstate.SCAN_INFO for x in now):
        return False, "this_run"                  # scanned this run, and nothing says it logged in
    if any(x["plugin_id"] in credstate.CRED_OK_PLUGINS + LOCAL_OK_PLUGINS or x["cred_yes"] for x in proof):
        return True, "prior_scan"
    if any(x["plugin_id"] == credstate.SCAN_INFO for x in proof):
        return False, "prior_scan"
    return None, "none"


def compute_verdicts(run, hosts_by_scan=None, path=None):
    """Every (asset, plugin) of the run → {asset_uuid, plugin_id, target, verdict, rule, evidence}."""
    norm, resolved = run.get("request") or {}, run.get("resolved") or {}
    plugins = [int(p) for p in norm.get("plugins") or []]
    if not plugins or not norm.get("verify", True):
        return []
    scans = run.get("scans") or []
    pl_scans = {s["plan_index"]: s for s in (run.get("plan") or {}).get("scans") or []}
    idx = {}
    for s in scans:
        ps = pl_scans.get(s["plan_index"]) or {}
        for t in ps.get("targets") or []:
            for p in ps.get("plugins") or []:
                idx[(t, int(p))] = s
    amap = resolved.get("asset_map") or {}
    infos = resolved.get("assets") or {}
    assets = sorted({u for us in amap.values() for u in us})
    base = {}
    for k, v in (run.get("baseline") or {}).items():
        u, _, p = k.rpartition("|")
        base[(u, int(p))] = v
    now = baseline(assets, plugins, path)
    fixed = _fixed_dates(assets, plugins, path)
    proof = _proof_rows(assets, path)
    fams = plugin_families(plugins, path)
    hosts_by_scan = hosts_by_scan or {}
    rows = []
    seen = set()
    for t, us in amap.items():
        for u in us:
            info = infos.get(u) or {}
            for p in plugins:
                if (u, p) in seen:
                    continue
                seen.add((u, p))
                s = idx.get((t, p)) or {}
                t0 = to_epoch(s.get("time_start"))
                done = str(s.get("status") or "") in OK_TERMINAL and t0 is not None
                row = now.get((u, p))
                fd = fixed.get((u, p))
                if row is None and fd is not None and t0 is not None and fd >= t0 - 1:
                    row = {"state": "fixed", "last_found": None, "scan_uuid": None}
                lf = to_epoch((row or {}).get("last_found"))
                changed = bool(row) and t0 is not None and ((lf is not None and lf >= t0 - 1)
                                                            or (fd is not None and fd >= t0 - 1))
                pr = proof.get(u) or []
                ingested = changed or any(x["t"] is not None and x["t"] >= t0 - 1 for x in pr) if t0 else False
                hs = hosts_by_scan.get(str(s.get("scan_id") or ""))
                if hs is None:
                    seen_host = ingested            # the scan's host list couldn't be read
                else:
                    keys = {t.lower(), str(info.get("ip") or "").lower(), str(info.get("host") or "").lower()} - {""}
                    seen_host = bool(keys & hs)
                local = is_local(fams.get(p))
                auth_ok, auth_ev = auth_fact(pr, t0, changed and local)
                fact = {"excluded": False, "scan_completed": done, "host_seen": seen_host, "local": local,
                        "auth_ok": auth_ok if local else True, "ingested": ingested, "time_start": t0, "fixed_date": fd}
                v, rule = verdict(base.get((u, p)), fact, row)
                rows.append({"asset_uuid": u, "plugin_id": p, "target": t, "verdict": v, "rule": rule, "evidence": {
                    "scan_id": s.get("scan_id"), "history_id": s.get("history_id"), "time_start": s.get("time_start"),
                    "scan_status": s.get("status"), "baseline": base.get((u, p)) or "absent",
                    "row": row or "absent", "fixed_date": fd, "auth_evidence": auth_ev if local else "n/a",
                    "local_check": local, "host_seen": seen_host, "ingested": ingested,
                    "host": info.get("host") or "", "ip": info.get("ip") or ""}})
    for e in resolved.get("excluded") or []:
        u = e.get("asset") or ""
        for p in plugins:
            if (u, p) not in seen:
                seen.add((u, p))
                rows.append({"asset_uuid": u, "plugin_id": p, "target": None, "verdict": "NOT_ASSESSED", "rule": "R1",
                             "evidence": {"excluded": e.get("reason")}})
    for t in resolved.get("targets") or []:
        if t not in amap:
            for p in plugins:
                rows.append({"asset_uuid": "target:" + t, "plugin_id": p, "target": t, "verdict": "NOT_ASSESSED",
                             "rule": "R1", "evidence": {"excluded": "not_in_navi_db",
                                                        "hint": "no navi.db asset for this target yet — sync assets, "
                                                                "then ↻ Re-verify"}})
    return rows


def summarize(rows):
    c = {v: 0 for v in VERDICTS}
    for r in rows:
        c[r["verdict"]] = c.get(r["verdict"], 0) + 1
    return {"pairs": len(rows), "counts": c}


# ══ the runner (one cli_jobs task per run) ═══════════════════════════════════════════════
LAUNCH_POLL_S = 5
_ACTIVE = {}                                   # run_id → threading.Event (cancel)
_RUN_LOCK = threading.Lock()


def _navi(ev, emit, live, cred):
    from core import cli_jobs
    msk = lambda l: mask_line(l, (cred,))

    def nv(argv, timeout, quiet=False):
        if not quiet:
            emit("$ navi " + " ".join(mask_argv(argv, cred)))
        # quiet = a read (explore api / status): parsed here, never shown or logged, so not masked
        return cli_jobs.run_navi_streamed(argv, (lambda _l: None) if quiet else emit, None if quiet else live,
                                          ev, timeout, None if quiet else msk)

    def read(path_):
        r = nv(build_api_argv(path_), STATUS_TIMEOUT_S, quiet=True)
        return parse_raw("\n".join(r.get("lines") or []))
    return nv, read


def _hdr(emit, i, n, text):
    emit("")
    emit(("── [%d/%d] %s " % (i, n, text)).ljust(72, "─"))


def _latest_history(raw):
    hs = history_entries(raw)
    if not hs:
        return None
    return max(hs, key=lambda e: (to_epoch(e.get("time_start")) or 0, int(_hid(e)) if _hid(e).isdigit() else 0))


def _scan_hosts(read, scan_id, history_id):
    if not scan_id:
        return None
    raw = read("/scans/%s" % scan_id + ("?history_id=%s" % history_id if history_id else ""))
    if not isinstance(raw, dict) or not isinstance(raw.get("hosts"), list):
        return None
    out = set()
    for h in raw["hosts"]:
        if isinstance(h, dict):
            for k in ("hostname", "host_ip", "host_fqdn", "ip"):
                if h.get(k):
                    out.add(str(h[k]).lower())
    return out


def _status_of(read, nv, scan_id):
    raw = read("/scans/%s/latest-status" % scan_id)
    if isinstance(raw, dict) and raw.get("status"):
        return norm_status(raw["status"])
    r = nv(build_control_argv("status", scan_id), STATUS_TIMEOUT_S, quiet=True)
    return norm_status(parse_status_line("\n".join(r.get("lines") or [])))


def _stop_running(run_id, nv, read, emit):
    run = get_run(run_id)
    for s in run["scans"]:
        if s.get("scan_id") and str(s.get("status") or "") not in TERMINAL:
            nv(build_control_argv("stop", s["scan_id"]), STATUS_TIMEOUT_S)
            st = _status_of(read, nv, s["scan_id"]) or "unknown"
            set_scan(run_id, s["plan_index"], status=st, note="stop issued (abort)")
            event(run_id, "stop", {"scan_id": s["scan_id"], "status_after": st})
            emit("■ scan %s → %s" % (s["scan_id"], st))


def _finish_verdicts(run_id, read, emit, final_state, note=None):
    run = get_run(run_id)
    hosts = {}
    for s in run["scans"]:
        if s.get("scan_id") and s.get("status") in OK_TERMINAL:
            hosts[str(s["scan_id"])] = _scan_hosts(read, s["scan_id"], s.get("history_id"))
    rows = compute_verdicts(run, hosts)
    save_verdicts(run_id, rows)
    summ = summarize(rows)
    set_state(run_id, final_state, summary_json=summ, **({"note": note} if note else {}))
    event(run_id, "verdicts", summ["counts"])
    return rows, summ


def execute(run_id, emit, live, ev, resume=False):
    """The state machine. Launched scans are never relaunched (resume=True skips creation)."""
    run = get_run(run_id)
    norm, pl = run["request"], run["plan"]
    cred = norm.get("credential_uuid")
    nv, read = _navi(ev, emit, live, cred)
    verify = bool(norm.get("plugins")) and norm.get("verify", True)
    n_steps = 4 if verify else 2
    started = time.time()
    try:
        # ── LAUNCHING ──
        if not resume:
            set_state(run_id, "LAUNCHING")
        rows = {s["plan_index"]: s for s in run["scans"]}
        total = len(pl["scans"])
        for ps in pl["scans"]:
            i = ps["plan_index"]
            if rows.get(i, {}).get("scan_id"):
                continue
            if ev.is_set():
                break
            if resume:
                set_scan(run_id, i, status="not_launched", note="not launched before the server restarted")
                continue
            if ps.get("rerun"):
                _hdr(emit, 1, n_steps, "RE-RUN scan %s" % ps["rerun"])
            else:
                _hdr(emit, 1, n_steps, "LAUNCH scan %d/%d · %s · %d target(s)"
                     % (i + 1, total, ("plugin " + ",".join(str(p) for p in ps["plugins"])) if ps["plugins"]
                        else "policy %s" % norm.get("policy_id"), len(ps["targets"])))
            rerun = ps.get("rerun")
            sid = rerun or (reusable_scan(ps["reuse_key"]) if norm.get("reuse") else None)
            before_raw = read("/scans/%s/history" % sid) if sid else None
            if rerun and before_raw is None:
                set_scan(run_id, i, scan_id=sid, status="launch_failed", note="scan can't be read in Tenable")
                emit("✗ scan %s can't be read in Tenable — not started" % sid)
                continue
            if sid and before_raw is None:
                emit("· scan %s can't be read any more (deleted in Tenable?) — creating a new one" % sid)
                sid = None
            if sid:
                ids = {_hid(e) for e in history_entries(before_raw)}
                emit(("▶ re-running scan %s on its own targets" % sid) if rerun else
                     "↺ reusing scan %s (identical targets, plugins, scanner, credential)" % sid)
                nv(build_control_argv("start", sid), CREATE_TIMEOUT_S)
                entry, until = None, time.time() + LAUNCH_PROOF_S
                while time.time() < until and not ev.is_set():
                    new = [e for e in history_entries(read("/scans/%s/history" % sid)) if _hid(e) not in ids]
                    if new:
                        entry = _latest_history({"history": new})
                        break
                    ev.wait(LAUNCH_POLL_S)
                if not entry:
                    set_scan(run_id, i, scan_id=sid, status="launch_failed",
                             note="start exited without a new run in the scan history (F7)")
                    event(run_id, "launch_failed", {"plan_index": i, "scan_id": sid, "why": "no new history id"})
                    emit("✗ scan %s did not start — navi exits 0 even when the start fails (F7)" % sid)
                    continue
            else:
                if not ps.get("argv"):
                    set_scan(run_id, i, status="launch_failed", note="no argv (no scanner)")
                    continue
                r = nv(ps["argv"], CREATE_TIMEOUT_S)
                sid, warn = parse_scan_id("\n".join(r.get("lines") or []))
                if warn and sid:
                    emit("⚠ " + warn)
                if not sid:
                    why = "timed out" if r.get("timed_out") else ("cancelled" if r.get("cancelled") else (warn or "no scan id"))
                    set_scan(run_id, i, status="launch_failed", note=why)
                    event(run_id, "launch_failed", {"plan_index": i, "why": why})
                    emit("✗ launch failed — %s" % why)
                    continue
                set_scan(run_id, i, scan_id=sid, status="launched", launched=time.time())
                entry, until = None, time.time() + LAUNCH_PROOF_S
                while time.time() < until and not ev.is_set():
                    entry = _latest_history(read("/scans/%s/history" % sid))
                    if entry:
                        break
                    ev.wait(LAUNCH_POLL_S)
            if entry:
                set_scan(run_id, i, scan_id=sid, history_id=_hid(entry), history_uuid=entry.get("uuid"),
                         time_start=to_epoch(entry.get("time_start")), status=norm_status(entry.get("status")) or "running",
                         launched=time.time())
                emit("✓ scan_id=%s history_id=%s time_start=%s" % (sid, _hid(entry), entry.get("time_start")))
                event(run_id, "launched", {"plan_index": i, "scan_id": sid, "history_id": _hid(entry)})
            else:
                emit("… scan %s created; its run hasn't appeared in the history yet — polling continues" % sid)
                event(run_id, "launched", {"plan_index": i, "scan_id": sid, "history_id": None})
        run = get_run(run_id)
        live_scans = [s for s in run["scans"] if s.get("scan_id") and s.get("status") != "launch_failed"]
        if ev.is_set():
            raise _Abort()
        if not live_scans:
            emit("✗ no scan launched")
            _finish_verdicts(run_id, read, emit, "LAUNCH_FAILED", note="no scan launched")
            return {"ok": False}
        # ── RUNNING ──
        set_state(run_id, "RUNNING")
        _hdr(emit, 2, n_steps, "WAIT for %d scan(s)" % len(live_scans))
        deadline = (min(s.get("launched") or started for s in live_scans) if resume else started) \
            + int(norm.get("timeout_min") or TIMEOUT_MIN_DEFAULT) * 60
        interval = POLL_FIRST_S
        while True:
            if ev.is_set():
                raise _Abort()
            run = get_run(run_id)
            pend = [s for s in run["scans"] if s.get("scan_id") and s.get("status") not in TERMINAL
                    and s.get("status") not in ("launch_failed", "not_launched", "timeout")]
            for s in pend:
                st = _status_of(read, nv, s["scan_id"])
                if not s.get("history_id"):
                    e = _latest_history(read("/scans/%s/history" % s["scan_id"]))
                    if e:
                        set_scan(run_id, s["plan_index"], history_id=_hid(e), history_uuid=e.get("uuid"),
                                 time_start=to_epoch(e.get("time_start")))
                if st and st != s.get("status"):
                    if st not in TERMINAL and st not in ("running", "pending", "processing", "initializing",
                                                         "publishing", "paused", "pausing", "resuming", "stopping",
                                                         "launched", "queued"):
                        emit("? scan %s reports an unknown status %r — treated as still running" % (s["scan_id"], st))
                    else:
                        emit("· scan %s: %s" % (s["scan_id"], st))
                    set_scan(run_id, s["plan_index"], status=st, **({"ended": time.time()} if st in TERMINAL else {}))
                    event(run_id, "status", {"scan_id": s["scan_id"], "status": st})
            run = get_run(run_id)
            pend = [s for s in run["scans"] if s.get("scan_id") and s.get("status") not in TERMINAL
                    and s.get("status") not in ("launch_failed", "not_launched", "timeout")]
            if not pend:
                break
            if time.time() > deadline:
                for s in pend:
                    set_scan(run_id, s["plan_index"], status="timeout", note="still running at the run timeout")
                emit("⏱ run timeout (%s min) — %d scan(s) still running are left as they are"
                     % (norm.get("timeout_min"), len(pend)))
                break
            live("waiting · %d scan(s) running · next check in %ds" % (len(pend), int(interval)))
            ev.wait(interval)
            interval = min(POLL_MAX_S, interval * POLL_BACKOFF)
        live("")
        set_state(run_id, "SCANS_DONE")
        run = get_run(run_id)
        done = [s for s in run["scans"] if s.get("status") in OK_TERMINAL and s.get("time_start")]
        if not verify:
            set_state(run_id, "VERIFIED", summary_json={"scan_now": True, "completed": len(done)})
            emit("✓ one-off scan finished — %d scan(s) completed (no navi.db sync, no verdicts — run a sync in "
                 "Settings when you want the results in navi.db)" % len(done))
            return {"ok": True}
        if not done:
            emit("✗ no scan completed — nothing to verify")
            _finish_verdicts(run_id, read, emit, "VERIFIED", note="no scan completed")
            return {"ok": True}
        return sync_and_verify(run_id, emit, live, ev, nv, read, n_steps)
    except _Abort:
        emit("")
        emit("■ cancelled — stopping every scan still running")
        nv2, read2 = _navi(threading.Event(), emit, live, cred)    # the cancel event would kill these too
        _stop_running(run_id, nv2, read2, emit)
        _finish_verdicts(run_id, read2, emit, "ABORTED", note="cancelled by the operator")
        return {"cancelled": True}
    finally:
        with _RUN_LOCK:
            _ACTIVE.pop(run_id, None)
        live("")


class _Abort(Exception):
    pass


def sync_args(norm, plugin, mode, since=None, threads=None):
    a = ["config", "update", "vulns", "--plugin_id", str(int(plugin))]
    if mode == "since":
        a += ["--state", "open", "--state", "reopened", "--state", "fixed", "--since", str(int(since))]
    else:
        a += ["--days", "1"]
    t = (norm.get("assets") or {}).get("tag")
    if t:
        a += ["--c", t["category"], "--v", t["value"]]
    if threads:
        a += ["--threads", str(int(threads))]
    return a


def sync_and_verify(run_id, emit, live, ev, nv=None, read=None, n_steps=4):
    run = get_run(run_id)
    norm = run["request"]
    if nv is None:
        nv, read = _navi(ev, emit, live, norm.get("credential_uuid"))
    done = [s for s in run["scans"] if s.get("status") in OK_TERMINAL and s.get("time_start")]
    since = int(min(float(s["time_start"]) for s in done)) if done else int(time.time() - 86400)
    plugins = [int(p) for p in norm.get("plugins") or []]
    multi = (run.get("plan") or {}).get("multi_plugin")
    local = any(is_local(f) for f in plugin_families(plugins).values())
    proof = [int(credstate.SCAN_INFO)] + ([p for p in PROOF_PLUGINS if p != int(credstate.SCAN_INFO)] if multi
                                          else ([int(p) for p in LOCAL_OK_PLUGINS + LOCAL_FAIL_PLUGINS] if local else []))
    attempts = int(norm.get("sync_attempts") or SYNC_ATTEMPTS_DEFAULT)
    set_state(run_id, "SYNCING")
    summ = None
    for a in range(1, attempts + 1):
        _hdr(emit, n_steps - 1, n_steps, "SYNC attempt %d/%d · %d plugin(s) since %d" % (a, attempts, len(plugins), since))
        for p in plugins + [x for x in proof if x not in plugins]:
            for mode in (("since", "days") if p in plugins else ("since",)):
                if ev.is_set():
                    raise _Abort()
                r = nv(sync_args(norm, p, mode, since), SYNC_TIMEOUT_S)
                if r.get("timed_out") and not ev.is_set():
                    # no slower retry: the next sync attempt (or ↻ Re-verify) picks it up again
                    emit("⏱ sync of plugin %s (%s) ran past %d min — continuing; the next attempt retries it"
                         % (p, mode, SYNC_TIMEOUT_S // 60))
                    event(run_id, "sync_timeout", {"plugin": p, "mode": mode})
        _hdr(emit, n_steps, n_steps, "VERIFY (%d/%d)" % (a, attempts))
        rows, summ = _finish_verdicts(run_id, read, emit, "SYNCING")
        pend = summ["counts"].get("PENDING_INGESTION", 0)
        unk = summ["counts"].get("UNCHANGED_UNKNOWN", 0)
        emit("  " + " · ".join("%s %d" % (k.replace("_", " ").lower(), v) for k, v in summ["counts"].items() if v))
        if not (pend or unk) or a == attempts:
            break
        # Tenable can take a while to flip a finding to fixed — keep checking while results are unknown
        emit("… %s — next sync in %ds" % (" · ".join(x for x in (
            ("%d pair(s) not in navi.db yet" % pend) if pend else "",
            ("%d pair(s) without a decision yet (Tenable may still be updating the findings)" % unk) if unk else "") if x),
            int(norm.get("sync_interval_s") or 300)))
        if ev.wait(int(norm.get("sync_interval_s") or SYNC_INTERVAL_DEFAULT)):
            raise _Abort()
    set_state(run_id, "VERIFIED", summary_json=summ)
    c = (summ or {}).get("counts") or {}
    decided = sum(v for k, v in c.items() if k in ("CONFIRMED_FIXED", "STILL_VULNERABLE", "NOT_VULNERABLE", "NEWLY_FOUND"))
    emit(("✓ done — %d of %d pair(s) decided" % (decided, (summ or {}).get("pairs", 0))) if decided
         else "⚠ done — no verdict yet for %d pair(s); ↻ Re-verify later" % (summ or {}).get("pairs", 0))
    return {"ok": True}


def start(run_id, resume=False, label=None, fn=None):
    """Start the run's task (the one live CLI window). Idempotent: an active run returns its job."""
    from core import cli_jobs
    with _RUN_LOCK:
        if run_id in _ACTIVE:
            run = get_run(run_id)
            return {"ok": True, "already": True, "job_id": run.get("job_id")}
        _ACTIVE[run_id] = None

    def body(emit, live, ev):
        with _RUN_LOCK:
            _ACTIVE[run_id] = ev
        return (fn or execute)(run_id, emit, live, ev, **({} if fn else {"resume": resume}))
    try:
        res = cli_jobs.start_task(label or ("Scan Confirmation · %s" % run_id), "scan_confirm", body,
                                  cmd="scan_confirm " + ("resume " if resume else "") + run_id)
    except Exception:
        with _RUN_LOCK:
            _ACTIVE.pop(run_id, None)
        raise
    jid = (res.get("job") or {}).get("id")
    set_job(run_id, jid)                       # the job id only — never write the state back (the worker owns it)
    return {"ok": True, "job_id": jid}


def set_job(run_id, job_id):
    with _LOCK:
        con = _con()
        try:
            con.execute("UPDATE scan_runs SET job_id=?, updated=? WHERE run_id=?", (job_id, time.time(), run_id))
            con.commit()
        finally:
            con.close()
    event(run_id, "job", {"job_id": job_id})


def is_active(run_id):
    with _RUN_LOCK:
        return run_id in _ACTIVE


def cancel(run_id):
    from core import cli_jobs
    run = get_run(run_id)
    if not run:
        return {"ok": False, "error": "no such run"}
    if run.get("job_id"):
        return cli_jobs.cancel(run["job_id"])
    return {"ok": False, "error": "this run has no live job"}


def deletable_scans(days, now=None):
    """Scans THIS agent created, older than `days`, not deleted yet (never any other scan — a re-run of an
    existing scan doesn't make it ours)."""
    cut = (now or time.time()) - int(days) * 86400
    con = _con()
    try:
        # a one-off RE-RUN started someone else's scan — never ours to delete
        theirs = set()
        for r in con.execute("SELECT request_json FROM scan_runs WHERE request_json LIKE '%rerun_scan_id%'"):
            try:
                v = (json.loads(r["request_json"] or "{}") or {}).get("rerun_scan_id")
            except ValueError:
                v = None
            if v:
                theirs.add(str(v))
        # one decision per SCAN, not per row: a reused scan appears on several runs' rows. It is deletable
        # only when EVERY row using it is old and finished, and no run using it is still going.
        return [dict(r) for r in con.execute(
            "SELECT s.scan_id, MIN(s.run_id) AS run_id, MAX(s.launched) AS launched FROM scan_run_scans s "
            "JOIN scan_runs r ON r.run_id = s.run_id "
            "WHERE s.scan_id IS NOT NULL AND s.deleted IS NULL "
            "GROUP BY s.scan_id "
            "HAVING MAX(COALESCE(s.launched, r.created)) < ? "
            "AND SUM(CASE WHEN s.status IN ('completed','canceled','cancelled','aborted','stopped','timeout',"
            "'launch_failed','not_launched') THEN 0 ELSE 1 END) = 0 "
            "AND SUM(CASE WHEN r.state IN ('REFUSED','LAUNCH_FAILED','VERIFIED','ABORTED') THEN 0 ELSE 1 END) = 0 "
            "ORDER BY MAX(s.launched)", (cut,)) if str(r["scan_id"]) not in theirs]
    finally:
        con.close()


def retention_days():
    try:
        return max(1, int(os.environ.get("NAVI_SCAN_RETENTION_DAYS") or 30))
    except ValueError:
        return 30


def refresh_resolved(run_id, resolved):
    """Re-verify: merge assets that appeared in navi.db since the plan (new targets' assets get an
    'absent' baseline — they had no row then)."""
    run = get_run(run_id)
    old = run.get("resolved") or {}
    amap = dict(old.get("asset_map") or {})
    infos = dict(old.get("assets") or {})
    added = 0
    for t, us in (resolved.get("asset_map") or {}).items():
        if t in (old.get("targets") or []) and t not in amap:
            amap[t] = us
            added += len(us)
            for u in us:
                infos[u] = (resolved.get("assets") or {}).get(u) or {}
    if not added:
        return 0
    new = dict(old, asset_map=dict(sorted(amap.items())), assets=infos)
    with _LOCK:
        con = _con()
        try:
            con.execute("UPDATE scan_runs SET resolved_json=?, updated=? WHERE run_id=?", (_j(new), time.time(), run_id))
            con.commit()
        finally:
            con.close()
    event(run_id, "resolved_refresh", {"assets_added": added})
    return added


def mark_deleted(scan_id):
    with _LOCK:
        con = _con()
        try:
            con.execute("UPDATE scan_run_scans SET deleted=? WHERE scan_id=? AND deleted IS NULL", (time.time(), str(scan_id)))
            con.commit()
        finally:
            con.close()


def scan_info(scan_id, runner=None):
    """One scan by id, even when it isn't in the picker list: GET /scans/<id> → {id, name, status,
    scanner_name, targets} (or None). The list's policy_id is added by the caller when it has it."""
    if not _DIGITS.match(str(scan_id or "")):
        return None
    raw = api_read("/scans/%s" % scan_id, runner, timeout=LIST_TIMEOUT_S)
    info = raw.get("info") if isinstance(raw, dict) else None
    if not isinstance(info, dict):
        return None
    return {"id": str(scan_id), "name": info.get("name"), "status": norm_status(info.get("status")),
            "scanner_name": info.get("scanner_name"), "targets": str(info.get("targets") or "")[:500],
            "policy_name": info.get("policy")}


def via_scan(scan_id, lk, runner=None):
    """'Send new hosts through scan N': its policy_id (from the scan list) + its scanner (by name) →
    {scan, policy_id, scanner_id, error}. navi's `scan start --targets` can't carry new targets (F8),
    so the new hosts get a NEW scan built from scan N's policy and scanner."""
    row = next((x for x in (lk.get("scans") or []) if x.get("id") == str(scan_id)), None)
    info = scan_info(scan_id, runner) or {}
    if not row and not info:
        return {"error": "scan #%s can't be read in Tenable" % scan_id}
    pol = (row or {}).get("policy_id")
    if not pol:
        return {"error": "Tenable didn't return a policy id for scan #%s — pick its policy by hand" % scan_id,
                "scan": dict(info, **(row or {}))}
    sname = info.get("scanner_name")
    sc_ = next((x for x in (lk.get("scanners") or []) if sname and x.get("name") == sname), None)
    return {"scan": dict(info, **(row or {})), "policy_id": pol, "scanner_id": (sc_ or {}).get("id"),
            "scanner_name": sname}



# ══ open findings — start a confirmation from what is open, not typed plugin IDs ═════════
_OPEN = "lower(COALESCE(state,'open')) IN ('open','reopened')"
FINDINGS_LIMIT = 100
OPEN_ASSETS_CAP = 5000                  # never more than ~5,000 asset UUIDs to the page


def _tag_cats(tag):
    from core import tagname
    return tagname.names(tag["category"]) or [tag["category"]]


def _tag_sub(tag):
    """(SQL subquery of the tagged assets, params) — hx_tags_kv covers (tag_key, tag_value, asset_uuid)."""
    cats = _tag_cats(tag)
    return ("SELECT asset_uuid FROM tags WHERE tag_key IN (%s) AND tag_value=?" % ",".join("?" * len(cats)),
            tuple(cats) + (tag["value"],))


def open_findings(by, q, tag=None, path=None):
    """Plugins with OPEN findings, for the 'start from open findings' search:
       by='cve'    q='CVE-2024-3400'      → plugins whose CVE list has it
       by='plugin' q='10863' or 'openssl' → that plugin id, or a name match
       by='tag'    (q empty) + tag         → the plugins open on the tagged assets
       tag (optional) scopes every search to the tagged assets.
    Reads the summary (hx_plugin) and the covering vulns indexes only — never a full scan of vulns.
    → {plugins: [{id, name, family, local, sev, open_assets}], scoped, truncated}"""
    q = str(q or "").strip()
    tag = tag if isinstance(tag, dict) and tag.get("category") and tag.get("value") else None
    hc = _cols("hx_plugin", path)
    use_hx = bool(hc)
    try:
        from core import hx_summary
        use_hx = use_hx and hx_summary.usable(path)
    except Exception:
        use_hx = False
    cand = []                                   # candidate plugin ids (strings)
    if by == "cve":
        m = re.match(r"^(?i:cve)-\d{4}-\d{4,7}$", q)
        if not m:
            raise ValueError("a CVE looks like CVE-2024-3400")
        pat = "%" + q.upper() + "%"
        if use_hx and "cves" in hc:
            cand = [str(r["plugin_id"]) for r in db.query("SELECT plugin_id FROM hx_plugin WHERE upper(cves) LIKE ? LIMIT 500",
                                                          (pat,), path=path)]
        elif "cves" in _cols("plugins", path):
            cand = [str(r["plugin_id"]) for r in db.query("SELECT plugin_id FROM plugins WHERE upper(cves) LIKE ? LIMIT 500",
                                                          (pat,), path=path)]
    elif by == "plugin":
        if re.match(r"^\d{1,7}$", q):
            cand = [q]
        elif len(q) >= 3:
            pat = "%" + q.lower() + "%"
            if use_hx and "lname" in hc:
                cand = [str(r["plugin_id"]) for r in db.query(
                    "SELECT plugin_id FROM hx_plugin WHERE lname LIKE ? ORDER BY open_assets DESC LIMIT 500", (pat,), path=path)]
            elif "name" in _cols("plugins", path):
                cand = [str(r["plugin_id"]) for r in db.query(
                    "SELECT plugin_id FROM plugins WHERE lower(name) LIKE ? LIMIT 500", (pat,), path=path)]
        else:
            raise ValueError("type a plugin ID, or at least 3 letters of its name")
    elif by == "tag":
        if not tag:
            raise ValueError("pick a tag category and value")
    else:
        raise ValueError("search by cve, plugin or tag")
    sev = "severity" if "severity" in _cols("vulns", path) else "''"
    counts = {}
    if by == "tag" and not cand:
        sub, sp = _tag_sub(tag)
        for r in db.query(f"SELECT plugin_id, COUNT(DISTINCT asset_uuid) AS n FROM vulns{db.indexed_by('hx_v_asset', path)} "
                          f"WHERE asset_uuid IN ({sub}) AND {_OPEN} AND lower(COALESCE({sev},'')) NOT IN ('info','0','none') "
                          f"GROUP BY plugin_id ORDER BY n DESC LIMIT {FINDINGS_LIMIT * 3}", sp, path=path):
            counts[str(r["plugin_id"])] = r["n"]
    elif cand:
        cand = cand[:500]
        args = tuple(cand)
        w = f"plugin_id IN ({','.join('?' * len(cand))}) AND {_OPEN}"
        if tag:
            sub, sp = _tag_sub(tag)
            w += f" AND asset_uuid IN ({sub})"
            args += sp
        for r in db.query(f"SELECT plugin_id, COUNT(DISTINCT asset_uuid) AS n FROM vulns{db.indexed_by('hx_v_plugin', path)} "
                          f"WHERE {w} GROUP BY plugin_id", args, path=path):
            counts[str(r["plugin_id"])] = r["n"]
    ids = sorted(counts, key=lambda k: -counts[k])
    names = plugin_names([int(i) for i in ids[:FINDINGS_LIMIT]], path)
    fams = plugin_families([int(i) for i in ids[:FINDINGS_LIMIT]], path)
    sevs = {}
    if use_hx and "sevn" in hc and ids:
        top = ids[:FINDINGS_LIMIT]
        for r in db.query(f"SELECT plugin_id, sevn FROM hx_plugin WHERE plugin_id IN ({','.join('?' * len(top))})",
                          tuple(top), path=path):
            sevs[str(r["plugin_id"])] = r.get("sevn")
    out = [{"id": int(i), "name": names.get(int(i)), "family": fams.get(int(i)), "local": is_local(fams.get(int(i))),
            "sev": sevs.get(i), "open_assets": counts[i]} for i in ids[:FINDINGS_LIMIT]]
    out.sort(key=lambda x: (-(x["sev"] or 0), -x["open_assets"]))
    return {"plugins": out, "scoped": bool(tag), "truncated": len(ids) > FINDINGS_LIMIT}


def open_assets(plugins, tag=None, path=None):
    """Asset UUIDs with an OPEN finding for any of `plugins` (optionally only tagged ones), capped."""
    plugins = [str(int(p)) for p in plugins or []][:MAX_PLUGINS]
    if not plugins:
        return {"uuids": [], "total": 0, "capped": False}
    tag = tag if isinstance(tag, dict) and tag.get("category") and tag.get("value") else None
    w = f"plugin_id IN ({','.join('?' * len(plugins))}) AND {_OPEN}"
    args = tuple(plugins)
    if tag:
        sub, sp = _tag_sub(tag)
        w += f" AND asset_uuid IN ({sub})"
        args += sp
    rows = db.query(f"SELECT DISTINCT asset_uuid FROM vulns{db.indexed_by('hx_v_plugin', path)} WHERE {w} "
                    f"LIMIT {OPEN_ASSETS_CAP + 1}", args, path=path)
    uu = sorted({str(r["asset_uuid"]).lower() for r in rows if r.get("asset_uuid")})
    return {"uuids": uu[:OPEN_ASSETS_CAP], "total": len(uu), "capped": len(uu) > OPEN_ASSETS_CAP}


def cred_suggestion(resolved, creds, path=None):
    """For local checks without a credential: the managed credential that fits most of the assets'
    OS family (Windows → a Windows credential, everything else → SSH). None when nothing fits."""
    if not creds:
        return None
    uu = list((resolved.get("assets") or {}).keys())[:5000]
    win = other = 0
    if uu and "operating_system" in _cols("assets", path):
        for r in _in_chunks(path, "SELECT operating_system AS os FROM assets", "uuid", uu):
            if "windows" in str(r.get("os") or "").lower():
                win += 1
            elif r.get("os"):
                other += 1
    want = "windows" if win > other else "ssh"
    fit = [c for c in creds if want in str(c.get("type") or "").lower()]
    pick = fit[0] if len(fit) >= 1 else (creds[0] if len(creds) == 1 else None)
    if not pick:
        return None
    return {"uuid": pick["uuid"], "name": pick.get("name"), "type": pick.get("type"),
            "why": ("%d of %d assets run Windows" % (win, win + other)) if want == "windows" and (win + other)
            else ("%d of %d assets aren't Windows" % (other, win + other)) if (win + other) else "the only managed credential"}
