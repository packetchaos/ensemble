"""Exposure Routes — owner-mapping agent (Atlas).

Pulls users & groups from navi (`navi explore info users|user_groups|agent_groups`,
live Tenable API) and the application **routes** (`vuln_route`) and filesystem
**paths** (`vuln_paths`) from navi.db. A plain-English instruction then maps each
route/path to an owner; applying a mapping tags every asset on that route/path
with `Owner:<group-or-user>` via the gated navi tag path.
"""
import datetime
import gzip
import hashlib
import json as _json
import os
import re
import functools
import threading
import time as _time

from core import db, navi_cli, tagname, hx_summary, hx_rpp, tagscope, snapcache
from core.agents.base import Agent
from core.security import private_open as _popen

_SPLIT = re.compile(r"\s{2,}")


def _sf(scope, col):
    """Build 489 tag filter: (' AND col IN (SELECT asset_uuid FROM tags WHERE …)', (k, v)) for a
    scope=(tag_key, tag_value); ('', ()) for the whole estate (None), so every estate query
    stays exactly what it was."""
    if not scope:
        return "", ()
    return tagscope.sql(scope[0], scope[1], col)
_DIV = re.compile(r"^-{5,}$")

# ---- Dispositions: mark a route/path as handled WITHOUT an owner ------------------
# 'ignore' = not worth assigning (noise); 'accept' = risk acknowledged, tracked not
# assigned. Both are written as Owner tags with a reserved value ('<name>: Ignored' /
# '<name>: Accepted') so the surface stops showing them as gaps — you see only what
# still NEEDS an owner. They're NOT counted as real owners on the graph or workload.
IGNORED, ACCEPTED, MITIGATED = "Ignored", "Accepted", "Mitigated"
DISPOSITIONS = (IGNORED, ACCEPTED, MITIGATED)
_DISP_VERBS = {"ignore": IGNORED, "ignored": IGNORED, "dismiss": IGNORED, "dismissed": IGNORED,
               "skip": IGNORED, "exclude": IGNORED, "hide": IGNORED, "noise": IGNORED,
               "accept": ACCEPTED, "accepted": ACCEPTED, "waive": ACCEPTED, "waived": ACCEPTED,
               "acknowledge": ACCEPTED, "acknowledged": ACCEPTED, "ack": ACCEPTED,
               "mitigate": MITIGATED, "mitigated": MITIGATED, "mitigating": MITIGATED,
               "remediate": MITIGATED, "remediated": MITIGATED, "remediating": MITIGATED,
               "patched": MITIGATED, "fixed": MITIGATED, "resolved": MITIGATED}
_DISP_STOP = {"the", "a", "an", "route", "routes", "path", "paths", "please", "as", "owner",
              "risk", "and", "then", "this", "that", "for", "of", "on", "to", "all", "it",
              "no", "just", "mark", "are", "is", "be", "been", "being", "should", "we", "i",
              "my", "our", "have", "has", "them", "these", "those", "set"}


def disposition_label(owner):
    """Return the canonical disposition ('Ignored'/'Accepted'/'Mitigated') ONLY when the
    owner string IS exactly one of them (case-insensitive).

    We deliberately do NOT match the broad NL verb list (_DISP_VERBS) here. Those verbs are
    for PARSING a plain-English prompt; using them to judge an EXISTING Owner tag would
    misread a real owner/team whose name happens to be 'Accept', 'Fixed', 'Ack', 'Skip',
    etc. as a disposition and silently drop it from the graph (everything looks unassigned).
    tag_owner only ever writes the three canonical labels, so exact-match is correct."""
    o = (owner or "").strip().lower()
    for d in DISPOSITIONS:
        if o == d.lower():
            return d
    return None


def _tokset(s):
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t}


def _compact(s):
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _targets(toks, rts, pas, kind):
    """Routes/paths that match the instruction terms, best tier first. Matches on the
    COMPACTED name (spaces/punctuation stripped) so 'note pad' hits 'Notepad++' and
    'Microsoft Windows Notepad'; a term counts if it's a substring of the compact name."""
    terms = [t for t in toks if len(t) >= 3]     # ignore tiny/filler tokens
    if not terms:
        terms = toks
    if not terms:
        return []

    def score(name):
        comp = _compact(name)
        return sum(1 for t in terms if t in comp)

    cand = []
    if kind != "path":
        for r in rts:
            nm = r.get("app_name") or ""
            s = score(nm)
            if s:
                cand.append((s, len(_compact(nm)), {"kind": "route", "name": nm,
                             "scope": f"{r.get('total_vulns') or 0} vulns"}))
    if kind != "route":
        for x in pas:
            nm = x.get("path") or ""
            s = score(nm)
            if s:
                cand.append((s, len(_compact(nm)), {"kind": "path", "name": nm, "path": nm,
                             "scope": f"{x.get('assets') or 0} assets"}))
    if not cand:
        return []
    mx = max(c[0] for c in cand)                 # keep only the strongest-match tier
    cand = [c for c in cand if c[0] == mx]
    cand.sort(key=lambda c: c[1])                # most specific (shortest name) first
    return [c[2] for c in cand]


def parse_dispositions(prompt, rts, pas):
    """Pull 'ignore the ICMP route' / 'accept the OpenSSL route' style instructions out of a
    prompt and resolve each to a route/path — no LLM needed. Returns mapping dicts with
    owner set to the disposition sentinel."""
    clauses = re.split(r"\s*(?:,|;|\band\b|\bthen\b|\.|\n)\s*", (prompt or "").lower())
    out, seen = [], set()
    for cl in clauses:
        cl = cl.strip()
        if not cl:
            continue
        # an ASSIGNMENT clause ("give the Jenkins route to Skip", "assign nginx to the Fixed
        # Income team") names an owner, not a disposition — leave it to the owner mapping
        if re.search(r"\b(give|gives|assign|assigned|hand|handed|belongs?|owned\s+by|owner|owners|own|owns)\b", cl):
            continue
        disp = None
        for w, lab in _DISP_VERBS.items():
            if re.search(r"\b" + re.escape(w) + r"\b", cl):
                disp = lab
                break
        if not disp:
            continue
        kind = "path" if "path" in cl else ("route" if "route" in cl else None)
        toks = [t for t in re.split(r"[^a-z0-9]+", cl) if t and t not in _DISP_STOP and t not in _DISP_VERBS]
        if not toks:
            continue
        cands = _targets(toks, rts, pas, kind)
        if not cands:
            continue
        # 'all …' or a plural (routes/paths) means EVERY match; otherwise just the best one.
        multi = bool(re.search(r"\ball\b", cl)) or "routes" in cl or "paths" in cl
        chosen = cands[:50] if multi else cands[:1]
        for best in chosen:
            key = (best["kind"], best["name"].lower())
            if key in seen:
                continue
            seen.add(key)
            m = {"kind": best["kind"], "match": best["name"], "owner": disp,
                 "disposition": disp, "scope": best.get("scope", "")}
            if best.get("path"):
                m["path"] = best["path"]
            out.append(m)
    return out


def _info_rows(stdout: str) -> list[list]:
    """Parse a `navi explore info` text table into its DATA rows only.

    navi prints a BANNER ('Level up your … Navi!') that has its OWN dashed divider,
    THEN the column header, THEN the real table divider, THEN the data. Starting at the
    first divider (the banner's) makes the column header ('User Name / Login Email / …')
    parse as a data row — a bogus owner, and the ONLY 'owner' when the table is empty
    (that's the '1 owner' bug). So we parse everything after the LAST divider, which is
    the table divider — skipping both the banner and the header."""
    lines = (stdout or "").splitlines()
    last_div = -1
    for i, ln in enumerate(lines):
        if _DIV.match(ln.strip()):
            last_div = i
    out = []
    for ln in lines[last_div + 1:]:
        t = ln.strip()
        if t:
            out.append([c.strip() for c in _SPLIT.split(t)])
    return out


def owners() -> list[dict]:
    """Users + groups available to assign — from the on-disk owner cache (see
    owners_cached); the live navi pull is _owners_live()."""
    return owners_cached()[0]


def _owners_live() -> list[dict]:
    """Users + groups available to assign. navi primary; the Tenable MCP acts as a
    backup/validator in the UI layer."""
    out, seen = [], set()

    def add(name, typ, detail="", search=""):
        name = (name or "").strip()
        if not name:
            return
        k = (typ, name.lower())
        if k in seen:
            return
        seen.add(k)
        # `search` holds every field navi reported (login, friendly name, email, …)
        # lowercased, so a mapping can be made by ANY of them — not just the username.
        out.append({"name": name, "type": typ, "detail": detail,
                    "search": (search or (name + " " + detail)).strip().lower()})

    for sub, typ in (("users", "user"), ("user_groups", "user group"),
                     ("agent_groups", "agent group")):
        r = navi_cli.explore_info(sub)
        for f in _info_rows(r.get("stdout", "")):
            if not f:
                continue
            if typ == "user":
                # f[0] = login/username; the remaining columns are the friendly name /
                # email etc. Keep the username as the canonical name, show the friendly
                # name as detail, and index ALL columns for matching.
                add(f[0], "user", f[1] if len(f) > 1 else "", search=" ".join(f))
            elif typ == "user group":
                cnt = f[-1] if (f and f[-1].isdigit()) else ""
                add(f[0], "user group", (cnt + " users") if cnt else "")
            else:
                add(f[0], "agent group", " · ".join(f[1:]) if len(f) > 1 else "")
    return out


def _own_tokens(s):
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t}


def _lev(a, b):
    """Levenshtein distance — tiny, for typo-tolerant 'did you mean' hints."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[len(b)]


def _sim(a, b):
    m = max(len(a), len(b)) or 1
    return 1 - _lev(a, b) / m


def _fmt_owner(o):
    """'creid (Casey Reid)' — username with the friendly name when they differ."""
    d = (o.get("detail") or "").strip()
    return o["name"] + (f" ({d})" if d and d.lower() != o["name"].lower() else "")


def _owner_suggest(query, ow, n=3):
    """Closest owner entries to a typed name — prefix, substring, or small typo."""
    ql = (query or "").strip().lower()
    if not ql:
        return []
    scored = []
    for o in ow:
        hay = o.get("search") or (o.get("name", "") + " " + o.get("detail", "")).lower()
        best = 0.0
        for t in _own_tokens(hay):
            if t.startswith(ql) or ql.startswith(t):
                best = max(best, 0.85)
            best = max(best, _sim(ql, t))
        if ql in hay:
            best = max(best, 0.75)
        if best >= 0.6:
            scored.append((best, o))
    scored.sort(key=lambda x: -x[0])
    out, seen = [], set()
    for _, o in scored:
        if o["name"] in seen:
            continue
        seen.add(o["name"])
        out.append(_fmt_owner(o))
        if len(out) >= n:
            break
    return out


def resolve_owner(query, owners_list=None):
    """Resolve a typed / LLM-produced owner string to ONE canonical owner entry.

    Users can be mapped by username (``creid``), full/friendly name (``Casey Reid``),
    first name (``Casey``), or email local-part — not just the login. Groups match by
    name. Returns ``(entry, None)`` on success, or ``(None, reason)`` when it can't be
    resolved unambiguously so the caller can alert instead of tagging a bogus owner.
    """
    ow = owners() if owners_list is None else owners_list
    q = (query or "").strip()
    if not q:
        return None, "no owner given"
    ql = q.lower()

    def _search(o):
        return o.get("search") or (o.get("name", "") + " " + o.get("detail", "")).lower()

    # 1) exact username / group name — the canonical identifier
    for o in ow:
        if o.get("name", "").strip().lower() == ql:
            return o, None
    # 2) exact friendly name (detail)
    ex = [o for o in ow if o.get("detail", "").strip().lower() == ql]
    if len(ex) == 1:
        return ex[0], None
    # 3) all query tokens present in the entry (first name, email local-part, etc.)
    qt = _own_tokens(q)
    if qt:
        tok = {o["name"]: o for o in ow if qt <= _own_tokens(_search(o))}
        if len(tok) == 1:
            return next(iter(tok.values())), None
    # 4) unique case-insensitive substring across all indexed fields
    sub = {o["name"]: o for o in ow if ql in _search(o)}
    if len(sub) == 1:
        return next(iter(sub.values())), None
    if len(sub) > 1:
        cands = " or ".join(_fmt_owner(o) for o in list(sub.values())[:4])
        return None, f"'{q}' matches several — did you mean {cands}? Be more specific."
    sg = _owner_suggest(q, ow)
    if sg:
        return None, f"'{q}' didn't match a user or group — did you mean {' or '.join(sg)}?"
    return None, f"'{q}' didn't match any user or group — pick one from the list."


def routes(db_path=None, scope=None) -> list[dict]:
    if not scope:
        return db.query("SELECT route_id, app_name, vuln_type, total_vulns, plugin_list "
                        "FROM vuln_route ORDER BY total_vulns DESC LIMIT 1000;", path=db_path)
    # a tag view: only the routes with a finding on the tag's assets. navi's total_vulns is a
    # tenant-wide figure, so it is kept as total_vulns_estate and total_vulns becomes the count
    # of the route's findings (its plugins) on the tag's assets in navi.db.
    rows = list(db.query("SELECT route_id, app_name, vuln_type, total_vulns, plugin_list FROM vuln_route",
                         path=db_path))
    n_by = _route_findings(rows, db_path, scope)
    out = []
    for r in rows:
        n = n_by.get(r.get("route_id"), 0)
        if n > 0:
            r = dict(r)
            r["total_vulns_estate"] = r.get("total_vulns")
            r["total_vulns"] = n
            out.append(r)
    out.sort(key=lambda r: -(r["total_vulns"] or 0))
    return out[:1000]


def _route_findings(rows, db_path, scope) -> dict:
    """route_id -> findings (vulns rows) of the route's plugins on the scope's assets."""
    pids = sorted({p for r in rows for p in _plugin_ids(r.get("plugin_list"))})
    if not pids:
        return {}
    frag, args = _sf(scope, "asset_uuid")
    per = {str(r["plugin_id"]): int(r["n"] or 0) for r in db.query(
        "SELECT plugin_id, COUNT(*) n FROM vulns" + db.indexed_by("hx_v_plugin", db_path) +
        " WHERE plugin_id IN (SELECT value FROM json_each(?))" + frag + " GROUP BY plugin_id",
        (_json.dumps(pids),) + tuple(args), path=db_path, budget="job")}
    return {r.get("route_id"): sum(per.get(p, 0) for p in set(_plugin_ids(r.get("plugin_list")))) for r in rows}


def _plugin_ids(pl) -> list[str]:
    """vuln_route.plugin_list is stored like ['51192', '187315'] — parse to ids."""
    import json
    try:
        return [str(x) for x in json.loads(str(pl or "[]").replace("'", '"'))]
    except Exception:
        return [s for s in re.sub(r"[\[\]'\s]", "", str(pl or "")).split(",") if s]


def paths(db_path=None, scope=None) -> list[dict]:
    if not scope:
        return db.query("SELECT path, MAX(plugin_id) plugin_id, "
                        "COUNT(DISTINCT asset_uuid) assets FROM vuln_paths "
                        "GROUP BY path ORDER BY assets DESC LIMIT 1000;", path=db_path)
    frag, args = _sf(scope, "asset_uuid")
    return db.query("SELECT path, MAX(plugin_id) plugin_id, "
                    "COUNT(DISTINCT asset_uuid) assets FROM vuln_paths WHERE 1=1" + frag +
                    " GROUP BY path ORDER BY assets DESC LIMIT 1000;", args, path=db_path)


def tag_owner(owner: str, route_id=None, path=None, app=None, db_path=None, scope=None) -> dict:
    """Apply a persistent Owner tag (NO remove) to the assets on a route or path.

    Value scheme: ``<App/technology>: <owner>`` so the tag records WHAT is owned, not
    just by whom. A route is tagged with navi's NATIVE ``--route_id`` selector — it's
    exact and avoids emitting a multi-thousand-plugin ``plugin_id IN (...)`` query (a
    route like "Windows Updates" carries ~750 plugins → a ~7 KB query that clutters the
    Tagging log and is easy to mis-read as truncated). Tagging runs on the background
    worker, so the old "route_id is slow / times out the MCP bridge" concern no longer
    applies (the call returns a job stub immediately). If a route_id can't be resolved,
    fall back to the plugin-membership query.

    scope=(tag_key, tag_value) (build 489, a tag view): only the tag's assets on the route/path
    are tagged. The set is re-read here from navi.db — the route's plugins (every vuln_route row
    with this name) on assets carrying the tag, or the path's assets carrying it — and paged
    through navi_cli.tag_set (≤ 1,999 UUIDs per navi job). navi's --route_id can't be narrowed
    to a tag, so a scoped route tag uses navi.db's route membership instead.
    """
    if scope:
        return _tag_owner_scoped(owner, route_id, path, app, db_path, scope)
    # A route can be identified by route_id (from the NL mapping) OR by its app NAME
    # (the Ownership Map hands off names, not ids) — resolve either to its route_id.
    if (route_id not in (None, "")) or (app and not path):
        if route_id not in (None, ""):
            rows = db.query("SELECT route_id, app_name, plugin_list FROM vuln_route WHERE route_id=?",
                            (route_id,), path=db_path)
        else:
            rows = db.query("SELECT route_id, app_name, plugin_list FROM vuln_route "
                            "WHERE app_name=? COLLATE NOCASE LIMIT 1", (app,), path=db_path)
        if not rows:
            return {"ok": False, "message": f"route {app or route_id!r} not found"}
        rid = rows[0].get("route_id")
        name = app or rows[0].get("app_name") or str(rid)
        if rid not in (None, ""):
            # native route selector: exact, one short command, no giant IN() query.
            # Several route_ids can share an app_name and the map merges them by name, so
            # tag EVERY row with this name — tagging only one left the route 'partial' forever.
            rids = [r["route_id"] for r in db.query(
                "SELECT route_id FROM vuln_route WHERE app_name=? COLLATE NOCASE ORDER BY route_id",
                (rows[0].get("app_name") or name,), path=db_path) if r.get("route_id") not in (None, "")] or [rid]
            jobs = [navi_cli.tag("Owner", f"{name}: {owner}", route_id=x, remove=False, agent="exproute")
                    for x in rids]
            first = dict(jobs[0])
            first["ok"] = all(j.get("ok", True) is not False for j in jobs)
            first["job_ids"] = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
            first["route_ids"] = rids
            return first
        # fallback — tag by the route's plugin set (local navi.db membership)
        ids = _plugin_ids(rows[0].get("plugin_list"))
        if not ids:
            return {"ok": False, "message": "route has no plugins to tag"}
        inlist = ",".join("'" + i.replace("'", "''") + "'" for i in ids)
        q = "SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN (" + inlist + ")"
        return navi_cli.tag("Owner", f"{name}: {owner}", query=q, remove=False, agent="exproute")
    if path:
        name = app or path
        q = "SELECT asset_uuid FROM vuln_paths WHERE path='" + str(path).replace("'", "''") + "'"
        return navi_cli.tag("Owner", f"{name}: {owner}", query=q, remove=False, agent="exproute")
    return {"ok": False, "message": "no route_id or path supplied"}


def _tag_owner_scoped(owner, route_id, path, app, db_path, scope) -> dict:
    frag, args = _sf(scope, "asset_uuid")
    if (route_id not in (None, "")) or (app and not path):
        if route_id not in (None, ""):
            rows = db.query("SELECT route_id, app_name, plugin_list FROM vuln_route WHERE route_id=?",
                            (route_id,), path=db_path)
        else:
            rows = db.query("SELECT route_id, app_name, plugin_list FROM vuln_route "
                            "WHERE app_name=? COLLATE NOCASE LIMIT 1", (app,), path=db_path)
        if not rows:
            return {"ok": False, "message": f"route {app or route_id!r} not found"}
        name = app or rows[0].get("app_name") or str(rows[0].get("route_id"))
        allr = db.query("SELECT route_id, plugin_list FROM vuln_route WHERE app_name=? COLLATE NOCASE",
                        (rows[0].get("app_name") or name,), path=db_path) or rows
        pids = sorted({p for r in allr for p in _plugin_ids(r.get("plugin_list"))})
        if not pids:
            return {"ok": False, "message": "route has no plugins to tag"}
        sql = ("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN (SELECT value FROM json_each(?))" + frag)
        params = (_json.dumps(pids),) + tuple(args)
        sel = {"route_ids": [r.get("route_id") for r in allr]}
    elif path:
        name = app or path
        sql = "SELECT DISTINCT asset_uuid FROM vuln_paths WHERE path=?" + frag
        params = (str(path),) + tuple(args)
        sel = {"path": path}
    else:
        return {"ok": False, "message": "no route_id or path supplied"}
    sc = tagscope.describe(scope[0], scope[1], db_path)
    jobs = navi_cli.tag_set("Owner", f"{name}: {owner}", sql=sql, params=params, agent="exproute", path=db_path)
    if not jobs:
        return {"ok": False, "message": f"no asset tagged {sc['label']} is on {name!r} — nothing to tag",
                "scope": sc, "assets": 0, **sel}
    out = dict(jobs[0]) if isinstance(jobs[0], dict) else {}
    out.update(navi_cli.jobs_summary(jobs))
    out["job_id"] = out.get("job_id") if out.get("job_id") is not None else (out["job_ids"][0] if out["job_ids"] else None)
    out.update(sel, scope=sc)
    return out


# Route↔asset membership: an asset is "on" a route when it carries a vuln whose plugin id
# is in that route's plugin_list (stored like ['51192','187315']). We match the id wrapped
# in quotes ('%'<id>'%') so 519 doesn't match 51192.
_RA = ("WITH ra AS (SELECT DISTINCT r.app_name app, v.asset_uuid au "
       "FROM vuln_route r JOIN vulns v ON r.plugin_list LIKE '%''' || v.plugin_id || '''%') ")
# _RA is kept for reference / ad-hoc SQL only. It joins every route to every finding with a
# LIKE — routes × findings string comparisons — so coverage() and ownership_map() no longer
# use it: _base() builds the same route→asset sets from linear scans in Python.


def _nk(s):
    """Owner-tag / route-name key: case-insensitive, whitespace-collapsed."""
    return " ".join((s or "").strip().lower().split())


def _base(db_path=None, scope=None) -> dict:
    """One pass over navi.db shared by ownership_map() and coverage().
    scope=(tag_key, tag_value) (build 489): every asset set below is cut to the tag's assets in
    SQL (findings, paths, Owner tags), and only the routes that touch them are kept. Route/path
    NAMES (for parsing Owner tags) stay estate-wide, so a tag parses the same in every view.

    The same relationships the old SQL computed, without the quadratic LIKE joins:
      route (app_name) → plugin ids   parsed from vuln_route.plugin_list
      route → assets                  plugin ids → DISTINCT (plugin_id, asset_uuid) from vulns
      path  → assets / plugin ids     from vuln_paths
      route ↔ path                    a route's plugin found at that path
      Owner tags                      '<name>: <user>' keyed by _nk(name)
    """
    def q(sql, args=()):
        try:
            return list(db.query(sql, args, path=db_path)) if args else list(db.query(sql, path=db_path))
        except Exception:
            return []
    b = {"has_routes": bool(q("SELECT name FROM sqlite_master WHERE type='table' AND name='vuln_route'"))}
    if scope:
        b["scope"] = tuple(scope)
    if not b["has_routes"]:
        return b
    # `if r[...]`: navi's " " placeholder reads as None (core.db._row) — IS NOT NULL doesn't drop it
    apps = [r["app_name"] for r in q("SELECT DISTINCT app_name FROM vuln_route WHERE app_name IS NOT NULL")
            if r.get("app_name")]
    known = {_nk(a) for a in apps} | {_nk(r["path"]) for r in q("SELECT DISTINCT path FROM vuln_paths WHERE path IS NOT NULL")
                                      if r.get("path")}

    def split(val):
        """'<name>: <user>'. Split at the ': ' whose left side is a known route/path — so an
        owner like 'Ops: EMEA' or a name containing ': ' parses right — else at the last ': '
        (Windows paths 'C:\\…' have no ': ')."""
        if ": " not in val:
            return val, ""
        at = [m.start() for m in re.finditer(": ", val)]
        for pos in at:
            if _nk(val[:pos]) in known:
                return val[:pos], val[pos + 2:]
        return val[:at[-1]], val[at[-1] + 2:]

    # name_owners       every user string on '<name>: …' tags (real owners AND disposition labels)
    # name_assets       assets carrying ANY Owner tag for the name (sizing / unmatched lists)
    # owned_assets      assets carrying a REAL owner for the name — not Ignored/Accepted/
    #                   Mitigated, not a bare '<name>' with no user
    # disp_assets       assets carrying a disposition for the name
    # user_assets       (name, user) -> assets, so an owner's workload is only their own assets
    name_owners, name_assets, name_display, tagged = {}, {}, {}, set()
    owned_assets, disp_assets, user_assets, asset_owned, asset_disp = {}, {}, {}, {}, {}
    _tf, _ta = _sf(scope, "asset_uuid")
    for r in q("SELECT asset_uuid, tag_value FROM tags WHERE " + tagname.sql_lit("tag_key", "Owner") + " AND tag_value IS NOT NULL" + _tf, _ta):
        val = (r.get("tag_value") or "").strip()
        au = r.get("asset_uuid")
        name, user = split(val)
        name, user = name.strip(), user.strip()
        k = _nk(name)
        name_display.setdefault(k, name)
        if user:
            name_owners.setdefault(k, set()).add(user)
        if not au:
            continue
        tagged.add(au)
        name_assets.setdefault(k, set()).add(au)
        if user and disposition_label(user):
            disp_assets.setdefault(k, set()).add(au)
            asset_disp.setdefault(au, set()).add(k)
        elif user:
            owned_assets.setdefault(k, set()).add(au)
            user_assets.setdefault((k, user), set()).add(au)
            asset_owned.setdefault(au, set()).add(k)
    app_plugins, plugin_apps = {}, {}
    for r in q("SELECT app_name, plugin_list FROM vuln_route WHERE app_name IS NOT NULL"):
        app = r.get("app_name")
        if not app:                       # " " → None (core.db._row): IS NOT NULL doesn't catch it
            continue
        pids = set(_plugin_ids(r.get("plugin_list")))
        app_plugins.setdefault(app, set()).update(pids)
        for pid in pids:
            plugin_apps.setdefault(pid, set()).add(app)
    # ── the route / path / plugin zipper (core/hx_rpp) ───────────────────────────────────────
    # ONE pass over every OPEN, NON-INFO finding (distinct plugin × asset) with its plugin's route
    # and the paths that plugin was found at on that asset — from ⚡ Optimize's hx_rpp index when
    # fresh, else straight from navi.db (same rows). Fixed and info findings no longer count
    # anywhere on this page. Each finding is:
    #   owned    the asset carries a real Owner tag for the plugin's route OR one of its paths
    #   decided  no owner, but a disposition (Ignored/Accepted/Mitigated) for the route or a path
    #   unowned  it has a route or a path, and neither is owned/decided on this asset
    #   orphan   no route and no path — tagging can't reach it until routes/paths are rebuilt
    route_assets, plugin_asset_n = {}, {}
    path_assets, path_plugin, path_rows = {}, {}, set()
    route_paths, path_routes = {}, {}
    path_inherit = {}                       # path → assets owned for it THROUGH the plugin's route
    zf = {"total": 0, "owned": 0, "decided": 0, "unowned": 0, "orphan": 0}
    zl = {"route_only": 0, "path_only": 0, "both": 0, "neither": 0}
    zp = {}                                 # plugin → [findings, owned, decided, orphan, route, paths set]
    zr, zpa = {}, {}                        # route / path → findings tagging it would close
    # build 497: coverage of each route / path by its FINDINGS, whatever method owns them —
    # [findings, owned, decided] and the assets with a finding on it that isn't owned
    cov_r, cov_p, open_r, open_p = {}, {}, {}, {}
    a_open, a_cov, a_all = set(), set(), set()   # a_open: an asset with ANY finding not owned
    _zf, _za = _sf(scope, "asset_uuid")
    try:
        src = "index" if hx_rpp.usable(db_path) else "navi.db"
        for pid, au, app, pths in hx_rpp.iter_findings(db_path, _zf, _za, budget="job"):
            pid = str(pid)
            a_all.add(au)
            plugin_asset_n[pid] = plugin_asset_n.get(pid, 0) + 1
            own = asset_owned.get(au, ())
            dsp = asset_disp.get(au, ())
            ka = _nk(app) if app else None
            via_route = bool(ka and ka in own)
            if app:
                route_assets.setdefault(app, set()).add(au)
            for p in pths:
                path_assets.setdefault(p, set()).add(au)
                path_plugin.setdefault(p, set()).add(pid)
                path_rows.add((p, au))
                if app:
                    route_paths.setdefault(app, set()).add(p)
                    path_routes.setdefault(p, set()).add(app)
                if via_route:
                    path_inherit.setdefault(p, set()).add(au)
            zl["both" if app and pths else "route_only" if app else "path_only" if pths else "neither"] += 1
            e = zp.get(pid)
            if e is None:
                e = zp[pid] = [0, 0, 0, 0, app, set()]
            e[0] += 1
            e[5].update(pths)
            zf["total"] += 1
            is_owned = via_route or any(_nk(p) in own for p in pths)
            is_dec = (not is_owned) and bool((ka and ka in dsp) or any(_nk(p) in dsp for p in pths))
            if app:
                c_ = cov_r.get(app)
                if c_ is None:
                    c_ = cov_r[app] = [0, 0, 0]
                c_[0] += 1
                c_[1] += is_owned
                c_[2] += is_dec
                if not is_owned:
                    open_r.setdefault(app, set()).add(au)
            for p in pths:
                c_ = cov_p.get(p)
                if c_ is None:
                    c_ = cov_p[p] = [0, 0, 0]
                c_[0] += 1
                c_[1] += is_owned
                c_[2] += is_dec
                if not is_owned:
                    open_p.setdefault(p, set()).add(au)
            if is_owned:
                zf["owned"] += 1
                e[1] += 1
                a_cov.add(au)
            elif is_dec:
                zf["decided"] += 1               # a decision, not an owner: covered, never closed
                e[2] += 1
                a_cov.add(au)
                a_open.add(au)
            elif not app and not pths:
                zf["orphan"] += 1
                e[3] += 1
                a_open.add(au)
            else:
                zf["unowned"] += 1
                a_open.add(au)
                if app:
                    zr[app] = zr.get(app, 0) + 1
                for p in pths:
                    zpa[p] = zpa.get(p, 0) + 1
    except db.QueryTimeout:
        raise
    except Exception as e:
        src = "unavailable: %s" % e
        route_assets, plugin_asset_n, path_assets, path_plugin, path_rows = {}, {}, {}, {}, set()
        route_paths, path_routes, path_inherit = {}, {}, {}
        cov_r, cov_p, open_r, open_p = {}, {}, {}, {}
    if scope:
        # the tag's attack surface: a route is in it when one of the tag's assets is on it, or
        # carries an Owner tag / decision for it (a disposition-only route)
        apps = [a for a in apps if route_assets.get(a) or name_assets.get(_nk(a))]
        _in = set(apps)
        app_plugins = {a: ps for a, ps in app_plugins.items() if a in _in}
        plugin_apps = {pid: {a for a in aps if a in _in} for pid, aps in plugin_apps.items()}
    b["zip_raw"] = {"source": src, "findings": zf, "links": zl, "plugins": zp, "routes": zr,
                    "paths": zpa, "assets_open": a_open, "assets_covered": a_cov, "assets_all": a_all}
    b.update(name_owners=name_owners, name_assets=name_assets, name_display=name_display,
             owned_assets=owned_assets, disp_assets=disp_assets, user_assets=user_assets,
             asset_owned=asset_owned, tagged=tagged, app_plugins=app_plugins, route_assets=route_assets,
             plugin_asset_n=plugin_asset_n, path_assets=path_assets, path_plugin=path_plugin,
             path_rows=path_rows, route_paths=route_paths, path_routes=path_routes, apps=apps,
             asset_disp=asset_disp, path_inherit=path_inherit,
             cov_r=cov_r, cov_p=cov_p, open_r=open_r, open_p=open_p)
    return b


ZIP_TOP = 200          # unowned plugins listed (the UI never gets the full set)
ZIP_GAP = 25           # routes / paths in each "close the gap" list


def zipper(b, db_path=None) -> dict:
    """Roll _base's per-finding zipper up for the page: findings, plugins, the route ↔ path
    ratio, the routes/paths that would close the most unowned findings, and the worst plugins."""
    z = b.get("zip_raw")
    if not z:
        return {"ok": False, "note": "No vuln_route table — run `navi config update route` + `navi config update paths`."}
    zf, zp = dict(z["findings"]), z["plugins"]
    tot = zf["total"]

    def pct(n, d):
        return round(100.0 * n / d, 1) if d else 0.0
    zf["pct_owned"] = pct(zf["owned"], tot)
    zf["pct_covered"] = pct(zf["owned"] + zf["decided"], tot)
    pl = {"total": len(zp), "owned": 0, "decided": 0, "partial": 0, "unowned": 0, "unrouted": 0}
    rows = []
    for pid, (n, o, d, orph, app, pths) in zp.items():
        done = o + d
        st = ("owned" if o == n else                 # every finding has an owner
              "decided" if done == n else            # the rest carry Ignored/Accepted/Mitigated
              "unrouted" if orph == n else
              "unowned" if done == 0 else "partial")
        pl[st] += 1
        if st != "owned":
            rows.append({"plugin_id": pid, "route": app, "paths": len(pths), "findings": n,
                         "owned": o, "decided": d, "orphan": orph, "open": n - done, "status": st})
    rows.sort(key=lambda r: (-r["open"], r["plugin_id"]))
    rows = rows[:ZIP_TOP]
    # names + severity for the listed plugins only (hx_plugin when fresh, else plugins)
    meta = {}
    ids = [r["plugin_id"] for r in rows]
    if ids:
        try:
            if hx_summary.usable(db_path):
                for r in db.query("SELECT plugin_id, name, sevn FROM hx_plugin WHERE plugin_id IN "
                                  "(SELECT value FROM json_each(?))", (_json.dumps(ids),), path=db_path):
                    meta[str(r["plugin_id"])] = (r.get("name"), r.get("sevn"))
            else:      # the same representative finding hx_plugin uses (its lowest rowid)
                for r in db.query("SELECT plugin_id, plugin_name name, severity FROM vulns WHERE rowid IN "
                                  "(SELECT MIN(rowid) FROM vulns" + db.indexed_by("hx_v_plugin", db_path) +
                                  " WHERE plugin_id IN (SELECT value FROM json_each(?)) GROUP BY plugin_id)",
                                  (_json.dumps(ids),), path=db_path, budget="job"):
                    meta[str(r["plugin_id"])] = (r.get("name"), r.get("severity"))
        except db.QueryTimeout:
            raise
        except Exception:
            meta = {}
    _sev = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: ""}
    _sevt = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "", "info": "", "none": ""}
    for r in rows:
        nm, sv = meta.get(r["plugin_id"], (None, None))
        r["name"] = nm or ""
        if isinstance(sv, int):
            r["severity"] = _sev.get(sv, "")
        else:
            t = str(sv or "").strip().lower()
            r["severity"] = _sevt.get(t, t) if t in _sevt or t in ("critical", "high", "medium", "low") else ""
    rp, pr = b.get("route_paths") or {}, b.get("path_routes") or {}
    apps = b.get("apps") or []
    ratio = {"routes_no_path": sum(1 for a in apps if (b["route_assets"].get(a)) and not rp.get(a)),
             "routes_one_path": sum(1 for a in apps if len(rp.get(a, ())) == 1),
             "routes_many_paths": sum(1 for a in apps if len(rp.get(a, ())) > 1),
             "paths_no_route": sum(1 for p in b["path_assets"] if not pr.get(p)),
             "paths_one_route": sum(1 for p in b["path_assets"] if len(pr.get(p, ())) == 1),
             "paths_many_routes": sum(1 for p in b["path_assets"] if len(pr.get(p, ())) > 1)}
    ratio["one_to_one"] = sum(1 for a in apps if len(rp.get(a, ())) == 1
                              and len(pr.get(next(iter(rp[a])), ())) == 1)
    gap_r = sorted(z["routes"].items(), key=lambda x: (-x[1], x[0]))[:ZIP_GAP]
    gap_p = sorted(z["paths"].items(), key=lambda x: (-x[1], x[0]))[:ZIP_GAP]
    a_all, a_open, a_cov = z["assets_all"], z["assets_open"], z["assets_covered"]
    return {"ok": True, "source": z["source"], "findings": zf, "links": dict(z["links"]), "plugins": pl,
            "ratio": ratio,
            "gap_routes": [{"name": n, "closes": c, "assets": len(b["route_assets"].get(n, ())),
                            "paths": len(rp.get(n, ()))} for n, c in gap_r],
            "gap_paths": [{"name": n, "closes": c, "assets": len(b["path_assets"].get(n, ())),
                           "routes": sorted(pr.get(n, ()))} for n, c in gap_p],
            "top_plugins": rows, "top_limit": ZIP_TOP,
            # closed: every open finding OWNED (a decision isn't an owner); ownerless: not one
            # finding owned or decided
            "assets": {"total": len(a_all), "closed": len(a_all - a_open),
                       "open": len(a_open), "ownerless": len(a_all - a_cov)}}


def plugin_assets(b, pid, db_path=None) -> int:
    """Distinct assets (NULL counted once, as the old DISTINCT pair scan did) carrying one plugin —
    from _base's route-plugin counts when it's a route plugin, else one index SEARCH."""
    pid = str(pid)
    n = (b.get("plugin_asset_n") or {}).get(pid)
    if n is not None:
        return int(n)
    if str((b.get("zip_raw") or {}).get("source", "")) in ("index", "navi.db"):
        return 0                    # build 496: assets with an OPEN, non-info finding — none
    if b.get("scope"):
        frag, args = _sf(b["scope"], "asset_uuid")
        try:
            return int(db.scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns" + db.indexed_by("hx_v_plugin", db_path) +
                                 " WHERE plugin_id=?" + frag, (pid,) + tuple(args), path=db_path, budget="job") or 0)
        except Exception:
            return 0
    try:
        if hx_summary.usable(db_path):
            # hx_plugin.assets = COUNT(DISTINCT asset_uuid) (NULL not counted) — add the NULL the
            # old DISTINCT counted once: one covered seek on hx_v_plugin(plugin_id, asset_uuid)
            n = db.scalar("SELECT assets FROM hx_plugin WHERE plugin_id=?", (pid,), path=db_path)
            if n is not None:
                return int(n) + int(db.scalar(
                    "SELECT EXISTS(SELECT 1 FROM vulns" + db.indexed_by("hx_v_plugin", db_path) +
                    " WHERE plugin_id=? AND asset_uuid IS NULL)", (pid,), path=db_path) or 0)
        return int(db.scalar("SELECT COUNT(*) FROM (SELECT DISTINCT asset_uuid FROM vulns" +
                             db.indexed_by("hx_v_plugin", db_path) + " WHERE plugin_id=?)", (pid,),
                             path=db_path, budget="run") or 0)
    except Exception:
        return 0


def _has_owner_tag(b, au, name):
    """The asset carries a REAL owner tag for this route/path ('<name>: <user>', name compared
    case- and whitespace-insensitively, no LIKE wildcards; dispositions don't count)."""
    return _nk(name) in b["asset_owned"].get(au, ())


def retag_owner_tags(from_name, to_name, db_path=None, scope=None) -> dict:
    """Move the Owner tags written for an UNMATCHED name ('WEB SERVER: alice') onto an exact
    route/path name ('WEB SERVER ALLOWS: alice') — on exactly the assets that carry the old
    tag, per owner. (Tagging the whole route by --route_id put every asset on the route under
    every owner of the old name.) Never removes the old tag.
    scope=(tag_key, tag_value): only the tag's assets that carry the old tag (re-read here)."""
    _rf, _ra = _sf(scope, "asset_uuid")
    _uf, _ua = _sf(scope, "uuid")
    rt = {_nk(r["app_name"]): r["app_name"] for r in db.query(
        "SELECT DISTINCT app_name FROM vuln_route WHERE app_name IS NOT NULL", path=db_path)}
    pa = {_nk(r["path"]): r["path"] for r in db.query(
        "SELECT DISTINCT path FROM vuln_paths WHERE path IS NOT NULL", path=db_path)}
    target = rt.get(_nk(to_name)) or pa.get(_nk(to_name))
    if not target:
        return {"ok": False, "message": f"'{to_name}' is not a route or path in navi.db"}
    src = _nk(from_name)
    if not src or src in rt or src in pa:
        return {"ok": False, "message": f"'{from_name}' already matches a route/path — nothing to move"}
    by_user, raw_vals = {}, {}
    owner_key = tagname.sql_lit("tag_key", "Owner")
    for r in db.query("SELECT asset_uuid, tag_value FROM tags WHERE " + owner_key + " AND tag_value IS NOT NULL" + _rf,
                      tuple(_ra), path=db_path):
        val = (r.get("tag_value") or "").strip()
        if ": " not in val or not r.get("asset_uuid"):
            continue
        name, user = val.rsplit(": ", 1)
        if _nk(name) == src and user.strip():
            by_user.setdefault(user.strip(), set()).add(r["asset_uuid"])
            raw_vals.setdefault(user.strip(), set()).add(r["tag_value"])
    if not by_user:
        return {"ok": False, "message": f"no Owner tags named '{from_name}: …' in navi.db"
                + (f" on the assets tagged {scope[0]} : {scope[1]}" if scope else "")}
    jobs, out = [], []
    for user, aus in sorted(by_user.items()):
        uu = sorted(aus)
        # the set's own definition (assets carrying one of these exact Owner tag values),
        # computed here and paged (≤1,999 per navi job)
        vals = ",".join("'" + str(v).replace("'", "''") + "'" for v in sorted(raw_vals.get(user, ())))
        q = ("SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (SELECT asset_uuid FROM tags WHERE "
             + owner_key + " AND tag_value IN (" + vals + "))" + _uf)
        if scope:
            js = navi_cli.tag_set("Owner", f"{target}: {user}", sql=q, params=tuple(_ua), agent="exproute", path=db_path)
        else:
            js = navi_cli.tag_set("Owner", f"{target}: {user}", sql=q, agent="exproute", path=db_path)
        jobs += [j.get("job_id") for j in js if j.get("job_id") is not None]
        out.append({"owner": user, "assets": len(uu)})
    res = {"ok": True, "target": target, "owners": out, "job_ids": jobs,
           "assets": sum(x["assets"] for x in out)}
    if scope:
        res["scope"] = tagscope.describe(scope[0], scope[1], db_path)
    return res


def coverage(db_path=None, base=None, om=None, users_total=None, scope=None) -> dict:
    """How much of the attack surface has an owner assigned. An asset is CLOSED only when
    EVERY route it sits on is owned (an Owner:'<app>: <user>' tag for each route). Read-only.
    Pass `base` / `om` (from _base / ownership_map) to reuse one pass instead of re-reading."""
    def sc(sql, args=()):
        try:
            return (db.scalar(sql, args, path=db_path) if args else db.scalar(sql, path=db_path)) or 0
        except Exception:
            return 0
    b = base if base is not None else _base(db_path, scope)
    scope = scope or b.get("scope")
    _f, _a = _sf(scope, "asset_uuid")
    if not b.get("has_routes"):
        return {"ok": True, "owned": 0, "assets_with_routes": 0, "avg_routes": 0.0,
                "closed": 0, "total_routes": 0, "total_paths": 0, "owned_paths": 0,
                "note": "No vuln_route table — run `navi config update route` + `navi config update paths`."}
    owned = len(b["asset_owned"])              # assets with a real owner on some route/path
    # distinct people/groups actually assigned in Owner tags (the '<app>: <user>' scheme) —
    # what the operator means by "my owners", independent of the navi user directory.
    owner_count = sc("SELECT COUNT(DISTINCT TRIM(substr(tag_value, instr(tag_value, ': ')+2))) "
                     "FROM tags WHERE " + tagname.sql_lit("tag_key", "Owner") + " AND tag_value LIKE '%: %'" + _f, _a)
    ra = b["route_assets"]
    asset_apps = {}
    for app, aus in ra.items():
        for au in aus:
            asset_apps.setdefault(au, set()).add(app)
    assets_with_routes = len(asset_apps)
    avg_routes = (sum(len(x) for x in asset_apps.values()) / len(asset_apps)) if asset_apps else 0
    total_routes = len(b["apps"])              # distinct route names — what the map counts
    # build 496: everything below counts OPEN, NON-INFO findings only (the zipper) — navi's
    # vuln_route.total_vulns and raw vuln_paths rows also count fixed and info findings.
    # workload reduction: path findings (asset × path) collapse to the distinct paths you
    # assign; route findings collapse to a handful of routes.
    _z = b.get("zip_raw") or {}
    _zl = _z.get("links") or {}
    total_paths = len(b.get("path_assets") or {})
    path_findings = len(b.get("path_rows") or ())
    route_findings = int(_zl.get("route_only", 0)) + int(_zl.get("both", 0))
    # Owner-tag matching is CASE-INSENSITIVE, the same as ownership_map(): an asset is
    # owned for a route/path when it carries an Owner '<name>: …' tag for that name.
    # Route and path ownership come from the map's statuses, so the two widgets can't
    # disagree: a route is owned when every asset on it has a real owner tag for it; a path
    # when every asset does OR the route covering it is owned.
    om = om if om is not None else ownership_map(db_path, base=b, scope=scope)
    routes_owned = sum(1 for r in om.get("routes", []) if r.get("status") == "owned")
    owned_paths = sum(1 for p in om.get("paths", []) if p.get("status") == "owned")
    # an ASSET is closed when every open finding on it is OWNED through its plugin's route or a
    # path it was found at (build 496 — it used to need every ROUTE owned, so an asset owned
    # through its paths never closed). Ignored/Accepted/Mitigated isn't an owner.
    closed = len(set(_z.get("assets_all") or ()) - set(_z.get("assets_open") or ()))
    # --- outcome of decisions on each route/path + who has no assigned work ------
    # Reuse the Ownership Map so these numbers reconcile exactly with the graph.
    #   owners_total    = people the platform knows as owners (any Owner tag, minus
    #                     disposition sentinels)
    #   owners_assigned = owners actually landed on a route/path (have work)
    #   owners_no_work  = owners with NOTHING assigned to a live route/path
    #   mitigated/accepted/ignored = share of the whole route+path surface handled
    owners_total = owners_assigned = owners_no_work = 0
    surface_total = mit = acc = ign = 0
    try:
        k = om.get("kpi", {}) or {}
        surface_total = int(k.get("routes", 0)) + int(k.get("paths", 0))
        mit = int(k.get("mitigated", 0)); acc = int(k.get("accepted", 0)); ign = int(k.get("ignored", 0))
        _disp_words = set(_DISP_VERBS) | {d.lower() for d in DISPOSITIONS}
        assigned_set = {str(o).strip() for o in om.get("owners", []) if str(o).strip()}
        all_set = set(assigned_set)
        for u in om.get("unmatched_owners", []):
            for o in (u.get("owners") or []):
                s = str(o).strip()
                if s and s.lower() not in _disp_words:
                    all_set.add(s)
        owners_assigned = len(assigned_set)
        owners_total = len(all_set)
        owners_no_work = max(0, owners_total - owners_assigned)
    except Exception:
        pass

    # total platform users (the denominator for owner engagement): 4 owners of 87 users.
    if users_total is None:                 # from the cached owner directory, not a live call
        try:
            users_total = sum(1 for o in owners() if o.get("type") == "user")
        except Exception:
            users_total = 0

    def _p(n, d):
        return round(100.0 * n / d, 1) if d else 0.0

    out = {"ok": True, "owned": int(owned), "owner_count": int(owner_count),
            "users_total": int(users_total),
            "assets_with_routes": int(assets_with_routes),
            "avg_routes": round(float(avg_routes or 0), 1), "closed": int(closed),
            "assets_total": len(_z.get("assets_all") or ()),     # assets with an open finding
            "routes_owned": int(routes_owned),
            "total_routes": int(total_routes), "total_paths": int(total_paths),
            "owned_paths": int(owned_paths), "path_findings": int(path_findings),
            "route_findings": int(route_findings),
            # NEW — owner engagement + decision outcomes (routes+paths surface)
            "owners_total": int(owners_total), "owners_assigned": int(owners_assigned),
            "owners_no_work": int(owners_no_work), "owners_pct": _p(owners_assigned, owners_total),
            "surface_total": int(surface_total),
            "mitigated": int(mit), "mitigated_pct": _p(mit, surface_total),
            "accepted": int(acc), "accepted_pct": _p(acc, surface_total),
            "ignored": int(ign), "ignored_pct": _p(ign, surface_total)}
    if scope:
        out["scope"] = tagscope.describe(scope[0], scope[1], db_path)
    return out


def ownership_map(db_path=None, base=None, scope=None) -> dict:
    """The Ownership Map — every route/path with the owners assigned to it (the Owner
    tag scheme '<name>: <user>'), the assets behind it, and a coverage status:
      owned   — every asset on it carries that route/path's Owner tag
      partial — some but not all of its assets are owned (too few owners)
      unowned — no owner at all
    Plus per-owner workload (routes/paths/assets each owner carries) and the count of
    assets on the attack surface with no owner. Read-only; feeds the network-thread graph."""
    def q(sql, args=()):
        try:
            return list(db.query(sql, args, path=db_path)) if args else list(db.query(sql, path=db_path))
        except Exception:
            return []
    if not q("SELECT name FROM sqlite_master WHERE type='table' AND name='vuln_route'"):
        return {"ok": True, "routes": [], "paths": [], "owners": [], "owner_load": [],
                "kpi": {"routes": 0, "paths": 0, "owners": 0, "unowned_assets": 0},
                "note": "No vuln_route/vuln_paths tables — run `navi config update route` + `navi config update paths`."}

    # Owner tags -> map a route/path NAME to its owners + the assets carrying that tag.
    # Keyed CASE-INSENSITIVELY (whitespace-collapsed) because owner tags are frequently
    # applied in a different case than navi's route app_name — e.g. an 'SIEMENS: …' tag
    # vs the 'Siemens' route, 'APACHE TOMCAT' vs 'Apache Tomcat'. The value scheme is
    # '<name>: <user>' (split on the LAST ': ' so Windows paths like 'C:\...' survive).
    # Built once in _base() and shared with coverage().
    b = base if base is not None else _base(db_path, scope)
    scope = scope or b.get("scope")
    name_owners, name_assets, name_display = b["name_owners"], b["name_assets"], b["name_display"]
    owned_by, disp_by = b["owned_assets"], b["disp_assets"]
    route_assets, path_assets = b["route_assets"], b["path_assets"]

    def _item(name, kind, assets):
        k = _nk(name)
        raw = name_owners.get(k, set())
        # split disposition sentinels (Ignored/Accepted/Mitigated) out of the real owners
        disp, real = None, set()
        for u in raw:
            lab = disposition_label(u)
            if lab:
                disp = lab
            else:
                real.add(u)
        owners = sorted(real)
        owned = len(owned_by.get(k, set()) & assets)        # real owners only — a disposition or a
                                                            # bare '<name>' tag doesn't own an asset
        total = len(assets)
        if disp and not owners:                             # disposition ONLY when no real owner
            status = disp.lower()                           # 'ignored' | 'accepted' | 'mitigated'
            # a route may have no plugin-membership assets but the disposition still tagged
            # some — size it by the tagged set so it shows on the Sankey (not filtered out).
            if total == 0:
                total = len(disp_by.get(k, set()) or name_assets.get(k, set()))
        else:
            status = ("unowned" if (not owners or owned == 0)
                      else "partial" if owned < total else "owned")
        return {"name": name, "type": kind, "owners": owners, "owner_count": len(owners),
                "assets": total, "owned_assets": owned, "status": status, "disposition": disp}

    routes = [_item(a, "route", route_assets.get(a, set())) for a in b["apps"]]
    paths = [_item(p, "path", a) for p, a in path_assets.items()]

    # ── Per-route/path threat scores: the HIGHEST VPR and HIGHEST CVSS3 on the route wins ──
    # VPR is stored per-finding in vulns.score (navi writes plugin['vpr']['score'] there); the
    # CVSS3 base score is stored per-plugin in plugins.cvss3_base_score. We roll BOTH up to the
    # route/path by taking the MAX across the plugins that define it, so the Ownership graphs can
    # filter to the biggest threats. Defensive: degrades to null (never errors) if a column or
    # table is missing / unscored — q() already returns [] on any query error.
    def _fnum(x):
        try:
            v = float(x)
            return v if v == v else None            # drop NaN
        except (TypeError, ValueError):
            return None
    vpr_by_pid = {}
    # only the plugins that define a route/path are ever looked up — read just theirs (index
    # SEARCH by plugin_id), not a GROUP BY over every finding
    _score_pids = sorted(set().union(*b["app_plugins"].values(), *b["path_plugin"].values())) \
        if (b["app_plugins"] or b["path_plugin"]) else []
    _vf, _va = _sf(scope, "asset_uuid")      # a tag view: the highest VPR among the tag's findings
    for r in (q("SELECT plugin_id, MAX(score) m FROM vulns WHERE plugin_id IN (SELECT value FROM json_each(?)) "
                "AND score IS NOT NULL" + _vf + " GROUP BY plugin_id", (_json.dumps(_score_pids),) + tuple(_va)) if _score_pids else []):
        v = _fnum(r.get("m"))
        if v is not None:
            vpr_by_pid[str(r.get("plugin_id"))] = v
    cvss_by_pid = {}
    if q("SELECT 1 FROM pragma_table_info('plugins') WHERE name='cvss3_base_score'"):
        for r in q("SELECT plugin_id, cvss3_base_score c FROM plugins "
                   "WHERE cvss3_base_score IS NOT NULL AND cvss3_base_score NOT IN ('','None')"):
            v = _fnum(r.get("c"))
            if v is not None:
                cvss_by_pid[str(r.get("plugin_id"))] = v
    app_plugins, path_plugin = b["app_plugins"], b["path_plugin"]

    def _maxscore(pids, table):
        vals = [table[p] for p in pids if p in table]
        return round(max(vals), 1) if vals else None
    for it in routes:
        pids = app_plugins.get(it["name"], set())
        it["vpr"] = _maxscore(pids, vpr_by_pid)
        it["cvss3"] = _maxscore(pids, cvss_by_pid)
    for it in paths:
        pids = path_plugin.get(it["name"], set())
        it["vpr"] = _maxscore(pids, vpr_by_pid)
        it["cvss3"] = _maxscore(pids, cvss_by_pid)

    # PLUGIN-MEDIATED route<->path link — the accurate relationship: a route's plugins
    # (plugin_list) found at a filesystem path (vuln_paths.plugin_id). One app/route can
    # cover MANY paths (e.g. a Jenkins route's plugins fire in many sub-dirs). This is the
    # true CVE→plugin→app→path chain, NOT the loose shared-asset proxy. Surfaces apps with
    # no filesystem-path detail and ORPHAN paths whose plugin belongs to no app.
    route_paths, path_routes = b["route_paths"], b["path_routes"]
    for it in routes:
        it["paths_on_route"] = len(route_paths.get(it["name"], set()))
    for it in paths:
        cov = path_routes.get(it["name"], set())
        it["routes"] = sorted(cov)                # which app(s) cover this path
        it["on_route"] = bool(cov)
    # ── Status = COVERAGE of the item's findings (build 497) ─────────────────────────────────
    # Routes and paths are two ways to assign PLUGINS to people. An item is owned when every open,
    # non-info finding on it is owned — by its own Owner tag, or by the route / path tag that
    # covers the same finding. Own the CentOS route and every CentOS path is 100% owned too;
    # hand one of those paths to someone else and it stays 100% owned (now by them).
    #   owned    every finding on it owned            partial  some
    #   ignored / accepted / mitigated  none owned, its findings carry that decision
    #   unowned  none owned
    # `assigned` = it carries a real Owner tag of its own (direct assignment) — counted
    # separately; owners = direct owners + the owners of the routes/paths that cover it.
    _route_by = {r["name"]: r for r in routes}
    _path_by = {p["name"]: p for p in paths}
    ua = b["user_assets"]
    cov_r, cov_p = b.get("cov_r") or {}, b.get("cov_p") or {}
    open_r, open_p = b.get("open_r") or {}, b.get("open_p") or {}
    for it in routes + paths:
        it["direct_owners"] = list(it["owners"])
        it["assigned"] = bool(it["owners"])
        is_r = it["type"] == "route"
        f = (cov_r if is_r else cov_p).get(it["name"])
        if not f or not f[0]:
            it.update(findings=0, findings_owned=0, findings_decided=0, coverage_pct=0.0)
            continue                      # no open finding on it: keep the tag-based status
        tot, own, dec = f
        aset = (route_assets if is_r else path_assets).get(it["name"], set())
        it["findings"], it["findings_owned"], it["findings_decided"] = tot, own, dec
        it["coverage_pct"] = round(100.0 * own / tot, 1)
        it["owned_assets"] = len(aset - (open_r if is_r else open_p).get(it["name"], set()))
        if own >= tot:
            it["status"] = "owned"
        elif own:
            it["status"] = "partial"
        elif dec:                          # nothing owned; its findings carry a decision
            it["status"] = (it.get("disposition") or "Accepted").lower()
        else:
            it["status"] = "unowned"
        # who covers it besides its own tag
        others = it["routes"] if not is_r else sorted(route_paths.get(it["name"], set()))
        lookup = _route_by if not is_r else _path_by
        via = sorted(o for o in others if lookup.get(o, {}).get("direct_owners", lookup.get(o, {}).get("owners"))
                     and owned_by.get(_nk(o), set()) & aset) if own else []
        if is_r:
            it["via_paths"] = via
        else:
            it["via_routes"] = via
            it["inherited"] = bool(via) and own > 0 and not it["assigned"]
        # who owns each of its assets: its OWN Owner tag wins on the assets it's on (a path handed
        # to bob is bob's there); the routes/paths covering it fill in the rest. Each asset splits
        # 1 between its owners → owner_assets, so the Sankey shows a reassigned path as the small
        # slice it is (own CentOS, give bob one path on one asset: CentOS stays all alice's).
        k = _nk(it["name"])
        share = {}
        for au in aset:
            ow = [o for o in it["direct_owners"] if au in ua.get((k, o), ())]
            if not ow and own:
                ow = sorted({u for v in via for u in lookup.get(v, {}).get("direct_owners", lookup.get(v, {}).get("owners", []))
                             if au in ua.get((_nk(v), u), ())})
            for o in ow:
                share[o] = share.get(o, 0.0) + 1.0 / len(ow)
        it["owner_assets"] = {o: round(v, 2) for o, v in sorted(share.items())}
        if own and via:
            it["owners"] = sorted(set(it["direct_owners"]) | {o for o, v in share.items() if v > 0})
            it["owner_count"] = len(it["owners"])
    route_paths_list = {a: sorted(s) for a, s in route_paths.items()}
    orphan_paths = sorted(p["name"] for p in paths if not p["on_route"])

    routes.sort(key=lambda x: (-x["assets"], x["name"]))
    paths.sort(key=lambda x: (-x["assets"], x["name"]))

    # per-owner workload: routes, paths and distinct assets each owner carries
    # — only the items an owner is DIRECTLY tagged on, and only the assets tagged to THEM
    #   (not every asset tagged for the name, which counted other owners' and dispositions')
    load = {}
    ua = b["user_assets"]
    for it in routes + paths:
        k = _nk(it["name"])
        for o in it.get("direct_owners", it["owners"]):
            e = load.setdefault(o, {"owner": o, "routes": 0, "paths": 0, "assets": set()})
            e["routes" if it["type"] == "route" else "paths"] += 1
            e["assets"] |= ua.get((k, o), set())
    owner_load = sorted(([{"owner": e["owner"], "routes": e["routes"], "paths": e["paths"],
                           "assets": len(e["assets"])} for e in load.values()]),
                        key=lambda x: -(x["routes"] + x["paths"]))

    # Ownerless Risk: assets where NO open finding is owned or decided through its route or a
    # path (build 496: from the per-finding zipper, so an asset owned through a path counts)
    _z = b.get("zip_raw") or {}
    all_assets = set(_z.get("assets_all") or ())
    unowned_assets = len(all_assets - set(_z.get("assets_covered") or ()))

    def kc(items, s):
        return sum(1 for i in items if i["status"] == s)

    # disposition tallies across routes+paths, with a % of the whole surface (items)
    surface = routes + paths
    n_items = len(surface) or 1
    n_ignored = sum(1 for i in surface if i["status"] == "ignored")
    n_accepted = sum(1 for i in surface if i["status"] == "accepted")
    n_mitigated = sum(1 for i in surface if i["status"] == "mitigated")
    # paths covered (fully or partly) THROUGH a route, with no Owner tag of their own
    paths_via_route = sum(1 for p in paths if p.get("inherited"))

    def _pct(n):
        return round(100.0 * n / n_items, 1)

    # ===== Reduction funnel + champion plugin — the workload-reduction story:
    # CVE line-items -> findings -> plugins -> apps/routes. People chase CVEs (the most
    # duplicated work); owning apps collapses that. Champion = one fix clearing the most CVEs.
    funnel, champion = {}, None
    if q("SELECT name FROM sqlite_master WHERE type='table' AND name='plugins'"):
        # the plugins present in vulns, read ONCE from the narrow hx_v_plugin index (it was a
        # DISTINCT over the table, twice) and handed to both statements as a JSON list
        _ib = db.indexed_by("hx_v_plugin", db_path)
        _present = None
        # build 496: paths = the distinct paths of OPEN findings (the same set as the map)
        _paths_sql, _routes_sql, _fa = "(SELECT %d)" % len(b.get("path_assets") or {}), "(SELECT COUNT(DISTINCT app_name) FROM vuln_route)", ()
        if scope:
            # a tag view: the funnel over the tag's findings, paths and routes only
            _ff, _fa = _sf(scope, "asset_uuid")
            try:
                _present = _json.dumps([r["plugin_id"] for r in db.query(
                    "SELECT DISTINCT plugin_id FROM vulns WHERE 1=1" + _ff, _fa, path=db_path, budget="job")])
                _findings = "(SELECT %d)" % int(db.scalar("SELECT COUNT(*) FROM vulns WHERE 1=1" + _ff, _fa,
                                                          path=db_path, budget="job") or 0)
            except db.QueryTimeout:
                raise
            except Exception:
                _present, _findings = "[]", "(SELECT 0)"
            _routes_sql = "(SELECT %d)" % len(b.get("apps") or [])
            _fa = ()                                  # no placeholders left in the funnel SQL
        elif hx_summary.usable(db_path):
            # ⚡ Optimize's hx_plugin: the present plugins and their finding counts without a
            # DISTINCT over the index or a COUNT(*) over vulns. Rows whose plugin_id is NULL (not
            # in hx_plugin) are added back exactly — one covered range on hx_v_plugin.
            try:
                _nulls = int(db.scalar("SELECT COUNT(*) FROM vulns" + _ib + " WHERE plugin_id IS NULL",
                                       path=db_path) or 0)
                _present = _json.dumps([r["plugin_id"] for r in
                                        db.query("SELECT plugin_id FROM hx_plugin", path=db_path)]
                                       + ([None] if _nulls else []))
                _findings = "(SELECT COALESCE(SUM(findings),0) + %d FROM hx_plugin)" % _nulls
            except db.QueryTimeout:
                raise
            except Exception:
                _present = None
        if _present is None:
            _present = _json.dumps([r["plugin_id"] for r in q("SELECT DISTINCT plugin_id FROM vulns" + _ib)])
            _findings = "(SELECT COUNT(*) FROM vulns)"
        _pw = "WITH present AS (SELECT value AS plugin_id FROM json_each(?)) "
        fr = q(_pw +
               "SELECT " + _findings + " findings,(SELECT COUNT(*) FROM present) plugins,"
               + _paths_sql + " paths," + _routes_sql + " routes,"
               "(SELECT SUM((length(p.cves)-length(replace(p.cves,'CVE-','')))/4) FROM plugins p "
               "JOIN present ON present.plugin_id=p.plugin_id WHERE p.cves IS NOT NULL AND p.cves NOT IN ('','[]','None')) cves",
               (_present,) + tuple(_fa))
        if fr:
            row = fr[0]
            funnel = {"cves": int(row.get("cves") or 0), "findings": int(row.get("findings") or 0),
                      "plugins": int(row.get("plugins") or 0), "paths": int(row.get("paths") or 0),
                      "routes": int(row.get("routes") or 0)}
        cr = q(_pw +
               "SELECT p.plugin_id,p.name,(length(p.cves)-length(replace(p.cves,'CVE-','')))/4 cve_count "
               "FROM plugins p JOIN present ON present.plugin_id=p.plugin_id "
               "WHERE p.cves IS NOT NULL AND p.cves NOT IN ('','[]','None') ORDER BY cve_count DESC LIMIT 1",
               (_present,))
        if cr:
            c = cr[0]
            champion = {"plugin_id": c.get("plugin_id"), "name": c.get("name"),
                        "cve_count": int(c.get("cve_count") or 0),
                        # per-plugin asset count from _base's one scan (a correlated
                        # COUNT(DISTINCT) per plugin was the slowest query on big tenants)
                        "assets": plugin_assets(b, c.get("plugin_id"), db_path)}

    # Owner tags that DON'T map to any route or path — surfaced (not silently dropped) so
    # you can see exactly what's not landing on the Sankey and why. These are usually tags
    # whose app-name was truncated/abbreviated differently from navi's route app_name
    # (e.g. 'WEB SERVER' vs 'Web Server Allows', 'ROCKWELL AUTOMATION' vs 'Rockwell
    # Automation RSLinx'). We suggest the closest route/path but never auto-attach — a wrong
    # owner is worse than a visible gap. Re-tag with the exact route name to land them.
    graph_keys = {_nk(r["name"]) for r in routes} | {_nk(p["name"]) for p in paths}
    pool = [r["name"] for r in routes] + [p["name"] for p in paths]

    def _closest(nm):
        n = _nk(nm)
        pre = [x for x in pool if _nk(x).startswith(n) or n.startswith(_nk(x))]
        cand = pre or [x for x in pool if n and (n in _nk(x) or _nk(x) in n)]
        return sorted(set(cand), key=len)[:2]

    unmatched = [{"name": name_display.get(k, k), "owners": sorted(ow),
                  "assets": len(name_assets.get(k, set())), "suggestions": _closest(name_display.get(k, k))}
                 for k, ow in name_owners.items() if k not in graph_keys]
    unmatched.sort(key=lambda x: -x["assets"])

    _vpr_vals = [it["vpr"] for it in routes + paths if it.get("vpr") is not None]
    _cvss_vals = [it["cvss3"] for it in routes + paths if it.get("cvss3") is not None]
    out = {"ok": True, "routes": routes, "paths": paths,
            "owners": sorted({o for it in routes + paths for o in it["owners"]}),
            "owner_load": owner_load, "unmatched_owners": unmatched,
            "route_paths": route_paths_list, "orphan_paths": orphan_paths,
            "funnel": funnel, "champion": champion,
            "scores": {"vpr": bool(_vpr_vals), "cvss3": bool(_cvss_vals),
                       "vpr_max": round(max(_vpr_vals), 1) if _vpr_vals else None,
                       "cvss3_max": round(max(_cvss_vals), 1) if _cvss_vals else None},
            "kpi": {"routes": len(routes), "routes_unowned": kc(routes, "unowned"),
                    "routes_partial": kc(routes, "partial"), "routes_owned": kc(routes, "owned"),
                    "paths": len(paths), "paths_unowned": kc(paths, "unowned"),
                    "paths_partial": kc(paths, "partial"), "paths_owned": kc(paths, "owned"),
                    "paths_via_route": int(paths_via_route),
                    # direct assignments (an Owner tag of its own) — the method, not the coverage
                    "routes_assigned": sum(1 for r in routes if r.get("assigned")),
                    "paths_assigned": sum(1 for p in paths if p.get("assigned")),
                    "owners": len(owner_load), "unowned_assets": unowned_assets,
                    "ignored": n_ignored, "ignored_pct": _pct(n_ignored),
                    "accepted": n_accepted, "accepted_pct": _pct(n_accepted),
                    "mitigated": n_mitigated, "mitigated_pct": _pct(n_mitigated),
                    "routes_ignored": kc(routes, "ignored"), "paths_ignored": kc(paths, "ignored"),
                    "routes_accepted": kc(routes, "accepted"), "paths_accepted": kc(paths, "accepted"),
                    "routes_mitigated": kc(routes, "mitigated"), "paths_mitigated": kc(paths, "mitigated"),
                    "owners_unmatched": len(unmatched), "asset_scope": len(all_assets),
                    "routes_no_paths": sum(1 for r in routes if r.get("paths_on_route", 0) == 0),
                    "routes_with_paths": sum(1 for r in routes if r.get("paths_on_route", 0) > 0),
                    "paths_orphan": len(orphan_paths),
                    "paths_covered": sum(1 for p in paths if p.get("on_route"))}}
    if scope:
        out["scope"] = tagscope.describe(scope[0], scope[1], db_path)
    return out


def path_detail(path, scope=None):
    """Drill-down for a single filesystem path (a newly-found gap): which assets carry it,
    their findings/plugins, and the owner(s) of the app(s) that cover it — so Gabriel can
    email the gap to the right person."""
    from core import db
    if not path:
        return {"ok": False, "error": "path required"}
    dbp = db.db_path()

    def q(sql, args=()):
        try:
            return list(db.query(sql, args, path=dbp))
        except Exception:
            return []

    _sfr, _sar = _sf(scope, "vp.asset_uuid")
    # build 498: only OPEN, non-info findings (vuln_paths also keeps fixed findings' paths) —
    # the same rows Exposure Routes' coverage counts (core/hx_rpp)
    try:
        from core import hx_rpp
        _vc = {r["name"] for r in q('SELECT name FROM pragma_table_info("vulns")')}
        _open = (" AND EXISTS (SELECT 1 FROM vulns WHERE vulns.plugin_id = vp.plugin_id AND vulns.asset_uuid = vp.asset_uuid AND "
                 + hx_rpp.finding_where(_vc).replace("plugin_id IS NOT NULL AND asset_uuid IS NOT NULL", "1=1")
                 .replace("state", "vulns.state").replace("severity", "vulns.severity") + ")") if _vc else ""
    except Exception:
        _open = ""
    rows = q("SELECT vp.asset_uuid au, vp.plugin_id pid, vp.finding_id fid, a.hostname host, "
             "a.ip_address ip, a.acr acr, a.url url FROM vuln_paths vp "
             "LEFT JOIN assets a ON a.uuid=vp.asset_uuid WHERE vp.path=?" + _open + _sfr, (path,) + tuple(_sar))
    by, findings, plugins = {}, set(), set()
    for r in rows:
        u = r.get("au")
        e = by.setdefault(u, {"uuid": u, "hostname": r.get("host"), "ip": r.get("ip"),
                              "acr": r.get("acr"), "url": r.get("url"), "plugins": set(), "findings": set()})
        if r.get("pid"):
            e["plugins"].add(str(r["pid"])); plugins.add(str(r["pid"]))
        if r.get("fid"):
            e["findings"].add(str(r["fid"])); findings.add(str(r["fid"]))
    assets = [{"uuid": e["uuid"], "hostname": e["hostname"], "ip": e["ip"], "acr": e["acr"],
               "url": e["url"], "plugins": len(e["plugins"]), "findings": sorted(e["findings"])}
              for e in by.values()]
    assets.sort(key=lambda x: -(float(x["acr"]) if x["acr"] else 0))
    # the routes of the plugins found here (each plugin has one route)
    try:
        from core import hx_rpp
        import contextlib as _cl
        with _cl.closing(db.connect(dbp)) as _c:
            _rm = hx_rpp.route_map(_c)
        apps = sorted({_rm[p][1] for p in plugins if p in _rm})
    except Exception:
        apps = []
    # who covers this path ON ITS ASSETS (build 498): its own Owner tag, or the Owner tag of the
    # route its plugins belong to — routes and paths are both ways the plugin gets assigned
    owners, direct, via = set(), set(), set()
    names = {_nk(path): "path"} | {_nk(a): "route" for a in apps}
    aus = [a["uuid"] for a in assets if a.get("uuid")]
    for i in range(0, len(aus), 900):
        part = aus[i:i + 900]
        for r in q("SELECT tag_value FROM tags WHERE " + tagname.sql_lit("tag_key", "Owner") + " AND tag_value IS NOT NULL "
                   "AND asset_uuid IN (%s)" % ",".join("?" * len(part)), tuple(part)):
            val = (r.get("tag_value") or "").strip()
            if ": " in val:
                nm, us = val.rsplit(": ", 1)
                kind = names.get(_nk(nm))
                if kind and us.strip() and not disposition_label(us.strip()):
                    owners.add(us.strip())
                    (direct if kind == "path" else via).add(us.strip())
    pnames = {}
    if plugins:
        for r in q("SELECT plugin_id, plugin_name FROM vulns WHERE rowid IN (SELECT MIN(rowid) FROM vulns "
                   "WHERE plugin_id IN (SELECT value FROM json_each(?)) GROUP BY plugin_id)", (_json.dumps(sorted(plugins)),)):
            pnames[str(r.get("plugin_id"))] = r.get("plugin_name") or ""
    out = {"ok": True, "path": path, "apps": sorted(apps), "owners": sorted(owners),
           "path_owners": sorted(direct), "route_owners": sorted(via),
           "plugin_names": pnames,
           "assets": assets, "plugins": sorted(plugins), "findings": sorted(findings),
           "asset_count": len(assets)}
    if scope:
        out["scope"] = tagscope.describe(scope[0], scope[1], dbp)
    return out


# ===================================================================================
# Snapshot — everything the page shows (owners, routes, paths, coverage, the ownership
# map) built in ONE pass, cached on disk and in memory, keyed by navi.db's signature
# (size + mtime of the db and its -wal). A navi update changes the signature, so the next
# Run rebuilds; until then a Run — or reopening the page — is instant. Builds run on the
# job queue, so leaving the page doesn't stop them. The owner directory (a live Tenable
# API call through navi) is cached separately for OWNERS_TTL.
# ===================================================================================

CACHE_DIR = os.environ.get("NAVI_CACHE_DIR") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "cache")
OWNERS_TTL = float(os.environ.get("NAVI_OWNERS_TTL_S", str(6 * 3600)))
SNAP_VERSION = 2   # 496: + zip (route/path/plugin zipper); open non-info findings only
_SNAP_MEM = {}            # key -> snapshot dict
_BUILDING = {}            # key -> {"job_id", "started"}
_SLOCK = threading.Lock()
# Build 489: a tag view's snapshot is its own store — keyed by navi.db + the tag, the newest 5
# kept — so a tag view never serves (or evicts) the whole estate's snapshot, nor the reverse.
SNAP_TAG = snapcache.Snapshots("exproute_tag", version=SNAP_VERSION, keep=5)


def _tag_extra(scope):
    return {"scope": {"tag_key": scope[0], "tag_value": scope[1]}}


def _cache_path(name):
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    return os.path.join(CACHE_DIR, name)


def _atomic_write(path, data: bytes):
    tmp = path + ".tmp"
    with _popen(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _db_file(db_path=None):
    try:
        return os.path.abspath(db_path or db.db_path())
    except Exception:
        return ""


def db_signature(db_path=None) -> str:
    p = _db_file(db_path)
    parts = []
    for fp in (p, p + "-wal"):
        try:
            st = os.stat(fp)
            parts.append(f"{st.st_size}:{st.st_mtime_ns}")
        except OSError:
            parts.append("-")
    return "|".join(parts)


def _snap_key(db_path=None):
    return hashlib.sha1(_db_file(db_path).encode()).hexdigest()[:16]


def owners_cached(refresh=False):
    """(owners, fetched_at). The live navi pull is cached on disk for OWNERS_TTL; a failed
    or empty live pull keeps the last good list rather than wiping it."""
    path = _cache_path("exproute_owners.json")
    old = None
    try:
        with open(path, encoding="utf-8") as f:
            old = _json.load(f)
    except Exception:
        old = None
    if old and not refresh and (_time.time() - float(old.get("at", 0))) < OWNERS_TTL:
        return old.get("owners") or [], float(old["at"])
    live = _owners_live()
    if not live and old:
        return old.get("owners") or [], float(old.get("at", 0))
    now = _time.time()
    try:
        _atomic_write(path, _json.dumps({"at": now, "owners": live}).encode())
    except Exception:
        pass
    return live, now


def _iso(ts):
    try:
        return datetime.datetime.fromtimestamp(float(ts)).astimezone().isoformat(timespec="seconds")
    except Exception:
        return None


def _load_snapshot(key, sig):
    s = _SNAP_MEM.get(key)
    if s and s.get("meta", {}).get("sig") == sig:
        return s
    try:
        with gzip.open(_cache_path(f"exproute_{key}.json.gz"), "rt", encoding="utf-8") as f:
            s = _json.load(f)
    except Exception:
        return None
    if s.get("meta", {}).get("sig") != sig or s.get("meta", {}).get("v") != SNAP_VERSION:
        return None
    _SNAP_MEM.clear()
    _SNAP_MEM[key] = s
    return s


def _save_snapshot(key, s):
    _SNAP_MEM.clear()
    _SNAP_MEM[key] = s
    try:
        _atomic_write(_cache_path(f"exproute_{key}.json.gz"),
                      gzip.compress(_json.dumps(s, default=list).encode("utf-8"), 5))
    except Exception:
        pass


def build_snapshot(db_path=None, refresh_owners=False, scope=None) -> dict:
    """The whole estate (saved to the estate store) or, with scope=(tag_key, tag_value), one
    tag's assets (returned — SNAP_TAG saves it under the tag's own key)."""
    t0 = _time.time()
    sig = db_signature(db_path)
    b = _base(db_path, scope)
    om = ownership_map(db_path, base=b)
    ow, ow_at = owners_cached(refresh_owners)
    cov = coverage(db_path, base=b, om=om, users_total=sum(1 for o in ow if o.get("type") == "user"))
    rt, pa = routes(db_path, scope), paths(db_path, scope)
    snap = {"load": {"owners": ow, "routes": rt, "paths": pa,
                     "counts": {"owners": len(ow), "routes": len(rt), "paths": len(pa)}},
            "coverage": cov, "map": om, "zip": zipper(b, db_path),
            "meta": {"v": SNAP_VERSION, "sig": sig, "db": _db_file(db_path),
                     "built_at": _iso(t0), "build_sec": round(_time.time() - t0, 2),
                     "owners_at": _iso(ow_at)}}
    if scope:
        snap["scope"] = snap["meta"]["scope"] = tagscope.describe(scope[0], scope[1], db_path)
        return snap
    _save_snapshot(_snap_key(db_path), snap)
    return snap


def snapshot_state(db_path=None, scope=None) -> dict:
    """What the page can show right now without computing anything."""
    if scope:
        st = SNAP_TAG.state(db_path, _tag_extra(scope))
        return {"snap": (st["snap"] or {}).get("result"), "building": st["building"], "key": st["key"]}
    key, sig = _snap_key(db_path), db_signature(db_path)
    s = _load_snapshot(key, sig)
    with _SLOCK:
        bld = dict(_BUILDING.get(key) or {})
    return {"snap": s, "building": bld or None, "key": key}


def note_run(rid, ok=True, ms=0, cached=False):
    """Build 498: a ▶ Run on this page is a run in "Done so far" (core.activity) like every other
    specialist's — recorded when the snapshot it asked for is READY (built, failed, or served from
    cache), with the real build time. The page opts out of the page cache, so the console's
    automatic run marker never reaches the server; it sends its own `record_run` id instead.
    Run the Ensemble records its own runs (core/release.py) and never passes one."""
    if not rid:
        return
    try:
        from core import activity
        activity.note_run("exproute", "snapshot", ok=bool(ok), ms=float(ms or 0), cached=bool(cached), rid=str(rid)[:40])
    except Exception:
        pass


def _recorded(fn, rid):
    """Wrap a build so it records the run when it ends (ok / failed, with its duration)."""
    if not rid:
        return fn

    def _go():
        t0 = _time.time()
        ok = False
        try:
            out = fn()
            ok = not (isinstance(out, dict) and out.get("ok") is False)
            return out
        finally:
            note_run(rid, ok=ok, ms=(_time.time() - t0) * 1000)
    return _go


def start_build(submit, db_path=None, refresh_owners=False, scope=None, record_run=None) -> dict:
    """Start (or join) the background build. `submit(fn)` puts fn on the job queue and
    returns the job stub. One build per navi.db at a time (per tag, for a tag view).
    record_run: the page's run id — the run is recorded in Done so far when the build ends."""
    if scope:
        return SNAP_TAG.start(submit, _recorded(lambda: build_snapshot(db_path, refresh_owners=refresh_owners, scope=scope),
                                                record_run),
                              db_path, _tag_extra(scope), label=f"Ownership snapshot · {scope[0]} : {scope[1]}")
    key = _snap_key(db_path)
    with _SLOCK:
        if key in _BUILDING:
            return dict(_BUILDING[key])

        @functools.partial(_recorded, rid=record_run)
        def _work():
            try:
                s = build_snapshot(db_path, refresh_owners=refresh_owners)
                m = s["meta"]
                return {"ok": True, "ready": True, "build_sec": m["build_sec"],
                        "message": f"ownership snapshot built in {m['build_sec']}s"}
            finally:
                with _SLOCK:
                    _BUILDING.pop(key, None)
        job = submit(_work)
        _BUILDING[key] = {"job_id": job.get("id"), "started": _iso(_time.time())}
        return dict(_BUILDING[key])


class ExpRouteAgent(Agent):
    id = "exproute"
    name = "Exposure Routes"
    icon = "🧭"
    description = ("Pulls users & groups (navi, Tenable MCP backup) and maps exposure "
                  "routes & paths to owners from plain English; tags Owner:<group/user>.")

    def summary(self):
        if not self.result:
            return {}
        c = self.result.get("counts", {})
        return {"owners": c.get("owners"), "routes": c.get("routes"), "paths": c.get("paths")}

    def _run(self, db_path=None, **kwargs):
        ow, rt, pa = owners(), routes(db_path), paths(db_path)
        return {"owners": ow, "routes": rt, "paths": pa,
                "counts": {"owners": len(ow), "routes": len(rt), "paths": len(pa)}}
