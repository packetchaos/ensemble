"""Dashboard boards on the server (build 509) — the Dashboards app's store, runner and cache.

A board is a layout of widget REFERENCES (core/widgets) plus a board-level tag scope:

  {id, name, rev, kind, layout: {cols, row, maxw, gap, dense},
   scope: {terms: [...]},
   widgets: [{iid, ref, w, h, title?, viz?, scope?(pinned), text?}]}

The array order is the layout order (the grid packs left→right, top→bottom); w is a column span
(1..cols), h a row span (1..MAX_H). Boards live in their own SQLite file (NAVI_BOARDS_DB, else
boards.db beside the Tagging log) — app state, never navi.db, which stays read-only. No board cap.

Running is explicit: `cached()` answers a whole board from the result cache without touching
navi.db; `run_widget()` runs one widget (the page queues them on ▶ Run stale / ▶ Run). Each result
is cached per (expanded SQL) and stamped with the navi.db fingerprint it ran on, so a board shows
"navi.db synced since" instead of passing an old number off as current.

Imported SQL never runs unseen: a SQL widget that arrives in an import is saved with review=1 and
run_widget refuses it until someone approves it after reading its SQL (`approve`).
Exports carry definitions only (layout, scope, SQL) — never cached rows.
"""
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time

from core import dashmetrics, db, widgets

MAX_COLS = 24
MAX_H = 16
MAX_WIDGETS = 120
NAME_MAX = 120
STALE_S = 24 * 3600
_LOCK = threading.Lock()
_OK = set()


def path():
    p = os.environ.get("NAVI_BOARDS_DB")
    if p:
        return p
    from core import tagq
    return os.path.join(os.path.dirname(os.path.abspath(tagq._DBPATH)), "boards.db")


def _con():
    p = path()
    con = sqlite3.connect(p, timeout=10.0)
    con.row_factory = sqlite3.Row
    if p not in _OK:
        with _LOCK:
            con.executescript(
                "PRAGMA journal_mode=WAL;"
                "CREATE TABLE IF NOT EXISTS boards(id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT, "
                "  is_default INTEGER DEFAULT 0, rev INTEGER DEFAULT 1, body TEXT NOT NULL, "
                "  created REAL, updated REAL);"
                "CREATE TABLE IF NOT EXISTS sqlwidgets(id TEXT PRIMARY KEY, title TEXT, note TEXT, viz TEXT, "
                "  sql TEXT NOT NULL, drill TEXT, label_col TEXT, value_col TEXT, w INTEGER, h INTEGER, "
                "  review INTEGER DEFAULT 0, origin TEXT, created REAL, updated REAL);"
                "CREATE TABLE IF NOT EXISTS wcache(key TEXT PRIMARY KEY, at REAL, body TEXT);"
                "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);"
                "CREATE TABLE IF NOT EXISTS trend(key TEXT, day TEXT, v REAL, at REAL, PRIMARY KEY(key, day)) WITHOUT ROWID;"
                "CREATE TABLE IF NOT EXISTS audit(at REAL, who TEXT, what TEXT, board TEXT, detail TEXT);")
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
            _OK.add(p)
    return con


def _audit(con, what, board="", detail=""):
    try:
        from core import gates
        who = "loopback" if gates.client_is_loopback() else "remote"
    except Exception:
        who = ""
    con.execute("INSERT INTO audit VALUES (?,?,?,?,?)", (time.time(), who, what, board, str(detail)[:500]))
    con.execute("DELETE FROM audit WHERE rowid NOT IN (SELECT rowid FROM audit ORDER BY at DESC LIMIT 2000)")


def _nid(prefix):
    return prefix + secrets.token_hex(5)


# ── layout normalisation ─────────────────────────────────────────────────────────────────────
DEFAULT_LAYOUT = {"cols": 12, "row": 90, "maxw": 0, "gap": "comfortable", "dense": True, "daily": False}
TREND_DAYS = 90


def norm_layout(lay):
    lay = lay if isinstance(lay, dict) else {}
    out = dict(DEFAULT_LAYOUT)
    try:
        out["cols"] = max(1, min(MAX_COLS, int(lay.get("cols", out["cols"]))))
    except (TypeError, ValueError):
        pass
    try:
        out["row"] = max(40, min(240, int(lay.get("row", out["row"]))))
    except (TypeError, ValueError):
        pass
    try:
        mw = int(lay.get("maxw", 0) or 0)
        out["maxw"] = 0 if mw <= 0 else max(720, min(4000, mw))
    except (TypeError, ValueError):
        pass
    out["gap"] = lay.get("gap") if lay.get("gap") in ("compact", "comfortable", "spacious") else out["gap"]
    out["dense"] = bool(lay.get("dense", True))
    out["daily"] = bool(lay.get("daily", False))
    return out


def norm_widget(w, cols):
    if not isinstance(w, dict):
        raise ValueError("a widget is {iid, ref, w, h}")
    ref = str(w.get("ref") or "")
    if not re.match(r"^[a-z0-9_]+\.[A-Za-z0-9_\-]+$", ref):
        raise ValueError(f"bad widget ref {ref!r}")
    iid = str(w.get("iid") or "") or _nid("w")
    if not re.match(r"^[A-Za-z0-9_\-]{1,40}$", iid):
        iid = _nid("w")
    out = {"iid": iid, "ref": ref}
    try:
        out["w"] = max(1, min(cols, int(w.get("w") or 3)))
    except (TypeError, ValueError):
        out["w"] = min(3, cols)
    try:
        out["h"] = max(1, min(MAX_H, int(w.get("h") or 2)))
    except (TypeError, ValueError):
        out["h"] = 2
    for k, n in (("title", NAME_MAX), ("text", 400)):
        v = w.get(k)
        if isinstance(v, str) and v.strip():
            out[k] = v.strip()[:n]
    if w.get("viz") in widgets.VIZ:
        out["viz"] = w["viz"]
    if w.get("scope") not in (None, "", {}):
        out["scope"] = dashmetrics.norm_scope(w["scope"])
    return out


def norm_board(b):
    if not isinstance(b, dict):
        raise ValueError("board must be an object")
    name = str(b.get("name") or "").strip()[:NAME_MAX] or "Untitled board"
    lay = norm_layout(b.get("layout"))
    ws = b.get("widgets") or []
    if not isinstance(ws, list):
        raise ValueError("widgets must be a list")
    if len(ws) > MAX_WIDGETS:
        raise ValueError(f"at most {MAX_WIDGETS} widgets on a board")
    seen, out = set(), []
    for w in ws:
        n = norm_widget(w, lay["cols"])
        if n["iid"] in seen:
            n["iid"] = _nid("w")
        seen.add(n["iid"])
        out.append(n)
    return {"name": name, "layout": lay, "scope": dashmetrics.norm_scope(b.get("scope")), "widgets": out}


# ── templates ────────────────────────────────────────────────────────────────────────────────
def _h(text, cols=12):
    return {"ref": "text.heading", "w": cols, "h": 1, "text": text}


def _w(ref, w=None, h=None):
    d = widgets.builtin().get(ref, {})
    return {"ref": ref, "w": w or d.get("w", 3), "h": h or d.get("h", 2)}


def templates():
    """name → board body. The Ensemble wall is the default landing board."""
    return {
        "ensemble_wall": {
            "name": "Ensemble wall", "kind": "template:ensemble_wall",
            "layout": dict(DEFAULT_LAYOUT),
            "widgets": [
                _h("Triage — what needs action today"),
                _w("preset.kev_assets"), _w("preset.crown_kev"), _w("preset.exploitable", 3),
                _w("preset.assets_in_scope", 3),
                _w("preset.kev_plugins", 6, 4), _w("preset.top_assets", 6, 4),
                _h("Operations — backlog, coverage and ownership"),
                _w("preset.cred_coverage", 3, 3), _w("preset.blind_hosts", 3, 3), _w("preset.ownerless", 3, 3),
                _w("preset.stale_assets", 3, 3),
                _w("preset.owner_open_crit", 6, 4), _w("preset.fix_leverage", 6, 4),
                _h("Board — posture the CISO reports"),
                _w("preset.sev_mix", 4, 3), _w("preset.unpatchable_pct", 4, 3), _w("preset.crown_jewels", 4, 3),
                _h("From the specialists' last runs"),
                _w("cisakev.kev_overdue", 3), _w("cisakev.kev_due", 6, 3), _w("cisakev.kev_ransomware", 3),
                _h("Hygiene — certificates and lifecycle"),
                _w("preset.cert_expiry", 4, 3), _w("preset.weak_keys", 4, 3), _w("preset.eol_products", 4, 3),
            ]},
        "program": {
            "name": "Program board", "kind": "template:program", "layout": dict(DEFAULT_LAYOUT),
            "widgets": [
                _w("preset.assets_in_scope"), _w("preset.kev_assets"), _w("preset.crown_kev"),
                _w("preset.unpatchable_pct"),
                _w("preset.sev_mix", 4, 3), _w("preset.cred_coverage", 4, 3), _w("preset.ownership_split", 4, 3),
                _w("preset.fix_leverage", 6, 4), _w("preset.owner_open_crit", 6, 4)]},
        "compliance": {
            "name": "Compliance board", "kind": "template:compliance", "layout": dict(DEFAULT_LAYOUT),
            "widgets": [
                _w("compliance.pass_rate", 3, 3), _w("compliance.failed_checks", 3, 3),
                _w("compliance.failing_assets", 3, 3), _w("preset.assets_in_scope", 3, 3),
                _w("compliance.failed_by_audit", 6, 4), _w("compliance.top_failing_checks", 6, 4),
                _w("compliance.weakest_assets", 12, 4)]},
        "certificates": {
            "name": "Certificates board", "kind": "template:certificates", "layout": dict(DEFAULT_LAYOUT),
            "widgets": [
                _w("certificate.expired", 3), _w("certificate.expiring_30", 3), _w("preset.weak_keys", 3),
                _w("certificate.cert_total", 3),
                _w("certificate.expiry_by_month", 8, 4), _w("preset.cert_expiry", 4, 4),
                _w("preset.cert_sig", 6, 4), _w("certificate.top_issuers", 6, 4)]},
        "ownership_analytics": {
            "name": "Ownership analytics", "kind": "template:ownership_analytics", "layout": dict(DEFAULT_LAYOUT),
            "widgets": [
                _h("Who owns the exposure — routes × tags × device type"),
                _w("preset.route_coverage", 3, 4), _w("preset.routes_by_device_type", 9, 4),
                _w("preset.routes_most_unowned", 6, 4), _w("preset.unowned_heatmap", 6, 4),
                _h("Where it matters most"),
                _w("preset.crown_unowned_route", 3, 4), _w("preset.kev_unowned_routes", 9, 4),
                _w("preset.routes_by_tier", 6, 4), _w("preset.paths_by_os", 6, 4),
                _w("preset.owner_workload", 12, 4)]},
        "blank": {"name": "New board", "kind": "user", "layout": dict(DEFAULT_LAYOUT), "widgets": []},
    }


def _seed(con):
    if con.execute("SELECT v FROM meta WHERE k='seeded'").fetchone():
        return
    now = time.time()
    for i, key in enumerate(("ensemble_wall", "program")):
        t = templates()[key]
        body = norm_board(t)
        con.execute("INSERT INTO boards VALUES (?,?,?,?,?,?,?,?)",
                    (_nid("b"), body["name"], t["kind"], 1 if i == 0 else 0, 1, json.dumps(body), now, now))
    con.execute("INSERT OR REPLACE INTO meta VALUES ('seeded', ?)", (str(now),))
    con.commit()


# ── CRUD ─────────────────────────────────────────────────────────────────────────────────────
def _row(r):
    body = json.loads(r["body"])
    body.update({"id": r["id"], "rev": r["rev"], "kind": r["kind"], "is_default": bool(r["is_default"]),
                 "updated": r["updated"]})
    return body


def list_boards():
    con = _con()
    try:
        _seed(con)
        rows = con.execute("SELECT * FROM boards ORDER BY is_default DESC, name COLLATE NOCASE").fetchall()
        return [{"id": r["id"], "name": r["name"], "kind": r["kind"], "is_default": bool(r["is_default"]),
                 "updated": r["updated"], "widgets": len(json.loads(r["body"]).get("widgets") or [])}
                for r in rows]
    finally:
        con.close()


def get(bid):
    con = _con()
    try:
        _seed(con)
        if not bid:
            r = con.execute("SELECT * FROM boards ORDER BY is_default DESC, updated DESC LIMIT 1").fetchone()
        else:
            r = con.execute("SELECT * FROM boards WHERE id=?", (str(bid),)).fetchone()
        return _row(r) if r else None
    finally:
        con.close()


def save(b):
    """Save a board's name / layout / scope / widgets. Optimistic: a stale `rev` is refused (409)
    so two tabs can't silently overwrite each other."""
    bid = str((b or {}).get("id") or "")
    body = norm_board(b)
    con = _con()
    try:
        r = con.execute("SELECT rev FROM boards WHERE id=?", (bid,)).fetchone()
        if not r:
            return None, "no such board"
        if b.get("rev") is not None:
            # compare-and-set in ONE statement: two saves carrying the same rev can't both win
            cur = con.execute("UPDATE boards SET name=?, body=?, rev=rev+1, updated=? WHERE id=? AND rev=?",
                              (body["name"], json.dumps(body), time.time(), bid, int(b.get("rev"))))
            if cur.rowcount == 0:
                return None, "conflict"
        else:
            con.execute("UPDATE boards SET name=?, body=?, rev=rev+1, updated=? WHERE id=?",
                        (body["name"], json.dumps(body), time.time(), bid))
        _audit(con, "save", bid, f"{len(body['widgets'])} widgets")
        con.commit()
    finally:
        con.close()
    return get(bid), None


def create(name=None, template="blank", copy_of=None):
    if copy_of:
        src = get(copy_of)
        if not src:
            raise ValueError("no such board to copy")
        t = {k: src[k] for k in ("layout", "scope", "widgets")}
        t["name"] = (name or (src["name"] + " (copy)"))
        kind = "user"
    else:
        tp = templates().get(template) or templates()["blank"]
        t = dict(tp)
        if name:
            t["name"] = name
        kind = tp.get("kind", "user")
    body = norm_board(t)
    now, bid = time.time(), _nid("b")
    con = _con()
    try:
        _seed(con)
        con.execute("INSERT INTO boards VALUES (?,?,?,?,?,?,?,?)",
                    (bid, body["name"], kind, 0, 1, json.dumps(body), now, now))
        _audit(con, "create", bid, template or "copy")
        con.commit()
    finally:
        con.close()
    return get(bid)


def delete(bid):
    con = _con()
    try:
        r = con.execute("SELECT is_default FROM boards WHERE id=?", (str(bid),)).fetchone()
        if not r:
            return False
        con.execute("DELETE FROM boards WHERE id=?", (str(bid),))
        if r["is_default"]:
            nxt = con.execute("SELECT id FROM boards ORDER BY updated DESC LIMIT 1").fetchone()
            if nxt:
                con.execute("UPDATE boards SET is_default=1 WHERE id=?", (nxt["id"],))
        _audit(con, "delete", str(bid))
        con.commit()
        return True
    finally:
        con.close()


def set_default(bid):
    con = _con()
    try:
        if not con.execute("SELECT 1 FROM boards WHERE id=?", (str(bid),)).fetchone():
            return False
        con.execute("UPDATE boards SET is_default=CASE WHEN id=? THEN 1 ELSE 0 END", (str(bid),))
        con.commit()
        return True
    finally:
        con.close()


# ── SQL widgets ("My SQL") ──────────────────────────────────────────────────────────────────
def _sqlw_def(r):
    return {"ref": "sql." + r["id"], "title": r["title"] or "SQL widget", "note": r["note"] or "",
            "group": "My SQL", "viz": r["viz"] if r["viz"] in widgets.VIZ else "table", "sql": r["sql"],
            "drill": r["drill"] or None, "label_col": r["label_col"] or None, "value_col": r["value_col"] or None,
            "w": r["w"] or 4, "h": r["h"] or 3, "review": bool(r["review"]), "origin": r["origin"] or "",
            "source": {"kind": "sql", "name": "My SQL"}}


def sql_widgets():
    con = _con()
    try:
        return [_sqlw_def(r) for r in con.execute("SELECT * FROM sqlwidgets ORDER BY title COLLATE NOCASE")]
    finally:
        con.close()


def save_sql_widget(d, origin="user", review=False):
    sql, err = widgets.check_sql(d.get("sql"))
    if err:
        raise ValueError(err)
    drill = None
    if d.get("drill"):
        drill, err = widgets.check_sql(d.get("drill"))
        if err:
            raise ValueError("drill SQL: " + err)
    try:
        dashmetrics.expand(sql)                     # unknown / malformed macros fail here
        if drill:
            dashmetrics.expand(drill)
    except ValueError as e:
        raise ValueError(str(e))
    sid = str(d.get("id") or "")
    if not re.match(r"^[A-Za-z0-9_\-]{4,40}$", sid):
        sid = _nid("q")
    now = time.time()
    title = (str(d.get("title") or "").strip() or "SQL widget")[:NAME_MAX]
    con = _con()
    try:
        old = con.execute("SELECT created, sql, review FROM sqlwidgets WHERE id=?", (sid,)).fetchone()
        # editing keeps a pending review pending unless a person is saving it (origin user)
        rv = 1 if review else 0
        con.execute("INSERT OR REPLACE INTO sqlwidgets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (sid, title, str(d.get("note") or "")[:400], d.get("viz") if d.get("viz") in widgets.VIZ
                     else "table", sql, drill, (d.get("label_col") or None), (d.get("value_col") or None),
                     int(d.get("w") or 4), int(d.get("h") or 3), rv, origin,
                     old["created"] if old else now, now))
        _audit(con, "sql_save", "", f"{sid} {title} ({origin}{', review' if rv else ''})")
        con.commit()
    finally:
        con.close()
    return "sql." + sid


def approve_sql(ref):
    sid = ref[4:] if ref.startswith("sql.") else ref
    con = _con()
    try:
        n = con.execute("UPDATE sqlwidgets SET review=0, updated=? WHERE id=?", (time.time(), sid)).rowcount
        _audit(con, "sql_approve", "", sid)
        con.commit()
        return bool(n)
    finally:
        con.close()


def delete_sql_widget(ref):
    sid = ref[4:] if ref.startswith("sql.") else ref
    con = _con()
    try:
        n = con.execute("DELETE FROM sqlwidgets WHERE id=?", (sid,)).rowcount
        con.commit()
        return bool(n)
    finally:
        con.close()


def definition(ref):
    if ref.startswith("sql."):
        con = _con()
        try:
            r = con.execute("SELECT * FROM sqlwidgets WHERE id=?", (ref[4:],)).fetchone()
        finally:
            con.close()
        return _sqlw_def(r) if r else None
    return widgets.builtin().get(ref)


def library():
    groups = {}
    order = []
    for d in list(widgets.builtin().values()) + sql_widgets():
        src = d["source"]["kind"]
        tab = {"preset": "presets", "specialist": "specialists", "sql": "mine", "layout": "presets"}[src]
        key = (tab, d.get("group") or "")
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(widgets.summary(d))
    return [{"tab": t, "group": g, "items": groups[(t, g)]} for (t, g) in order]


# ── running ──────────────────────────────────────────────────────────────────────────────────
def _find(board, iid):
    for w in board.get("widgets") or []:
        if w["iid"] == iid:
            return w
    return None


def resolve(board, iid):
    """(widget, definition, effective_scope, pinned) for a board's widget."""
    w = _find(board, iid)
    if not w:
        raise LookupError("no such widget on this board")
    d = definition(w["ref"])
    if not d:
        raise LookupError(f"widget {w['ref']} is no longer in the library")
    pinned = "scope" in w
    return w, d, (w["scope"] if pinned else board.get("scope")), pinned


def _ckey(sql):
    return hashlib.sha1(sql.encode()).hexdigest()


def prepare(d, scope, drill=False):
    """Expanded SQL (+display + info) for a definition under a scope."""
    src = (d.get("drill") or d["sql"]) if drill else d["sql"]
    clean, err = widgets.check_sql(src)
    if err:
        raise ValueError(err)
    full, disp, info = dashmetrics.expand(clean, scope)
    info["scope_label"] = dashmetrics.scope_label(scope) if info["scoped"] else "Whole estate (this widget ignores the scope)"
    info["scope_applied"] = info["scoped"] or not dashmetrics.norm_scope(scope)["terms"]
    return full, disp, info


def _state(body):
    """Freshness of a cached result: fresh · stale (over a day) · db_changed (navi.db synced since)."""
    if not body:
        return "not_run"
    if body.get("db_fp") and body.get("db_fp") != dashmetrics.fingerprint():
        return "db_changed"
    if time.time() - (body.get("at") or 0) > STALE_S:
        return "stale"
    return "fresh"


# ── specialist snapshots (build 510) ────────────────────────────────────────────────────────
_SNAPMEMO = {}


def _get_path(o, path):
    for part in str(path or "").split("."):
        if isinstance(o, dict) and part in o:
            o = o[part]
        elif isinstance(o, list) and part.isdigit() and int(part) < len(o):
            o = o[int(part)]
        else:
            return None
    return o


def _snap_target(scope):
    """(tag_key, tag_value) the scope is, (None, None) for the whole estate, or False when a
    specialist (one tag at a time) can't run on it."""
    terms = dashmetrics.norm_scope(scope)["terms"]
    if not terms:
        return None, None
    if len(terms) == 1 and terms[0]["op"] == "in" and len(terms[0]["values"]) == 1:
        return terms[0]["key"], terms[0]["values"][0]
    return False, False


def _snap_url(page, k, v):
    from urllib.parse import urlencode, quote
    return page + ("?" + urlencode({"tk": k, "tv": v}, quote_via=quote) if k else "")


def snapshot_result(d, scope):
    """A specialist widget's number from the specialist's own last run on this scope."""
    from urllib.parse import parse_qs
    from core import pagecache
    page = d["source"]["page"]
    k, v = _snap_target(scope)
    base = {"snapshot": True, "page": page, "specialist": d["source"].get("name")}
    if k is False:
        base.update({"state": "scope_unsupported", "open": page})
        return base
    base["open"] = _snap_url(page, k, v)
    key = None
    for it in pagecache.listing():
        kk = it.get("key") or ""
        path, _, q = kk.partition("?")
        if path != page:
            continue
        qs = parse_qs(q)
        tk, tv = (qs.get("tk") or [None])[0], (qs.get("tv") or [None])[0]
        if (tk or None, tv or None) == (k, v):
            key = kk
            break
    if not key:
        base["state"] = "not_run"
        return base
    m = pagecache.meta(key) or {}
    memo = _SNAPMEMO.get(key)
    if memo and memo[0] == m.get("at"):
        entry = memo[1]
    else:
        entry = pagecache.get(key)
        if entry:
            call = f"POST /api/{d['source']['agent']}/"
            entry = {"at": entry.get("at"), "resp": {rk: rv for rk, rv in (entry.get("resp") or {}).items()
                                                     if rk.startswith(call)}}
        _SNAPMEMO[key] = (m.get("at"), entry)
    if not entry:
        base["state"] = "not_run"
        return base
    snap = d["snapshot"]
    body = None
    for rk, rv in entry["resp"].items():
        if rk.startswith(f"POST /api/{d['source']['agent']}/{snap['call']} ") or rk == f"POST /api/{d['source']['agent']}/{snap['call']}":
            body = (rv or {}).get("body")
            break
    if not isinstance(body, dict):
        base["state"] = "not_run"
        return base
    if snap.get("paths"):
        rows = []
        for lbl, pth in snap["paths"]:
            val = _get_path(body, pth)
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                rows.append({"label": lbl, "value": val})
        cols = ["label", "value"]
    else:
        val = _get_path(body, snap.get("path"))
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            base.update({"state": "error", "error": "the specialist's last run has no value for this widget"})
            return base
        rows, cols = [{snap.get("label") or d["title"]: val}], [snap.get("label") or d["title"]]
    at = (entry.get("at") or 0) / 1000.0
    base.update({"rows": rows, "columns": cols, "count": len(rows), "at": at, "cached": True,
                 "state": "stale" if time.time() - at > STALE_S else "fresh"})
    _trend_note(f"snap:{key}:{d['ref']}", rows, at)
    base["trend"] = _trend_get(f"snap:{key}:{d['ref']}")
    return base


# ── trends: one point per KPI per day (build 510) ────────────────────────────────────────────
def _kpi_value(rows):
    if len(rows or []) != 1:
        return None
    for v in rows[0].values():
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return float(v)
        try:
            if isinstance(v, str) and v.strip():
                return float(v)
        except ValueError:
            continue
    return None


def _trend_note(key, rows, at=None):
    v = _kpi_value(rows)
    if v is None:
        return
    at = at or time.time()
    day = time.strftime("%Y-%m-%d", time.localtime(at))
    con = _con()
    try:
        con.execute("INSERT OR REPLACE INTO trend VALUES (?,?,?,?)", (key, day, v, at))
        con.execute("DELETE FROM trend WHERE key=? AND day < ?",
                    (key, time.strftime("%Y-%m-%d", time.localtime(time.time() - 400 * 86400))))
        con.commit()
    finally:
        con.close()


def _trend_get(key, con=None):
    own = con is None
    con = con or _con()
    try:
        rows = con.execute("SELECT day, v FROM trend WHERE key=? ORDER BY day DESC LIMIT ?",
                           (key, TREND_DAYS)).fetchall()
    finally:
        if own:
            con.close()
    return [[r["day"], r["v"]] for r in reversed(rows)]


def cached(board):
    """{iid: result-or-None} for the whole board from the cache — runs no widget SQL."""
    keys, out = {}, {}
    for w in board.get("widgets") or []:
        if w["ref"] == "text.heading":
            continue
        try:
            _, d, scope, pinned = resolve(board, w["iid"])
            if d.get("review"):
                out[w["iid"]] = {"state": "review"}
                continue
            if d.get("snapshot"):
                out[w["iid"]] = dict(snapshot_result(d, scope), pinned=pinned,
                                     scope_label=dashmetrics.scope_label(scope), scope_applied=True)
                continue
            full, _disp, info = prepare(d, scope)
            keys[w["iid"]] = (_ckey(full), info, pinned)
        except Exception as e:
            out[w["iid"]] = {"state": "error", "error": str(e)}
    if keys:
        con = _con()
        try:
            got = {}
            ks = list({k for k, _i, _p in keys.values()})
            for i in range(0, len(ks), 400):
                part = ks[i:i + 400]
                for r in con.execute(f"SELECT key, body FROM wcache WHERE key IN ({','.join('?' * len(part))})", part):
                    got[r["key"]] = json.loads(r["body"])
        finally:
            con.close()
        con = _con()
        try:
            trends = {k: _trend_get(k, con) for k, _i, _p in keys.values()}
        finally:
            con.close()
        for iid, (k, info, pinned) in keys.items():
            body = got.get(k)
            if body:
                body = dict(body)
                body["state"] = _state(body)
                body["cached"] = True
            else:
                body = {"state": "not_run"}
            body.update({"scope_label": info["scope_label"], "scope_applied": info["scope_applied"],
                         "pinned": pinned, "notes": info["notes"]})
            if trends.get(k):
                body["trend"] = trends[k]
            out[iid] = body
    return out


def run_widget(board, iid, refresh=False):
    w, d, scope, pinned = resolve(board, iid)
    if d.get("viz") == "text":
        return {"state": "fresh", "rows": [], "columns": []}
    if d.get("review"):
        raise PermissionError("this SQL came from an import — read it and approve it before it runs")
    if d.get("snapshot"):
        return dict(snapshot_result(d, scope), pinned=pinned, scope_label=dashmetrics.scope_label(scope),
                    scope_applied=True)
    full, disp, info = prepare(d, scope)
    key = _ckey(full)
    if not refresh:
        con = _con()
        try:
            r = con.execute("SELECT body FROM wcache WHERE key=?", (key,)).fetchone()
        finally:
            con.close()
        if r:
            body = json.loads(r["body"])
            if _state(body) == "fresh":
                body.update({"state": "fresh", "cached": True, "scope_label": info["scope_label"],
                             "scope_applied": info["scope_applied"], "pinned": pinned, "notes": info["notes"],
                             "trend": _trend_get(key)})
                return body
    t0 = time.time()
    rows, more = [], False
    it = db.user_iter(full)
    try:
        for r in it:
            if len(rows) >= widgets.ROW_CAP:
                more = True
                break
            rows.append(r)
    finally:
        it.close()
    body = {"rows": rows, "columns": list(rows[0].keys()) if rows else [], "truncated": more,
            "count": len(rows), "at": time.time(), "ms": round((time.time() - t0) * 1000),
            "db_fp": dashmetrics.fingerprint(), "defs": info["defs"]}
    con = _con()
    try:
        con.execute("INSERT OR REPLACE INTO wcache VALUES (?,?,?)", (key, body["at"], json.dumps(body, default=str)))
        con.execute("DELETE FROM wcache WHERE key NOT IN (SELECT key FROM wcache ORDER BY at DESC LIMIT 3000)")
        con.commit()
    finally:
        con.close()
    _trend_note(key, rows, body["at"])
    body = dict(body)
    body.update({"state": "fresh", "cached": False, "scope_label": info["scope_label"],
                 "scope_applied": info["scope_applied"], "pinned": pinned, "notes": info["notes"],
                 "trend": _trend_get(key)})
    return body


def sql_info(board, iid):
    w, d, scope, pinned = resolve(board, iid)
    if d.get("viz") == "text":
        return {"ok": True, "text": True}
    if d.get("snapshot"):
        k, v = _snap_target(scope)
        snap = d["snapshot"]
        where = ", ".join(f"{lbl} ← {p}" for lbl, p in (snap.get("paths") or [])) or str(snap.get("path"))
        return {"ref": d["ref"], "title": w.get("title") or d["title"], "snapshot": True, "sql": "", "sql_full": "",
                "raw": "", "defs": [], "scope_label": dashmetrics.scope_label(scope), "pinned": pinned, "notes": [],
                "lineage": (d.get("lineage") or []) + [
                    {"t": f"{d['source'].get('name')}'s own last run on this scope (its page cache) — the specialist's "
                          f"logic, read as it saved it, never recomputed here", "src": f"{d['source']['page']}"},
                    {"t": f"Value read from the {snap['call']} response", "src": where}],
                "open": (_snap_url(d["source"]["page"], k, v) if k is not False else d["source"]["page"]),
                "source": d.get("source"), "review": False, "navi_db": os.path.basename(db.db_path() or "navi.db")}
    full, disp, info = prepare(d, scope)
    out = {"ref": d["ref"], "title": w.get("title") or d["title"], "sql": disp, "sql_full": full,
           "raw": d["sql"], "defs": [{"name": n, **dashmetrics.DEFS[n]} for n in info["defs"]],
           "scope_label": info["scope_label"], "pinned": pinned, "notes": info["notes"],
           "lineage": d.get("lineage") or [], "source": d.get("source"), "review": bool(d.get("review")),
           "navi_db": os.path.basename(db.db_path() or "navi.db")}
    if d.get("drill"):
        out["drill"] = prepare(d, scope, drill=True)[1]
    return out


def data(board, iid, page=0, size=50):
    """One server-side page of the widget's rows (its drill SQL, else its own SQL)."""
    w, d, scope, pinned = resolve(board, iid)
    if d.get("review"):
        raise PermissionError("approve this widget's SQL before opening its data")
    if d.get("snapshot"):
        raise LookupError("this number comes from the specialist's page — open it there for the rows")
    full, disp, info = prepare(d, scope, drill=True)
    size = max(1, min(widgets.EXPORT_MAX, int(size or 50)))
    page = max(0, int(page or 0))
    rows = db.user_query(f"SELECT * FROM ({full}\n) LIMIT {size + 1} OFFSET {page * size}")   # \n: a trailing -- comment must not swallow the wrapper
    more = len(rows) > size
    rows = rows[:size]
    total = None
    if page == 0:
        try:
            total = int(db.user_query(f"SELECT COUNT(*) AS n FROM (SELECT 1 FROM ({full}\n) LIMIT 100001)")[0]["n"])
        except Exception:
            total = None
    return {"rows": rows, "columns": list(rows[0].keys()) if rows else [], "page": page, "size": size,
            "more": more, "total": total, "total_capped": total is not None and total > 100000,
            "sql": disp, "scope_label": info["scope_label"]}


# ── import / export (definitions only) ──────────────────────────────────────────────────────
def export(bid):
    b = get(bid)
    if not b:
        return None
    sqls = {}
    for w in b["widgets"]:
        if w["ref"].startswith("sql."):
            d = definition(w["ref"])
            if d:
                sqls[w["ref"]] = {k: d.get(k) for k in ("title", "note", "viz", "sql", "drill", "label_col",
                                                        "value_col", "w", "h")}
    return {"format": "navi-ensemble-board", "version": 1, "exported": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "board": {k: b[k] for k in ("name", "layout", "scope", "widgets")}, "sql_widgets": sqls,
            "note": "Definitions only — layout, scope and SQL. No rows, hostnames or IPs."}


def import_doc(doc, origin="file"):
    """Create a board from an exported doc (or a legacy browser board). SQL widgets from a FILE
    arrive with review=1; a browser board (this browser's own localStorage) is the user's own SQL."""
    if not isinstance(doc, dict):
        raise ValueError("not a board export")
    if doc.get("format") == "navi-ensemble-board":
        src = doc.get("board") or {}
        remap = {}
        for ref, d in (doc.get("sql_widgets") or {}).items():
            if isinstance(d, dict):
                remap[ref] = save_sql_widget(d, origin=origin, review=(origin == "file"))
        ws = []
        for w in src.get("widgets") or []:
            if not isinstance(w, dict):
                continue
            w = dict(w)
            if str(w.get("ref", "")).startswith("sql."):
                if w["ref"] not in remap:
                    continue
                w["ref"] = remap[w["ref"]]
            w.pop("iid", None)
            ws.append(w)
        body = {"name": src.get("name") or "Imported board", "layout": src.get("layout"),
                "scope": src.get("scope"), "widgets": ws}
    elif isinstance(doc.get("items"), list):                # legacy localStorage board
        ws = []
        size = {"xs": (2, 2), "s": (3, 2), "m": (6, 3), "l": (8, 4), "xl": (12, 4)}
        for it in doc["items"][:MAX_WIDGETS]:
            if not isinstance(it, dict) or not str(it.get("sql") or "").strip():
                continue
            r = it.get("r") or {}
            viz = r.get("viz") if r.get("viz") in widgets.VIZ else ("table" if r.get("viz") not in (None, "auto") else "bar")
            w, h = size.get(it.get("size"), (6, 3))
            ref = save_sql_widget({"title": it.get("title"), "note": it.get("note"), "sql": it["sql"], "viz": viz,
                                   "label_col": r.get("label_col"), "value_col": r.get("value_col"), "w": w, "h": h},
                                  origin=origin, review=(origin == "file"))
            ws.append({"ref": ref, "w": w, "h": h})
        body = {"name": doc.get("name") or "Browser board", "widgets": ws}
    else:
        raise ValueError("not a board export")
    body = norm_board(body)
    now, bid = time.time(), _nid("b")
    con = _con()
    try:
        _seed(con)
        con.execute("INSERT INTO boards VALUES (?,?,?,?,?,?,?,?)",
                    (bid, body["name"], "user", 0, 1, json.dumps(body), now, now))
        _audit(con, "import", bid, origin)
        con.commit()
    finally:
        con.close()
    return get(bid)


# ── daily snapshots (opt-in per board: Board size → "Snapshot once a day") ────────────────────
_DAILY = {"started": False}


def _daily_pass():
    """Run each KPI widget of every daily board that has no trend point today."""
    today = time.strftime("%Y-%m-%d")
    for bi in list_boards():
        b = get(bi["id"])
        if not b or not (b.get("layout") or {}).get("daily"):
            continue
        for w in b["widgets"]:
            try:
                _, d, scope, _p = resolve(b, w["iid"])
                if d.get("review") or d.get("snapshot") or d.get("viz") not in ("kpi", "gauge"):
                    continue
                full, _disp, _info = prepare(d, scope)
                pts = _trend_get(_ckey(full))
                if pts and pts[-1][0] == today:
                    continue
                with db.budget_scope("job"):
                    run_widget(b, w["iid"], refresh=True)
            except Exception:
                continue


def ensure_daily():
    """Start the daily-snapshot thread once (it only runs SQL for boards that opted in)."""
    if _DAILY["started"] or os.environ.get("NAVI_BOARDS_DAILY", "1") == "0":
        return
    _DAILY["started"] = True

    def loop():
        time.sleep(60)
        while True:
            try:
                _daily_pass()
            except Exception:
                pass
            time.sleep(1800)
    threading.Thread(target=loop, name="boards-daily", daemon=True).start()
