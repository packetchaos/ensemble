"""One definition per number (build 509) — the metric definitions and SQL macros every dashboard
widget shares, so "KEV-exposed assets" is the same count on a board, on the Ensemble wall and on
the CISA KEV page.

A widget's SQL is ordinary read-only SQLite over navi.db plus these macros, expanded on the server
(never in the browser) just before it runs:

    $__scope(col)      the board's tag scope on an asset-uuid column        → "col IN (…)" / "1=1"
    $__open(alias)     open_finding: state open/reopened, severity not info  (vulns row)
    $__kev(alias)      kev finding: the plugin names a CISA KEV catalog CVE, or carries the KEV xref
    $__cred(alias)     credentialed_asset proof row (core/credstate's one definition)
    $__crown(alias)    crown_jewel: ACR ≥ the Settings line (core.crown, default 8)  (assets row)
    $__certdate(col)   a certificate date ('Apr 03 16:07:23 2027 GMT' or ISO) → 'YYYY-MM-DD'

The scope is boolean over the tags table — OR within a category, AND across categories, NOT for
exclusions — and is compiled into one sub-query, so asset ids never reach the browser:

    {"terms": [{"key": "Business Tier", "values": ["Production", "Staging"]},
               {"key": "Lifecycle", "values": ["Decommissioned"], "op": "not"}]}

Values are inlined as escaped SQL literals so the SQL panel shows exactly the statement that ran
(and an auditor can paste it into `navi explore query`).
"""
from core.errors import swallowed as _swallowed  # no silent excepts
import hashlib
import json
import re
import threading

from core import credstate, db

from core import crown as _crown   # crown_jewel = ACR ≥ the Settings line (default 8), on every page
MAX_TERMS = 12
MAX_VALUES = 50
MAX_LEN = 200

DEFS = {
    "open_finding": {
        "label": "Open finding",
        "doc": "A vulns row whose state is open or reopened (any letter case; a row with no state counts "
               "as open) and whose severity is not info."},
    "kev_asset": {
        "label": "KEV finding / KEV asset",
        "doc": "An open finding whose plugin names a CVE in the CISA Known Exploited Vulnerabilities catalog "
               "(the catalog CISA KEV uses), or that carries Tenable's CISA-KNOWN-EXPLOITED xref. A KEV asset "
               "has at least one."},
    "credentialed_asset": {
        "label": "Credentialed asset",
        "doc": "The scanner logged in: plugin 19506 says 'Credentialed checks : yes', or plugin 141118 / "
               "110095 is open on the asset (core/credstate — the definition every specialist uses). "
               "Blind = scanned but not credentialed."},
    "crown_jewel": {
        "label": "Crown jewel",
        "doc": "An asset whose Asset Criticality Rating (ACR) is at or above the crown-jewel line in Settings (default 8)."},
    "route_assets": {
        "label": "Route × asset",
        "doc": "One row per exposure route and asset with an open, non-info finding of one of the route's "
               "plugins. owned = the asset carries an Owner tag '<route>: <user>' (not Ignored / Accepted / "
               "Mitigated); decided = it carries one of those dispositions — Exposure Routes' rule."},
    "path_assets": {
        "label": "Path × asset",
        "doc": "One row per vulnerable path and asset, owned / decided by an Owner tag '<path>: <user>'."},
    "asset_facts": {
        "label": "Asset facts",
        "doc": "One row per asset: host, ip, OS family, device type (Device Type tag → Asset Inventory "
               "'Device Type: …' → Nessus plugin 54615 → 'Unclassified'), ACR, crown jewel flag, whether it "
               "has any Owner tag."},
    "tag_scope": {
        "label": "Tag scope",
        "doc": "OR within a tag category, AND across categories, NOT for exclusions — matched exactly on "
               "tag_key / tag_value in navi.db's tags table (tags are as fresh as the last asset sync)."},
}

SCANNED_PLUGINS = credstate.SCANNED_PLUGINS
_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")
_MACRO = re.compile(r"\$__([a-z_]+)\(\s*([^()]*?)\s*\)")
_MEMO = {}
_LOCK = threading.Lock()


def lit(s) -> str:
    return "'" + str(s).replace("'", "''") + "'"


# ── scope ────────────────────────────────────────────────────────────────────────────────────
def norm_scope(scope):
    """A clean scope dict ({'terms': [...]}) — or {'terms': []} for the whole estate. Raises
    ValueError on a malformed one (the API answers 400)."""
    if scope in (None, "", {}, []):
        return {"terms": []}
    if not isinstance(scope, dict):
        raise ValueError("scope must be {terms:[…]}")
    terms = scope.get("terms") or []
    if not isinstance(terms, list):
        raise ValueError("scope.terms must be a list")
    if len(terms) > MAX_TERMS:
        raise ValueError(f"at most {MAX_TERMS} scope filters")
    out, seen = [], {}
    for t in terms:
        if not isinstance(t, dict):
            raise ValueError("each scope filter is {key, values, op}")
        k = t.get("key")
        k = k.strip() if isinstance(k, str) else ""
        vals = t.get("values")
        if isinstance(vals, str):
            vals = [vals]
        vals = [v.strip() for v in (vals or []) if isinstance(v, str) and v.strip()]
        op = "not" if t.get("op") == "not" else "in"
        if not k or not vals:
            continue
        if len(k) > MAX_LEN or any(len(v) > MAX_LEN for v in vals):
            raise ValueError("tag category / value too long")
        if len(vals) > MAX_VALUES:
            raise ValueError(f"at most {MAX_VALUES} values per filter")
        key = (k, op)
        if key in seen:                         # same category + op twice → one OR list
            prev = seen[key]
            prev["values"] = sorted(set(prev["values"]) | set(vals))
            continue
        seen[key] = {"key": k, "values": sorted(set(vals)), "op": op}
        out.append(seen[key])
    return {"terms": out}


def scope_label(scope) -> str:
    sc = norm_scope(scope)
    if not sc["terms"]:
        return "Whole estate"
    parts = []
    for t in sc["terms"]:
        v = " or ".join(t["values"])
        parts.append(("not " if t["op"] == "not" else "") + f"{t['key']} = {v}")
    return " · ".join(parts)


def scope_sig(scope) -> str:
    return hashlib.sha1(json.dumps(norm_scope(scope), sort_keys=True).encode()).hexdigest()[:12]


def scope_pred(scope, col) -> str:
    """Boolean SQL over asset-uuid column `col` ('1=1' for the whole estate)."""
    if not _ID.match(col or ""):
        raise ValueError(f"$__scope needs a column name, not {col!r}")
    sc = norm_scope(scope)
    if not sc["terms"]:
        return "1=1"
    w = []
    for t in sc["terms"]:
        vals = ",".join(lit(v) for v in t["values"])
        sub = f"SELECT asset_uuid FROM tags WHERE tag_key={lit(t['key'])} AND tag_value IN ({vals})"
        w.append(f"{col} {'NOT IN' if t['op'] == 'not' else 'IN'} ({sub})")
    return "(" + " AND ".join(w) + ")"


def scope_count(scope, path=None) -> int | None:
    """Assets in the scope (all assets for the whole estate)."""
    try:
        return int(db.scalar(f"SELECT COUNT(*) FROM assets a WHERE {scope_pred(scope, 'a.uuid')}", path=path) or 0)
    except Exception:
        return None


# ── navi.db facts the macros need (memoised per navi.db fingerprint) ──────────────────────────
def fingerprint(path=None) -> str:
    """A short hash of navi.db's identity (path + mtime/size + hx fingerprint) — changes on every sync."""
    try:
        from core import crown               # the crown-jewel line is part of every widget's answer
        return hashlib.sha1((str(credstate._fp(path)) + crown.sig()).encode()).hexdigest()[:16]
    except Exception:
        return ""


def _facts(path=None):
    fp = fingerprint(path)
    with _LOCK:
        hit = _MEMO.get(path)
        if hit and hit[0] == fp:
            return hit[1]
    f = {"vcols": set(), "acols": set(), "kev_pids": None, "kev_src": "xref"}
    try:
        f["vcols"] = {r["name"] for r in db.query('PRAGMA table_info("vulns")', path=path)}
        f["acols"] = {r["name"] for r in db.query('PRAGMA table_info("assets")', path=path)}
    except Exception as _e:
        _swallowed(_e)
    try:
        from core import hx_summary, kev
        if "cves" in f["vcols"] and hx_summary.usable(path):
            cat, _src = kev.fetch_catalog(allow_live=False)
            K = {v["cveID"].upper() for v in cat.get("vulnerabilities", []) if v.get("cveID")}
            pids = kev._kev_plugins(K, path)
            if pids is not None:
                f["kev_pids"] = sorted(set(pids), key=lambda p: (len(p), p))
                f["kev_src"] = f"catalog ({len(K):,} CISA KEV CVEs)"
    except Exception as _e:
        _swallowed(_e)
    with _LOCK:
        _MEMO[path] = (fp, f)
    return f


# ── macro expansion ─────────────────────────────────────────────────────────────────────────
def _alias(arg, macro):
    arg = (arg or "").strip()
    if not arg:
        return ""
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", arg):
        raise ValueError(f"$__{macro}( ) takes a table alias, not {arg!r}")
    return arg + "."


def _certdate(col):
    if not _ID.match(col or ""):
        raise ValueError(f"$__certdate needs a column name, not {col!r}")
    mon = " ".join(f"WHEN '{m}' THEN '{i:02d}'" for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1))
    c = f"trim({col})"
    return (f"(CASE WHEN {c} GLOB '[0-9][0-9][0-9][0-9]-*' THEN substr({c},1,10) "
            f"WHEN {c} GLOB '[A-Z][a-z][a-z] *' THEN substr(rtrim(replace({c},' GMT','')),-4,4)||'-'||"
            f"(CASE substr({c},1,3) {mon} END)||'-'||printf('%02d',CAST(trim(substr({c},5,2)) AS INTEGER)) "
            f"END)")


# ── semantic tables: the hard joins, written once ───────────────────────────────
_DISP = "('ignored','accepted','mitigated')"


def _tag_args(arg):
    m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)\s*,\s*'((?:[^']|'')*)'\s*$", arg or "")
    if not m:
        raise ValueError("$__tag needs (asset_uuid column, 'Tag category') — e.g. $__tag(a.uuid, 'Business Tier')")
    return m.group(1), m.group(2).replace("''", "'")


def _open_w(f, a):
    w = []
    if not f["vcols"] or "state" in f["vcols"]:
        w.append(f"lower(COALESCE({a}state,'open')) IN ('open','reopened')")
    if not f["vcols"] or "severity" in f["vcols"]:
        w.append(f"lower(COALESCE({a}severity,'')) NOT IN ('info','informational')")
    return " AND ".join(w) or "1=1"


def _owned_join(base, name_col):
    """route/path rows + the Owner tags naming them: owned / decided / owner per (name, asset)."""
    u = f"trim(substr(_o.tv, length({name_col})+3))"
    return (f"(SELECT _b.*, MAX(CASE WHEN _o.tv IS NOT NULL AND {u}<>'' AND lower({u}) NOT IN {_DISP} THEN 1 ELSE 0 END) AS owned, "
            f"MAX(CASE WHEN _o.tv IS NOT NULL AND lower({u}) IN {_DISP} THEN 1 ELSE 0 END) AS decided, "
            f"MIN(CASE WHEN _o.tv IS NOT NULL AND {u}<>'' AND lower({u}) NOT IN {_DISP} THEN {u} END) AS owner "
            f"FROM ({base}) _b LEFT JOIN (SELECT asset_uuid, tag_value AS tv FROM tags WHERE tag_key='Owner' "
            f"AND tag_value LIKE '%: %') _o ON _o.asset_uuid=_b.asset_uuid "
            f"AND lower(substr(_o.tv,1,length({name_col})+2))=lower({name_col})||': ' "
            f"GROUP BY {', '.join('_b.' + c for c in _b_cols(base))})")


def _b_cols(base):
    return [c.strip().split(" AS ")[-1].split(".")[-1] for c in base.split(" FROM ")[0][len("SELECT DISTINCT "):].split(",")]


def _route_assets(f, path):
    t = _tables(path)
    if "vuln_route" not in t or not f["vcols"]:
        return ("(SELECT NULL AS route_id, NULL AS route, NULL AS route_type, NULL AS asset_uuid, 0 AS owned, "
                "0 AS decided, NULL AS owner WHERE 0)")
    try:
        from core import hx_rpp
        fresh = hx_rpp.usable(path)
    except Exception:
        fresh = False
    if fresh:
        base = ("SELECT DISTINCT _r.route_id AS route_id, _r.app_name AS route, _r.vuln_type AS route_type, "
                "_h.asset_uuid AS asset_uuid FROM hx_rpp _h JOIN vuln_route _r "
                "ON CAST(_r.route_id AS TEXT)=CAST(_h.route_id AS TEXT) WHERE TRIM(COALESCE(_r.app_name,''))<>''")
    else:
        pl = "replace(_r.plugin_list, char(39), char(34))"
        base = ("SELECT DISTINCT _r.route_id AS route_id, _r.app_name AS route, _r.vuln_type AS route_type, "
                f"_v.asset_uuid AS asset_uuid FROM vuln_route _r, json_each(CASE WHEN json_valid({pl}) THEN {pl} "
                "ELSE '[]' END) _j JOIN vulns _v ON _v.plugin_id=CAST(_j.value AS TEXT) "
                f"WHERE TRIM(COALESCE(_r.app_name,''))<>'' AND {_open_w(f, '_v.')}")
    return _owned_join(base, "_b.route")


def _path_assets(f, path):
    t = _tables(path)
    if "vuln_paths" not in t:
        return "(SELECT NULL AS path, NULL AS asset_uuid, 0 AS owned, 0 AS decided, NULL AS owner WHERE 0)"
    try:
        from core import hx_rpp
        fresh = hx_rpp.usable(path)
    except Exception:
        fresh = False
    if fresh:
        base = "SELECT DISTINCT _p.path AS path, _p.asset_uuid AS asset_uuid FROM hx_rpp_path _p WHERE TRIM(COALESCE(_p.path,''))<>''"
    else:
        base = ("SELECT DISTINCT _p.path AS path, _p.asset_uuid AS asset_uuid FROM vuln_paths _p "
                "WHERE TRIM(COALESCE(_p.path,''))<>''")
    return _owned_join(base, "_b.path")


def _asset_facts(f, path):
    a = f["acols"]
    host = "COALESCE(NULLIF(_a.hostname,''), _a.ip_address)" if {"hostname", "ip_address"} <= a else "_a.uuid"
    ip = "_a.ip_address" if "ip_address" in a else "NULL"
    osx = "COALESCE(_a.operating_system,'')" if "operating_system" in a else "''"
    osf = (f"(CASE WHEN {osx} LIKE '%Windows%' THEN 'Windows' WHEN {osx} LIKE '%Linux%' OR {osx} LIKE '%CentOS%' "
           f"OR {osx} LIKE '%Ubuntu%' OR {osx} LIKE '%Red Hat%' OR {osx} LIKE '%Debian%' THEN 'Linux' "
           f"WHEN {osx} LIKE '%Mac%' THEN 'macOS' WHEN {osx}='' THEN 'Unknown' ELSE 'Other' END)")
    acr = "CAST(COALESCE(NULLIF(_a.acr,''),0) AS REAL)" if "acr" in a else "0"
    n54 = "instr(_v.output,'Remote device type :')"
    nessus = (f"(SELECT _v.asset_uuid, MIN(trim(substr(_v.output, {n54}+20, instr(substr(_v.output, {n54}+20)||char(10), "
              f"char(10))-1))) AS v FROM vulns _v WHERE _v.plugin_id='54615' AND {n54}>0 GROUP BY _v.asset_uuid)"
              if "output" in f["vcols"] else "(SELECT NULL AS asset_uuid, NULL AS v WHERE 0)")
    return (f"(SELECT _a.uuid AS asset_uuid, {host} AS host, {ip} AS ip, {osf} AS os_family, "
            f"COALESCE(NULLIF(_d1.v,''), NULLIF(_d2.v,''), CASE WHEN _d3.v IS NOT NULL AND _d3.v<>'' THEN "
            f"upper(substr(_d3.v,1,1))||substr(_d3.v,2) END, 'Unclassified') AS device_type, "
            f"{acr} AS acr, CASE WHEN {acr} >= {_crown.threshold()} THEN 1 ELSE 0 END AS crown, "
            f"CASE WHEN _ow.asset_uuid IS NULL THEN 0 ELSE 1 END AS has_owner_tag "
            f"FROM assets _a "
            f"LEFT JOIN (SELECT asset_uuid, MIN(tag_value) AS v FROM tags WHERE tag_key='Device Type' GROUP BY asset_uuid) _d1 "
            f"ON _d1.asset_uuid=_a.uuid "
            f"LEFT JOIN (SELECT asset_uuid, MIN(trim(substr(tag_value,14))) AS v FROM tags WHERE tag_key='Asset Inventory' "
            f"AND tag_value LIKE 'Device Type:%' GROUP BY asset_uuid) _d2 ON _d2.asset_uuid=_a.uuid "
            f"LEFT JOIN {nessus} _d3 ON _d3.asset_uuid=_a.uuid "
            f"LEFT JOIN (SELECT DISTINCT asset_uuid FROM tags WHERE tag_key='Owner') _ow ON _ow.asset_uuid=_a.uuid)")


_TABLES = {"route_assets": _route_assets, "path_assets": _path_assets, "asset_facts": _asset_facts}


def _tables(path=None):
    try:
        return {r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'", path=path)}
    except Exception:
        return set()


def expand(sql, scope=None, path=None):
    """(expanded_sql, display_sql, info) — info = {"defs": [...], "scoped": bool, "lineage": [...]}.
    display_sql is the same statement with the long KEV plugin list folded into a comment."""
    f = _facts(path)
    info = {"defs": [], "scoped": False, "notes": []}
    folded = {}

    def use(d):
        if d not in info["defs"]:
            info["defs"].append(d)

    def rep(m):
        name, arg = m.group(1), m.group(2)
        if name == "scope":
            info["scoped"] = True
            use("tag_scope")
            return scope_pred(scope, arg)
        if name == "open":
            a = _alias(arg, name)
            use("open_finding")
            w = []
            if not f["vcols"] or "state" in f["vcols"]:
                w.append(f"lower(COALESCE({a}state,'open')) IN ('open','reopened')")
            if not f["vcols"] or "severity" in f["vcols"]:
                w.append(f"lower(COALESCE({a}severity,'')) NOT IN ('info','informational')")
            return "(" + (" AND ".join(w) or "1=1") + ")"
        if name == "kev":
            a = _alias(arg, name)
            use("kev_asset")
            x = f"{a}xrefs LIKE '%CISA-KNOWN-EXPLOITED%'" if (not f["vcols"] or "xrefs" in f["vcols"]) else "0"
            pids = f["kev_pids"]
            if pids is None:
                if "xref only" not in " ".join(info["notes"]):
                    info["notes"].append("KEV matched by Tenable's xref only — run Optimize (Settings) so "
                                         "the CISA catalog match is used, like the CISA KEV page.")
                return f"({x})"
            if not pids:
                return f"({x})"
            full = f"({a}plugin_id IN ({','.join(lit(p) for p in pids)}) OR {x})"
            tok = f"__KEVLIST{len(folded)}__"
            folded[tok] = (full, f"({a}plugin_id IN (/* {len(pids):,} plugin ids naming a CISA KEV CVE — "
                                 f"{f['kev_src']} */) OR {x})")
            return tok
        if name == "cred":
            use("credentialed_asset")
            a = _alias(arg, name).rstrip(".")
            return credstate.cred_sql(f["vcols"] or {"state"}, a)
        if name == "crown":
            a = _alias(arg, name)
            use("crown_jewel")
            return _crown.sql(a + "acr")
        if name == "certdate":
            return _certdate(arg)
        if name == "tag":
            col, key = _tag_args(arg)
            return f"(SELECT MIN(_t.tag_value) FROM tags _t WHERE _t.asset_uuid={col} AND _t.tag_key={lit(key)})"
        if name in ("route_assets", "path_assets", "asset_facts"):
            if arg.strip():
                raise ValueError(f"$__{name}() takes no arguments — join it and filter with $__scope(…)")
            use(name)
            if name == "asset_facts":
                use("crown_jewel")
            return _TABLES[name](f, path)
        raise ValueError(f"unknown macro $__{name}( )")

    out = _MACRO.sub(rep, sql or "")
    if "$__" in out:
        raise ValueError("a $__macro( ) is malformed — see the macro list")
    disp = out
    for tok, (full, short) in folded.items():
        out = out.replace(tok, full)
        disp = disp.replace(tok, short)
    return out, disp, info


def uses_scope(sql) -> bool:
    return bool(re.search(r"\$__scope\(", sql or ""))


def catalog():
    """The definitions + macro list for the library / SQL panel."""
    return {"defs": DEFS, "macros": [
        {"m": "$__scope(col)", "d": "the board's tag scope on an asset-uuid column"},
        {"m": "$__open(v)", "d": "open_finding on a vulns alias"},
        {"m": "$__kev(v)", "d": "KEV finding on a vulns alias (CISA catalog)"},
        {"m": "$__cred(v)", "d": "credentialed proof row on a vulns alias"},
        {"m": "$__crown(a)", "d": "crown jewel on an assets alias"},
        {"m": "$__certdate(c.not_valid_after)", "d": "certificate date → YYYY-MM-DD"},
        {"m": "$__tag(a.uuid, 'Business Tier')", "d": "an asset's value for a tag category"},
        {"m": "$__route_assets() ra", "d": "table: route_id, route, route_type, asset_uuid, owned, decided, owner"},
        {"m": "$__path_assets() pa", "d": "table: path, asset_uuid, owned, decided, owner"},
        {"m": "$__asset_facts() af", "d": "table: asset_uuid, host, ip, os_family, device_type, acr, crown, has_owner_tag"}]}
