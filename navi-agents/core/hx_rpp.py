"""The route / path / plugin index — the "zipper" that says who owns every open finding.

navi builds two independent views of the same findings:
  vuln_route   every non-info plugin → exactly one route (app_name), from `navi config update route`
  vuln_paths   (plugin, asset, path) rows parsed from non-info plugin output, from `… update paths`
A route has many plugins; a plugin can sit at many paths and a path can carry many plugins, so a
route ↔ path pairing is 1:1 or many-to-many. Ownership is applied by tagging either side
(Owner '<route or path>: <user>'), so the only way to know whether EVERY finding is owned is to
zip the two together per finding:

  hx_rpp       one row per OPEN, NON-INFO finding (plugin_id, asset_uuid): its plugin's route_id
               (NULL = the plugin has no route — the route table is older than the plugin) and
               how many paths that finding was found at
  hx_rpp_path  (plugin_id, asset_uuid, path) — the paths of those findings (vuln_paths cut to
               open, non-info findings and de-duplicated)

A finding is OWNED when its asset carries a real Owner tag for the plugin's route OR for one of
the paths that plugin was found at on that asset. agents/exproute rolls that up per plugin, per
route, per path and per asset.

Built by ⚡ Optimize inside hx_summary.build's transaction (after hx_route_plugin). "Open" =
state open/reopened (any case, NULL = open); "non-info" = severity not info (finding_where()). Freshness = hx_summary's vulns/assets fingerprint AND rpp_src, a fingerprint of
vuln_route + vuln_paths (a route or paths update doesn't touch vulns). When either is stale,
iter_findings() computes the same rows from navi.db directly — the index is an accelerator,
never the source of truth.
"""
import hashlib
import re
import sqlite3

DDL = {
    "hx_rpp": ("CREATE TABLE hx_rpp(plugin_id TEXT, asset_uuid TEXT, route_id INTEGER, paths INTEGER, "
               "PRIMARY KEY(plugin_id, asset_uuid)) WITHOUT ROWID"),
    "hx_rpp_path": ("CREATE TABLE hx_rpp_path(plugin_id TEXT, asset_uuid TEXT, path TEXT, "
                    "PRIMARY KEY(plugin_id, asset_uuid, path)) WITHOUT ROWID"),
}
_QUOTED = re.compile(r"'([^']*)'")


def finding_where(vcols):
    """SQL for "open and not informational" over vulns, given its columns. navi always writes
    state + severity; a database without them (the bundled sample, hand-made fixtures) treats a
    missing column / NULL as open and as not-info — an unknown finding is counted, never hidden."""
    w = ["plugin_id IS NOT NULL", "asset_uuid IS NOT NULL"]
    if "state" in vcols:
        w.append("lower(COALESCE(state,'open')) IN ('open','reopened')")
    if "severity" in vcols:
        w.append("lower(TRIM(COALESCE(severity,''))) NOT IN ('info','informational','0','none')")
    return " AND ".join(w)


def _tables(c):
    return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def src_fingerprint(c):
    """vuln_route content hash + vuln_paths (rootpage, max rowid). Cheap: vuln_route is small
    (one row per route); vuln_paths costs two b-tree descents. '-' parts when a table is missing."""
    have = _tables(c)
    parts = []
    if "vuln_route" in have:
        h = hashlib.sha1()
        try:
            for row in c.execute("SELECT * FROM vuln_route ORDER BY rowid"):
                h.update(repr(tuple(row)).encode("utf-8", "replace"))
            parts.append("r:" + h.hexdigest()[:16])
        except sqlite3.Error:
            parts.append("r:?")
    else:
        parts.append("r:-")
    if "vuln_paths" in have:
        rp = c.execute("SELECT rootpage FROM sqlite_master WHERE type='table' AND name='vuln_paths'").fetchone()
        mx = c.execute("SELECT MAX(rowid) FROM vuln_paths").fetchone()[0]
        parts.append("p:%s:%s" % (rp[0] if rp else "-", mx if mx is not None else 0))
    else:
        parts.append("p:-")
    return "|".join(parts)


def route_map(c):
    """{plugin_id: (route_id, app_name)} from vuln_route — navi gives each plugin one route;
    if a custom table lists a plugin twice, the lowest route_id wins (deterministic)."""
    if "vuln_route" not in _tables(c):
        return {}
    cols = {r[1] for r in c.execute('PRAGMA table_info("vuln_route")')}
    if not {"app_name", "plugin_list"} <= cols:
        return {}
    rid = "route_id" if "route_id" in cols else "rowid"
    out = {}
    for r_id, app, pl in c.execute("SELECT %s, app_name, plugin_list FROM vuln_route ORDER BY %s" % (rid, rid)):
        if not app or not str(app).strip():
            continue
        for pid in set(_QUOTED.findall(str(pl or ""))):
            out.setdefault(pid, (r_id, app))
    return out


# ── build (inside hx_summary.build's write transaction) ───────────────────────────────────────
def write(c, emit=None):
    """Create hx_rpp / hx_rpp_path on write connection c. Returns the hx_meta rows to add."""
    emit = emit or (lambda s: None)
    for t, ddl in DDL.items():
        c.execute('DROP TABLE IF EXISTS "%s"' % t)
        c.execute(ddl)
    have = _tables(c)
    if "vulns" not in have:
        return {}
    idx = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    ib = ' INDEXED BY "hx_v_plugin"' if "hx_v_plugin" in idx else ""
    rmap = route_map(c)
    where = finding_where({r[1] for r in c.execute('PRAGMA table_info("vulns")')})
    c.execute("DROP TABLE IF EXISTS temp.hx_rr")
    c.execute("CREATE TEMP TABLE hx_rr(plugin_id TEXT PRIMARY KEY, route_id INTEGER) WITHOUT ROWID")
    c.executemany("INSERT INTO temp.hx_rr VALUES (?, ?)", ((p, v[0]) for p, v in rmap.items()))
    # one ordered pass over the covering hx_v_plugin(plugin_id, asset_uuid, state, severity):
    # GROUP BY follows the index, so no sort of the findings
    c.execute("""INSERT INTO hx_rpp(plugin_id, asset_uuid, route_id, paths)
        SELECT v.plugin_id, v.asset_uuid, rr.route_id, 0
        FROM (SELECT CAST(plugin_id AS TEXT) plugin_id, asset_uuid FROM vulns%s WHERE %s
              GROUP BY plugin_id, asset_uuid) v
        LEFT JOIN temp.hx_rr rr ON rr.plugin_id = v.plugin_id""" % (ib, where))
    c.execute("DROP TABLE temp.hx_rr")
    n = c.execute("SELECT COUNT(*) FROM hx_rpp").fetchone()[0]
    npath = 0
    pcols = {r[1] for r in c.execute('PRAGMA table_info("vuln_paths")')} if "vuln_paths" in have else set()
    if {"plugin_id", "asset_uuid", "path"} <= pcols:
        # vuln_paths keeps fixed findings' paths too — keep only those of open, non-info findings
        c.execute("""INSERT OR IGNORE INTO hx_rpp_path(plugin_id, asset_uuid, path)
            SELECT CAST(p.plugin_id AS TEXT), p.asset_uuid, TRIM(p.path) FROM vuln_paths p
            WHERE p.path IS NOT NULL AND TRIM(p.path) != ''
              AND EXISTS (SELECT 1 FROM hx_rpp r WHERE r.plugin_id = CAST(p.plugin_id AS TEXT)
                                                   AND r.asset_uuid = p.asset_uuid)""")
        c.execute("""UPDATE hx_rpp SET paths = (SELECT COUNT(*) FROM hx_rpp_path x
                     WHERE x.plugin_id = hx_rpp.plugin_id AND x.asset_uuid = hx_rpp.asset_uuid)
                     WHERE EXISTS (SELECT 1 FROM hx_rpp_path x WHERE x.plugin_id = hx_rpp.plugin_id
                                   AND x.asset_uuid = hx_rpp.asset_uuid)""")
        npath = c.execute("SELECT COUNT(*) FROM hx_rpp_path").fetchone()[0]
    emit("✓ hx_rpp: %s open findings zipped to their route and %s paths" % (format(n, ","), format(npath, ",")))
    return {"rpp": str(n), "rpp_paths": str(npath), "rpp_src": src_fingerprint(c)}


# ── readers ───────────────────────────────────────────────────────────────────────────────────
def usable(path=None):
    """True when hx_rpp matches this navi.db: vulns/assets AND vuln_route/vuln_paths unchanged."""
    from core import hx_summary
    if not hx_summary.usable(path):
        return False
    return bool(hx_summary.state(path).get("rpp_fresh"))


def iter_findings(db_path=None, scope_frag="", scope_args=(), budget="job"):
    """Yield (plugin_id, asset_uuid, app_name or None, (paths…)) for every open, non-info finding
    (distinct plugin × asset), from the index when fresh, else straight from navi.db.
    scope_frag/scope_args: an `AND asset_uuid …` filter (a tag view)."""
    import contextlib
    from core import db
    with contextlib.closing(db.connect(db_path)) as c:
        vcols = {r[1] for r in c.execute('PRAGMA table_info("vulns")')}
        if not {"plugin_id", "asset_uuid"} <= vcols:
            return                       # no vulns table (or not navi's): no findings to zip
        rmap = route_map(c)
        where = finding_where(vcols)
    names = {p: v[1] for p, v in rmap.items()}
    if usable(db_path):
        rid_name = {str(v[0]): v[1] for v in rmap.values()}     # route_id may be TEXT in navi.db
        paths = {}
        for pid, au, p in db.iter("SELECT plugin_id, asset_uuid, path FROM hx_rpp_path WHERE 1=1" + scope_frag,
                                  tuple(scope_args), path=db_path, budget=budget, tuples=True):
            paths.setdefault((pid, au), []).append(p)
        for pid, au, rid in db.iter("SELECT plugin_id, asset_uuid, route_id FROM hx_rpp WHERE 1=1" + scope_frag,
                                    tuple(scope_args), path=db_path, budget=budget, tuples=True):
            yield pid, au, rid_name.get(str(rid)) if rid is not None else None, tuple(paths.get((pid, au), ()))
        return
    # fallback: the same rows from vulns (+ the covering index when it exists) and vuln_paths
    ib = db.indexed_by("hx_v_plugin", db_path)
    pairs = set()
    for pid, au in db.iter("SELECT DISTINCT plugin_id, asset_uuid FROM vulns" + ib + " WHERE " + where +
                           scope_frag, tuple(scope_args), path=db_path, budget=budget, tuples=True):
        pairs.add((str(pid), au))
    paths = {}
    try:
        it = db.iter("SELECT plugin_id, asset_uuid, path FROM vuln_paths WHERE path IS NOT NULL" + scope_frag,
                     tuple(scope_args), path=db_path, budget=budget, tuples=True)
        for pid, au, p in it:
            k = (str(pid), au)
            p = (p or "").strip()
            if p and k in pairs:
                s = paths.setdefault(k, [])
                if p not in s:
                    s.append(p)
    except db.QueryTimeout:
        raise
    except Exception:
        paths = {}
    for pid, au in sorted(pairs):
        yield pid, au, names.get(pid), tuple(sorted(paths.get((pid, au), ())))
