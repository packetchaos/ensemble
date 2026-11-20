"""Build 509 — the Dashboards app: server-side boards, shared metric definitions, boolean tag scope,
per-widget cache, review of imported SQL, resizable / reorderable widgets.
Run: python3 tests/test_dashboards_509.py"""
import json
import os
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="dash509_")
os.environ["NAVI_BOARDS_DB"] = os.path.join(TMP, "boards.db")
os.environ.setdefault("NAVI_CACHE_DIR", os.path.join(TMP, "cache"))
os.environ.setdefault("NAVI_TAGLOG_DB", os.path.join(TMP, "tag.db"))

# a small navi.db
DB = os.path.join(TMP, "navi.db")
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, operating_system TEXT, acr TEXT, last_found TEXT);
CREATE TABLE vulns(asset_uuid TEXT, asset_hostname TEXT, asset_ip TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT,
  state TEXT, xrefs TEXT, cves TEXT, output TEXT, score REAL, exploit TEXT, first_found TEXT, last_found TEXT, plugin_family TEXT);
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE certs(asset_uuid TEXT, common_name TEXT, issuer_name TEXT, not_valid_after TEXT, signature_algorithm TEXT, key_length TEXT);
CREATE TABLE compliance(asset_uuid TEXT, audit_file TEXT, check_name TEXT, status TEXT, actual_value TEXT, expected_value TEXT);
""")
for i in range(6):
    c.execute("INSERT INTO assets VALUES (?,?,?,?,?,?)", (f"u{i}", f"h{i}", f"10.0.0.{i}", "Linux", "9" if i < 2 else "5", "2026-11-01"))
c.executemany("INSERT INTO tags VALUES (?,?,?)", [("u0", "Tier", "Prod"), ("u1", "Tier", "Prod"), ("u2", "Tier", "Dev"),
                                                  ("u1", "Life", "Decom"), ("u0", "Owner", "Web")])
X = "CISA-KNOWN-EXPLOITED"
rows = [("u0", "1", "Critical", "OPEN", X), ("u1", "1", "critical", "fixed", X), ("u2", "1", "high", "reopened", X),
        ("u3", "2", "info", "open", X), ("u4", "3", "low", "open", ""), ("u0", "19506", "info", "open", "")]
for (u, pid, sev, st, xr) in rows:
    c.execute("INSERT INTO vulns(asset_uuid,asset_hostname,asset_ip,plugin_id,plugin_name,severity,state,xrefs,cves,output,score,exploit,first_found)"
              " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
              (u, "h" + u[1], "ip", pid, "Plugin " + pid, sev, st, xr, "", "Credentialed checks : yes" if pid == "19506" else "", 7.0, "false", "2026-01-01"))
c.execute("INSERT INTO certs VALUES ('u0','a','b','Apr 03 16:07:23 2020 GMT','sha1',1024)")
c.commit(); c.close()
os.environ["NAVI_DB_PATH"] = DB

from core import boards, dashmetrics as dm, db, widgets  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def run(ref, scope=None):
    d = boards.definition(ref)
    full, _d, _i = boards.prepare(d, scope)
    return db.user_query(full)


# ── definitions ──
r = run("preset.kev_assets")[0]["KEV-exposed assets"]
check(r == 2, f"kev_assets counts open/reopened, non-info KEV findings only (u0, u2) → {r}")
check(run("preset.crown_jewels")[0]["Crown jewels"] == 2, "crown_jewel = ACR ≥ 9")
check(run("preset.crown_kev")[0]["Crown jewels with KEV"] == 1, "crown jewels with an OPEN KEV finding (u1's is fixed)")
# ── scope: OR within a category, AND across, NOT ──
sc = {"terms": [{"key": "Tier", "values": ["Prod", "Dev"]}]}
check(run("preset.assets_in_scope", sc)[0]["Assets"] == 3, "OR within a category")
sc2 = {"terms": [{"key": "Tier", "values": ["Prod", "Dev"]}, {"key": "Life", "values": ["Decom"], "op": "not"}]}
check(run("preset.assets_in_scope", sc2)[0]["Assets"] == 2, "AND across categories with NOT")
check(dm.scope_label(sc2) == "Tier = Dev or Prod · not Life = Decom", "scope label reads like the bar")
try:
    dm.scope_pred(sc, "x); DROP TABLE t; --")
    check(False, "a bad $__scope column is refused")
except ValueError:
    check(True, "a bad $__scope column is refused")
full, disp, info = dm.expand("SELECT 1 FROM tags t WHERE $__scope(t.asset_uuid)", {"terms": [{"key": "K'x", "values": ["v'1"]}]})
check("'K''x'" in full and "'v''1'" in full, "scope values are escaped SQL literals")
check(info["scoped"] and "tag_scope" in info["defs"], "expand reports the scope and the definitions it used")
check(dm.expand("SELECT $__certdate(c.not_valid_after) AS d FROM certs c")[0] and
      db.user_query(dm.expand("SELECT $__certdate(c.not_valid_after) AS d FROM certs c")[0])[0]["d"] == "2020-04-03",
      "$__certdate turns 'Apr 03 … 2020 GMT' into 2020-04-03")
try:
    dm.expand("SELECT $__nope(v) FROM vulns v")
    check(False, "unknown macros are refused")
except ValueError:
    check(True, "unknown macros are refused")
# every preset and specialist widget runs (and its drill) on this db
bad = []
for ref, d in widgets.builtin().items():
    if d.get("viz") == "text" or d.get("snapshot"):      # snapshots: tests/test_dashboards_510.py
        continue
    for drill in (False, True):
        try:
            f, _x, _y = boards.prepare(d, sc2, drill=drill)
            db.user_query(f"SELECT * FROM ({f}) LIMIT 2")
        except Exception as e:
            bad.append(f"{ref}{' drill' if drill else ''}: {e}")
check(not bad, "every library widget (and its drill) runs scoped: " + "; ".join(bad[:3]))
check(any(d["source"]["kind"] == "specialist" for d in widgets.builtin().values()), "specialists declare widgets in manifest.json")

# ── boards: seed, save (rev), sizes clamp, cache, run is explicit ──
bl = boards.list_boards()
check([b["name"] for b in bl][:1] == ["Ensemble wall"] and bl[0]["is_default"], "Ensemble wall is seeded as the default landing board")
b = boards.get(None)
b["layout"]["cols"] = 99
b["widgets"][1]["w"] = 50
b["widgets"][1]["h"] = 99
nb, err = boards.save(b)
check(err is None and nb["layout"]["cols"] == 24 and nb["widgets"][1]["w"] == 24 and nb["widgets"][1]["h"] == boards.MAX_H,
      "board columns / widget size are clamped on the server")
_, err = boards.save(dict(b, rev=1))
check(err == "conflict", "a stale rev is refused (two tabs can't overwrite each other)")
iid = nb["widgets"][1]["iid"]
check(boards.cached(nb)[iid]["state"] == "not_run", "opening a board runs nothing — not_run until ▶ Run")
res = boards.run_widget(nb, iid)
check(res["state"] == "fresh" and res["rows"], "▶ Run runs the widget")
check(boards.cached(nb)[iid]["state"] == "fresh" and boards.cached(nb)[iid]["cached"], "the result is served from the server cache")
check("db_fp" in res and "/" not in res["db_fp"], "results carry a navi.db fingerprint hash, not a path")
nb["scope"] = sc
nb2, _ = boards.save(nb)
check(boards.cached(nb2)[iid]["state"] == "not_run", "a new scope is a new cache entry (not run for this scope)")
info = boards.sql_info(nb2, iid)
check("tag_key='Tier'" in info["sql_full"] and info["defs"], "{ } SQL shows the scope expanded + definitions")
dat = boards.data(nb2, iid, 0, 2)
check(dat["size"] == 2 and "rows" in dat and dat["total"] is not None, "↗ Data is paged on the server")
# reorder persists
ws = nb2["widgets"]
ws.insert(0, ws.pop(3))
nb3, _ = boards.save(nb2)
check([w["iid"] for w in nb3["widgets"]][:1] == [ws[0]["iid"]], "widget order (reorder) persists")

# ── SQL widgets: validation + import review ──
for bad_sql in ("DELETE FROM assets", "SELECT 1; SELECT 2", "SELECT * FROM assets WHERE uuid=?", "ATTACH 'x' AS y"):
    try:
        boards.save_sql_widget({"title": "x", "sql": bad_sql})
        check(False, "refused: " + bad_sql)
    except ValueError:
        check(True, "refused: " + bad_sql)
ref = boards.save_sql_widget({"title": "Mine", "sql": "SELECT COUNT(*) n FROM assets a WHERE $__scope(a.uuid)", "viz": "kpi"})
doc = {"format": "navi-ensemble-board", "version": 1,
       "board": {"name": "Shared", "widgets": [{"ref": ref, "w": 3, "h": 2}, {"ref": "preset.kev_assets"}]},
       "sql_widgets": {ref: {"title": "Mine", "sql": "SELECT COUNT(*) n FROM assets a WHERE $__scope(a.uuid)", "viz": "kpi"}}}
ib = boards.import_doc(doc, origin="file")
wid = ib["widgets"][0]
check(boards.definition(wid["ref"])["review"], "SQL arriving in a file import needs review")
try:
    boards.run_widget(ib, wid["iid"])
    check(False, "unreviewed imported SQL does not run")
except PermissionError:
    check(True, "unreviewed imported SQL does not run")
boards.approve_sql(wid["ref"])
check(boards.run_widget(ib, wid["iid"])["state"] == "fresh", "after approval it runs")
ex = boards.export(ib["id"])
check('"rows":' not in json.dumps(ex) and ex["sql_widgets"], "export carries definitions only (no rows)")
lb = boards.import_doc({"name": "Old", "items": [{"title": "t", "sql": "SELECT 1 AS x", "r": {"viz": "kpi"}, "size": "s"}]}, origin="browser")
check(len(lb["widgets"]) == 1 and not boards.definition(lb["widgets"][0]["ref"])["review"], "a browser board migrates (the user's own SQL)")

# ── page + wiring (static) ──
page = open(os.path.join(ROOT, "web/dashboards.html"), encoding="utf-8").read()
check('data-page-cache="off"' in page, "dashboards page opts out of the page cache")
check("class=\"rsz\"" in page and "resizeStart" in page and "dragDrop" in page, "widgets resize (corner) and reorder (drag)")
check("id=\"bsize\"" in page and "id=\"lc\"" in page and "id=\"lr\"" in page and "id=\"lw\"" in page, "board size: columns, row height, width")
check("loadCached" in page and "widget_run" in page and "runstale" in page, "board opens from cache; runs only on ▶")
js = open(os.path.join(ROOT, "web/assets/console.js"), encoding="utf-8").read()
check("'/web/certdash.html'" in js[js.index("const DASH_PAGES"):js.index("function mountDashboardsNav")], "Certificates is in the Dashboards bar")
L = open(os.path.join(ROOT, "core/launcher.py"), encoding="utf-8").read()
check('"widget_run"' in L and '"board_save"' in L, "board actions bypass the short read cache")
m = json.load(open(os.path.join(ROOT, "agents/dashboard/manifest.json"), encoding="utf-8"))
from agents.dashboard import api  # noqa: E402
check(set(m["actions"]) == set(api.ACTIONS), "manifest actions == api ACTIONS")
cd = open(os.path.join(ROOT, "web/customdash.html"), encoding="utf-8").read()
check("agentApi('email')" not in cd, "Custom Dashboard header no longer turns into Notify & Report")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
