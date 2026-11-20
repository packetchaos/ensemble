"""Build 511 — ✨ Ask AI for dashboard widgets + the semantic tables that make hard questions short
($__route_assets / $__path_assets / $__asset_facts / $__tag) + the Ownership analytics board.
The model is stubbed — no network. Run: python3 tests/test_dashboards_511.py"""
import json
import os
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="dash511_")
os.environ.update(NAVI_BOARDS_DB=os.path.join(TMP, "boards.db"), NAVI_CACHE_DIR=os.path.join(TMP, "cache"),
                  NAVI_TAGLOG_DB=os.path.join(TMP, "tag.db"), NAVI_BOARDS_DAILY="0")
DB = os.path.join(TMP, "navi.db")
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, operating_system TEXT, acr TEXT, last_found TEXT);
CREATE TABLE vulns(asset_uuid TEXT, asset_hostname TEXT, asset_ip TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT,
  state TEXT, xrefs TEXT, cves TEXT, output TEXT, score REAL, exploit TEXT, first_found TEXT, last_found TEXT);
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE vuln_route(route_id INTEGER, app_name TEXT, plugin_list TEXT, total_vulns INTEGER, vuln_type TEXT);
CREATE TABLE vuln_paths(path_id INTEGER, plugin_id TEXT, path TEXT, asset_uuid TEXT, finding_id TEXT);
INSERT INTO assets VALUES ('a1','fw1','10.0.0.1','FortiOS','9',''),('a2','fw2','10.0.0.2','FortiOS','5',''),
                          ('a3','srv','10.0.0.3','Linux','5',''),('a4','cam','10.0.0.4','','5','');
INSERT INTO tags VALUES ('a1','Device Type','Firewall'),('a2','Asset Inventory','Device Type: Firewall'),
                        ('a1','Owner','APACHE: alice'),('a3','Owner','APACHE: Ignored'),('a3','Business Tier','Prod'),
                        ('a2','Owner','apache: bob'),('a1','Owner','/opt/x: carol');
INSERT INTO vuln_route VALUES (1,'APACHE',"['100','101']",3,'Application'),(2,'CENTOS',"['200']",1,'Operating System'),
                              (3,'BROKEN','not json',0,'Application');
INSERT INTO vuln_paths VALUES (1,'100','/opt/x','a1','f'),(2,'100','/opt/x','a2','f');
""")
for (a, pid, st, out) in [("a1", "100", "open", ""), ("a2", "101", "OPEN", ""), ("a3", "100", "open", ""),
                          ("a4", "100", "fixed", ""), ("a3", "200", "open", ""),
                          ("a4", "54615", "open", "Remote device type : camera\nConfidence level : 70")]:
    c.execute("INSERT INTO vulns(asset_uuid,plugin_id,plugin_name,severity,state,xrefs,cves,output) VALUES (?,?,?,?,?,?,?,?)",
              (a, pid, "p" + pid, "info" if pid == "54615" else "high", st, "", "", out))
c.commit(); c.close()
os.environ["NAVI_DB_PATH"] = DB

from core import boards, dashai, dashmetrics as dm, db, llm, widgets  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


q = lambda s, sc=None: db.user_query(dm.expand(s, sc)[0])

ra = {(r["route"], r["asset_uuid"]): r for r in q("SELECT * FROM $__route_assets() ra")}
check(set(ra) == {("APACHE", "a1"), ("APACHE", "a2"), ("APACHE", "a3"), ("CENTOS", "a3")},
      "route_assets: one row per route × asset with an OPEN finding (fixed a4 out; a malformed plugin_list is skipped)")
check(ra[("APACHE", "a1")]["owned"] == 1 and ra[("APACHE", "a1")]["owner"] == "alice", "owned via '<route>: <user>'")
check(ra[("APACHE", "a2")]["owned"] == 1, "route name matches case-insensitively, like Exposure Routes")
check(ra[("APACHE", "a3")]["owned"] == 0 and ra[("APACHE", "a3")]["decided"] == 1, "Ignored is decided, not owned")
check(ra[("CENTOS", "a3")]["owned"] == 0 and ra[("CENTOS", "a3")]["decided"] == 0, "no Owner tag → unowned")
pa = q("SELECT path, asset_uuid, owned, owner FROM $__path_assets() pa ORDER BY asset_uuid")
check([(r["asset_uuid"], r["owned"]) for r in pa] == [("a1", 1), ("a2", 0)], "path_assets: owned via '<path>: <user>'")
af = {r["asset_uuid"]: r for r in q("SELECT * FROM $__asset_facts() af")}
check(af["a1"]["device_type"] == "Firewall" and af["a2"]["device_type"] == "Firewall", "device type from the tag and from Asset Inventory")
check(af["a4"]["device_type"] == "Camera" and af["a3"]["device_type"] == "Unclassified", "device type from Nessus 54615, else Unclassified")
check(af["a1"]["crown"] == 1 and af["a3"]["os_family"] == "Linux" and af["a1"]["has_owner_tag"] == 1, "crown / OS family / owner flag")
check(q("SELECT $__tag(a.uuid, 'Business Tier') t FROM assets a WHERE a.uuid='a3'")[0]["t"] == "Prod", "$__tag(col, 'Category')")
for bad in ("SELECT $__tag(a.uuid) FROM assets a", "SELECT * FROM $__route_assets(x) ra"):
    try:
        dm.expand(bad)
        check(False, "malformed semantic macro refused: " + bad)
    except ValueError:
        check(True, "malformed semantic macro refused: " + bad)
d = next(x for x in widgets.ANALYTICS if x["ref"] == "preset.routes_by_device_type")
rows = {r["device_type"]: r for r in q(d["sql"])}
check(rows["Firewall"]["Total routes"] == 1 and rows["Firewall"]["Owned routes"] == 1 and
      rows["Unclassified"]["Unowned routes"] == 2, "routes by device type: owned only when every asset of that type is")
sc = {"terms": [{"key": "Business Tier", "values": ["Prod"]}]}
check({r["device_type"] for r in q(d["sql"], sc)} == {"Unclassified"}, "the analytics follow the board scope")
nb = boards.create(template="ownership_analytics")
bad = []
for w in nb["widgets"]:
    try:
        boards.run_widget(nb, w["iid"])
        if boards.definition(w["ref"]).get("drill"):
            boards.data(nb, w["iid"], 0, 5)
    except Exception as e:
        bad.append(f"{w['ref']}: {e}")
check(not bad and len(nb["widgets"]) >= 10, f"Ownership analytics board runs end to end {bad[:2]}")

# ── Ask AI (model stubbed) ──
calls = []
GOOD = {"title": "Unowned routes by device type", "viz": "grouped", "label_col": "device_type", "value_col": "nope",
        "note": "n", "sql": d["sql"]}


def fake(system, user, max_tokens=0, timeout=0):
    calls.append((system, user))
    if len(calls) == 1:
        return json.dumps(dict(GOOD, sql="SELECT no_such_col FROM $__route_assets() ra WHERE $__scope(ra.asset_uuid)"))
    return "Here you go: " + json.dumps(GOOD)


llm.available = lambda: True
llm._messages = fake
out = dashai.ask("unowned routes by device type", None)
check(out["ok"] and out["attempts"] == 2, "a failing query goes back to the model once with the error")
check("no such column" in calls[1][1] and "previous answer failed" in calls[1][1], "the retry carries the SQL error")
check("$__route_assets()" in calls[0][0] and "Unowned routes" in calls[0][0], "the prompt teaches the semantic tables + worked examples")
check(out["spec"]["viz"] == "grouped" and out["spec"]["value_col"] is None and out["spec"]["label_col"] == "device_type",
      "spec normalised (unknown columns dropped)")
check(out["preview"]["rows"] and out["preview"]["scoped"], "preview rows from a read-only test run")
calls.clear()
llm._messages = lambda *a, **k: json.dumps(dict(GOOD, sql="DELETE FROM assets"))
out = dashai.ask("drop everything", None)
check(not out["ok"] and "SELECT" in out["error"], "a write the model proposes never runs")
llm.available = lambda: False
check(dashai.ask("x", None).get("needs_key"), "no model configured → says so (needs_key)")
try:
    dashai.preview("SELECT 1; DROP TABLE assets")
    check(False, "preview refuses multi-statement SQL")
except ValueError:
    check(True, "preview refuses multi-statement SQL")

from agents.dashboard import api  # noqa: E402
m = json.load(open(os.path.join(ROOT, "agents/dashboard/manifest.json"), encoding="utf-8"))
check({"ai_sql", "sql_preview"} <= set(m["actions"]) and set(m["actions"]) == set(api.ACTIONS), "manifest == api actions")
L = open(os.path.join(ROOT, "core/launcher.py"), encoding="utf-8").read()
check('"ai_sql"' in L and '"sql_preview"' in L, "AI / preview answers are never served from the read cache")
page = open(os.path.join(ROOT, "web/dashboards.html"), encoding="utf-8").read()
check('id="askai"' in page and "call('ai_sql'" in page and "call('sql_preview'" in page, "app: ✨ Ask AI + ▶ Preview")
viz = open(os.path.join(ROOT, "web/assets/dashviz.js"), encoding="utf-8").read()
check("v<=100)?100" in viz, "a single gauge value ≤ 100 reads as a percentage (no longer always full)")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
