"""Build 510 — specialist widgets read the specialist's own last run, KPI trend lines (+ opt-in
daily snapshots), Compliance and Certificates as templated boards, Builder → "Add to board".
Run: python3 tests/test_dashboards_510.py"""
import json
import os
import sqlite3
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="dash510_")
os.environ["NAVI_BOARDS_DB"] = os.path.join(TMP, "boards.db")
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ["NAVI_TAGLOG_DB"] = os.path.join(TMP, "tag.db")
os.environ["NAVI_BOARDS_DAILY"] = "0"
DB = os.path.join(TMP, "navi.db")
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, operating_system TEXT, acr TEXT, last_found TEXT);
CREATE TABLE vulns(asset_uuid TEXT, asset_hostname TEXT, asset_ip TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT,
  state TEXT, xrefs TEXT, cves TEXT, output TEXT, score REAL, exploit TEXT, first_found TEXT, last_found TEXT);
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE certs(asset_uuid TEXT, common_name TEXT, issuer_name TEXT, not_valid_after TEXT, signature_algorithm TEXT, key_length TEXT);
CREATE TABLE compliance(asset_uuid TEXT, audit_file TEXT, check_name TEXT, status TEXT, actual_value TEXT, expected_value TEXT);
INSERT INTO assets VALUES ('u0','h0','10.0.0.1','Linux','9','2026-11-01');
INSERT INTO tags VALUES ('u0','Tier','Prod');
INSERT INTO compliance VALUES ('u0','CIS.audit','chk','FAILED','a','b');
INSERT INTO certs VALUES ('u0','cn','CN=x','Apr 03 16:07:23 2020 GMT','sha256',2048);
""")
c.commit(); c.close()
os.environ["NAVI_DB_PATH"] = DB

from core import boards, dashmetrics as dm, pagecache, widgets  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def kev_entry(n):
    return {"at": int(time.time() * 1000), "title": "CISA KEV", "steps": [], "final": {},
            "resp": {'POST /api/cisakev/run {"approved":true}': {"status": 200, "body": {"ok": True, "result": {
                "kev": {"metrics": {"overdue_assets": n, "due7_assets": 2, "due30_assets": 1, "recent_assets": 0,
                                    "ransomware_assets": 5, "crown_overdue_assets": 1}}}}}}}


ok, err = pagecache.put("/agents/cisakev/page.html", kev_entry(14))
check(ok, "fixture: whole-estate CISA KEV run in the page cache " + str(err or ""))
pagecache.put("/agents/cisakev/page.html?tk=Tier&tv=Prod", kev_entry(9))

d = widgets.builtin()["cisakev.kev_overdue"]
check(d.get("snapshot") and not d.get("sql"), "a specialist widget can be a snapshot of its own run (no SQL)")
r = boards.snapshot_result(d, None)
check(r["state"] == "fresh" and r["rows"][0]["Assets with overdue KEVs"] == 14, "snapshot reads the whole-estate run")
r = boards.snapshot_result(d, {"terms": [{"key": "Tier", "values": ["Prod"]}]})
check(r["rows"][0]["Assets with overdue KEVs"] == 9 and "tk=Tier" in r["open"], "a one-tag scope reads that tag's run")
r = boards.snapshot_result(d, {"terms": [{"key": "Tier", "values": ["Dev"]}]})
check(r["state"] == "not_run", "a tag the specialist hasn't run on is 'not run' — never another scope's number")
r = boards.snapshot_result(d, {"terms": [{"key": "Tier", "values": ["Prod", "Dev"]}]})
check(r["state"] == "scope_unsupported", "a multi-value scope can't be matched to a one-tag run")
r = boards.snapshot_result(widgets.builtin()["cisakev.kev_due"], None)
check([x["label"] for x in r["rows"]][:2] == ["Overdue", "Due ≤ 7 days"], "a snapshot can return several labelled values")
check(widgets.summary(d)["snapshot"], "the library marks snapshot widgets")

# board with a snapshot widget: cached/run/sql/data
b = boards.get(None)
names = [w["ref"] for w in b["widgets"]]
check("cisakev.kev_overdue" in names, "the Ensemble wall carries the specialists' last-run widgets")
iid = next(w["iid"] for w in b["widgets"] if w["ref"] == "cisakev.kev_overdue")
check(boards.cached(b)[iid]["state"] == "fresh", "board load serves the snapshot widget")
info = boards.sql_info(b, iid)
check(info["snapshot"] and info["lineage"] and info["open"].startswith("/agents/cisakev/"), "{ } shows lineage + where to open it")
try:
    boards.data(b, iid)
    check(False, "snapshot widgets send ↗ to the specialist page")
except LookupError:
    check(True, "snapshot widgets send ↗ to the specialist page")

# trends
k = next(w for w in b["widgets"] if w["ref"] == "preset.assets_in_scope")
res = boards.run_widget(b, k["iid"])
full, _x, _y = boards.prepare(boards.definition(k["ref"]), b.get("scope"))
con = boards._con()
con.execute("INSERT OR REPLACE INTO trend VALUES (?,?,?,?)", (boards._ckey(full), "2000-01-01", 5.0, 0))
con.commit(); con.close()
t = boards.cached(b)[k["iid"]].get("trend")
check(t and t[0] == ["2000-01-01", 5.0] and t[-1][1] == 1.0, "KPI runs leave one trend point per day (cached result carries them)")
check(boards._kpi_value([{"a": "x", "n": 3}]) == 3.0 and boards._kpi_value([{"a": 1}, {"a": 2}]) is None, "only one-row KPIs trend")

# daily snapshots
b["layout"]["daily"] = True
b, _ = boards.save(b)
check(b["layout"]["daily"] is True, "Board size → daily snapshot is saved with the board")
con = boards._con(); con.execute("DELETE FROM trend"); con.commit(); con.close()
boards._daily_pass()
t = boards.cached(b)[k["iid"]].get("trend")
check(t and t[-1][0] == time.strftime("%Y-%m-%d"), "the daily pass snapshots a daily board's KPIs")

# templates
for tpl, must in (("compliance", "compliance.pass_rate"), ("certificates", "certificate.expired")):
    nb = boards.create(template=tpl)
    refs = [w["ref"] for w in nb["widgets"]]
    missing = [r for r in refs if not boards.definition(r)]
    check(must in refs and not missing and nb["kind"] == "template:" + tpl, f"{tpl} template board ({missing})")
    bad = []
    for w in nb["widgets"]:
        try:
            boards.run_widget(nb, w["iid"])
        except Exception as e:
            bad.append(f"{w['ref']}: {e}")
    check(not bad, f"every {tpl} widget runs: {bad[:2]}")

# pages
P = lambda f: open(os.path.join(ROOT, f), encoding="utf-8").read()
page = P("web/dashboards.html")
check("trendHtml" in page and "openSpecialist" in page and "ldaily" in page and "qs('template')" in page,
      "app: trend lines, open-in-specialist, daily toggle, ?template=")
check("template=compliance" in P("web/compliancedash.html") and "template=certificates" in P("web/certdash.html"),
      "Compliance / Certificate dashboards link to their board")
check("dashBoardAdd" in P("agents/dashboard/page.html") and "/api/dashboard/sql_save" in P("agents/dashboard/page.html"),
      "Builder → Add to board saves a SQL widget onto a server board")
check("indexOf('__')!==0" in P("web/assets/dashviz.js") and "indexOf('__')!==0" in P("web/customdash.html"),
      "__coverage-style helper columns no longer show as headline numbers")
check("opacity:.35" not in P("web/customdash.html"), "Custom Dashboard ⋯ is no longer faint")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
