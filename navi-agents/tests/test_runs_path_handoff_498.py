"""Build 498 — Exposure Routes / SLA Tracker report their runs like every other specialist, and a
path's detail is open findings only with who covers it.

  1. ▶ Run on Exposure Routes (snapshot + record_run) → one run in Done so far when the background
     build ends (action snapshot, ok, a real duration); a second Run served from cache → a cached
     run; a peek or a request without record_run (Run the Ensemble) → nothing recorded.
  2. The same for SLA Tracker.
  3. path_detail: a fixed finding's path rows don't count; owners split into the path's own and
     the route's (covering it on those assets); plugin names for the Remediation picker.
Run: python3 tests/test_runs_path_handoff_498.py"""
import os
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


TMP = tempfile.mkdtemp(prefix="run498_")
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ["NAVI_TAGLOG_DB"] = os.path.join(TMP, "tag_jobs.db")
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE vulns (finding_id TEXT PRIMARY KEY, asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT,
  plugin_family TEXT, severity TEXT, state TEXT, xrefs TEXT, output TEXT, score TEXT, cves TEXT,
  first_found TEXT, last_found TEXT);
CREATE TABLE assets (uuid TEXT PRIMARY KEY, hostname TEXT, ip_address TEXT, acr TEXT, url TEXT);
CREATE TABLE plugins (plugin_id TEXT PRIMARY KEY, name TEXT, severity TEXT, cves TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE vuln_route (route_id INTEGER PRIMARY KEY, app_name TEXT, plugin_list TEXT, total_vulns INTEGER, vuln_type TEXT);
CREATE TABLE vuln_paths (path_id INTEGER PRIMARY KEY, plugin_id TEXT, path TEXT, asset_uuid TEXT, finding_id TEXT);
INSERT INTO assets VALUES ('A1','h1','10.0.0.1','8',''),('A2','h2','10.0.0.2','5',''),('A3','h3','10.0.0.3','3','');
INSERT INTO vulns VALUES ('f1','A1','P1','OpenSSL old','fam','high','open','','','7','','2026-01-01','2026-11-01'),
  ('f2','A2','P1','OpenSSL old','fam','high','open','','','7','','2026-01-01','2026-11-01'),
  ('f3','A3','P1','OpenSSL old','fam','high','fixed','','','7','','2026-01-01','2026-11-01');
INSERT INTO plugins VALUES ('P1','OpenSSL old','high','');
INSERT INTO vuln_route VALUES (1,'OPENSSL',"['P1']",3,'App');
INSERT INTO vuln_paths(plugin_id,path,asset_uuid,finding_id) VALUES ('P1','/usr/lib/ssl','A1','f1'),
  ('P1','/usr/lib/ssl','A2','f2'),('P1','/usr/lib/ssl','A3','f3');
INSERT INTO tags VALUES ('A1','Owner','OPENSSL: alice'),('A2','Owner','/usr/lib/ssl: bob'),('A3','Owner','OPENSSL: carol');
""")
c.commit()
c.close()
from core import activity  # noqa: E402
from agents.exproute import api as xapi, agent as xag  # noqa: E402
xag.owners = lambda *a, **k: []          # no Tenable call for the owner directory
xag._owners_live = lambda: []


def runs(agent):
    return (activity.summary(agent).get("runs") or {})


def wait_build(api, body):
    o, _ = api.snapshot(body)
    for _ in range(300):
        p, _ = api.snapshot({"peek": True})
        if p.get("result") is not None and not p.get("building"):
            return o
        time.sleep(0.1)
    return o


# 1. Exposure Routes
o = wait_build(xapi, {"record_run": "er-test-1"})
r = runs("exproute")
check(o.get("building") and r.get("count") == 1, "exproute: a ▶ Run that builds → 1 run recorded (%s)" % r.get("count"))
check((r.get("last") or {}).get("action") == "snapshot" and (r.get("last") or {}).get("ok") == 1
      and (r.get("last") or {}).get("rid") == "er-test-1", "exproute: action snapshot, ok, the page's run id")
xapi.snapshot({"record_run": "er-test-2"})
r = runs("exproute")
check(r.get("count") == 2 and (r.get("last") or {}).get("cached") == 1, "exproute: a Run served from cache → a cached run")
xapi.snapshot({"peek": True, "record_run": "er-peek"})
xapi.snapshot({})
check(runs("exproute").get("count") == 2, "exproute: peek / no run id (Run the Ensemble) → nothing recorded")

# 2. SLA Tracker
from agents.sla import api as sapi  # noqa: E402
o, _ = sapi.snapshot({"record_run": "sl-test-1"})
for _ in range(300):
    p, _ = sapi.snapshot({"peek": True})
    if p.get("result") is not None and not p.get("building"):
        break
    time.sleep(0.1)
# SLA Tracker shows no Done so far panel (category Risk) — its run history is read directly
sl = activity._q("SELECT action, ok, rid FROM runs WHERE agent='sla'")
check(len(sl) == 1 and sl[0]["rid"] == "sl-test-1" and sl[0]["action"] == "snapshot" and sl[0]["ok"] == 1,
      "sla: a ▶ Run → 1 run in its history (%s)" % sl)
sapi.snapshot({"peek": True, "record_run": "sl-peek"})
check(len(activity._q("SELECT 1 FROM runs WHERE agent='sla'")) == 1, "sla: peek → nothing recorded")

# 3. path_detail
d = xag.path_detail("/usr/lib/ssl")
check(d.get("ok") and d["asset_count"] == 2 and {a["uuid"] for a in d["assets"]} == {"A1", "A2"},
      "path_detail: the fixed finding's asset (A3) is out")
check(d["path_owners"] == ["bob"] and d["route_owners"] == ["alice"] and d["owners"] == ["alice", "bob"],
      "path_detail: bob owns the path, alice covers it via the route (carol is only on A3)")
check(d["apps"] == ["OPENSSL"] and d["plugin_names"] == {"P1": "OpenSSL old"}, "path_detail: its route and plugin names")
check(all(a.get("ip") for a in d["assets"]), "path_detail: each host has an IP for the Remote Remediation hand-off")

shutil.rmtree(TMP, ignore_errors=True)
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
