"""Build 498 — the Ownership specialist (asset_ownership) counts ownership on PLUGINS (open,
non-info findings) with routes and paths as the ways they're assigned — the same rule as
Exposure Routes (core/hx_rpp).

CENTOS route = P1, P2.  A1: P1 at /usr/lib64/a, P2 at /usr/lib64/b.  P9 has no route, sits at
/opt/x on A1.  P8 is info, P7 is fixed — neither counts.
  1. A1 tagged `CENTOS: alice` only → 2 of its 3 open findings owned (the CentOS ones, both
     paths covered by the route) → 66.7% claimed (it was 1 of 4 route/path items before).
  2. + `/opt/x: bob` → 100% claimed.
  3. The Asset Owner cascade ('complete') tags the route + only the path of the unrouted
     finding — not the CentOS paths the route already covers; 'remainder' after step 1 tags
     only /opt/x.
Run: python3 tests/test_ownership_specialist_498.py"""
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


TMP = tempfile.mkdtemp(prefix="own498_")
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ.pop("NAVI_ALLOW_WRITES", None)
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes INTEGER);
CREATE TABLE vulns (finding_id TEXT, asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, xrefs TEXT, state TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE vuln_route (route_id INTEGER, app_name TEXT, plugin_list TEXT);
CREATE TABLE vuln_paths (asset_uuid TEXT, plugin_id TEXT, path TEXT, finding_id TEXT);
INSERT INTO assets VALUES ('A1','host1','10.0.0.1','7',0);
INSERT INTO vuln_route VALUES (1,'CENTOS',"['P1', 'P2', 'P7']");
INSERT INTO vulns VALUES ('f1','A1','P1','c1','high','','open'),('f2','A1','P2','c2','critical','','open'),
  ('f9','A1','P9','x','medium','','open'),('f8','A1','P8','info','info','','open'),('f7','A1','P7','old','high','','fixed');
INSERT INTO vuln_paths VALUES ('A1','P1','/usr/lib64/a','f1'),('A1','P2','/usr/lib64/b','f2'),('A1','P9','/opt/x','f9'),
  ('A1','P7','/usr/lib64/old','f7');
""")
c.commit()
c.close()
from core import asset_ownership as eng  # noqa: E402


def tags(rows):
    c = sqlite3.connect(DB)
    c.execute("DELETE FROM tags")
    c.executemany("INSERT INTO tags VALUES (?,?,?)", rows)
    c.commit()
    c.close()


def row():
    r = eng.overview(DB)
    return {x["uuid"]: x for x in r["assets"]}["A1"], r["kpi"]


tags([("A1", "Owner", "CENTOS: alice")])
a, k = row()
check(a["surface"] == 3 and a["routes"] == 1 and a["paths"] == 3, "1: surface = 3 open findings on 1 route / 3 paths (info + fixed out)")
check(a["claimed_pct"] == 66.7 and k["surface_owned"] == 2, "1: route tag owns both CentOS findings → 66.7%% claimed (%s)" % a["claimed_pct"])

tags([("A1", "Owner", "CENTOS: alice"), ("A1", "Owner", "/opt/x: bob")])
a, k = row()
check(a["claimed_pct"] == 100.0 and k["fully_claimed"] == 1, "2: + the unrouted finding's path → 100% claimed")

tags([])
casc = eng.owner_cascade(["A1"], "carol", "complete", DB)
check(set(casc) == {"CENTOS: carol", "/opt/x: carol"}, "3: complete cascade = the route + the unrouted path only (%s)" % sorted(casc))
tags([("A1", "Owner", "CENTOS: alice")])
casc = eng.owner_cascade(["A1"], "carol", "remainder", DB)
check(set(casc) == {"/opt/x: carol"}, "3: remainder after the route is owned = /opt/x only (%s)" % sorted(casc))

shutil.rmtree(TMP, ignore_errors=True)
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
