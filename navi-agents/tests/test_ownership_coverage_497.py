"""Build 497 — routes and paths are METHODS of assigning plugins; ownership follows the findings.

CENTOS route = plugins P1, P2.  P1 found at /usr/lib64/a on A1 + A2; P2 at /usr/lib64/b on A2 + A3.
  1. alice owns the CENTOS route on A1-A3 → the route, BOTH paths and both plugins are 100% owned,
     every asset closed — and the paths count as covered through their route, not as assigned.
  2. bob takes /usr/lib64/b on A2 → still 100% everywhere; bob's workload is that one path; the
     path's owners are alice + bob; /usr/lib64/b is now assigned directly.
  3. alice's tag comes off A3 → the route and /usr/lib64/b drop to partial (A3), /usr/lib64/a stays owned.
  4. no route tag at all, every path tagged → the route is owned through its paths.
Run: python3 tests/test_ownership_coverage_497.py"""
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


TMP = tempfile.mkdtemp(prefix="cov497_")
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ["NAVI_TAGLOG_DB"] = os.path.join(TMP, "tag_jobs.db")
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE vulns (finding_id TEXT PRIMARY KEY, asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT,
  plugin_family TEXT, severity TEXT, state TEXT, xrefs TEXT, output TEXT, score TEXT, cves TEXT);
CREATE TABLE plugins (plugin_id TEXT PRIMARY KEY, name TEXT, severity TEXT, cves TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE vuln_route (route_id INTEGER PRIMARY KEY, app_name TEXT, plugin_list TEXT, total_vulns INTEGER, vuln_type TEXT);
CREATE TABLE vuln_paths (path_id INTEGER PRIMARY KEY, plugin_id TEXT, path TEXT, asset_uuid TEXT, finding_id TEXT);
INSERT INTO vulns VALUES ('f1','A1','P1','CentOS P1','fam','high','open','','','',''),
                         ('f2','A2','P1','CentOS P1','fam','high','open','','','',''),
                         ('f3','A2','P2','CentOS P2','fam','critical','open','','','',''),
                         ('f4','A3','P2','CentOS P2','fam','critical','open','','','','');
INSERT INTO plugins VALUES ('P1','CentOS P1','high',''),('P2','CentOS P2','critical','');
INSERT INTO vuln_route VALUES (1,'CENTOS',"['P1', 'P2']",4,'OS');
INSERT INTO vuln_paths(plugin_id,path,asset_uuid,finding_id) VALUES ('P1','/usr/lib64/a','A1','f1'),
  ('P1','/usr/lib64/a','A2','f2'),('P2','/usr/lib64/b','A2','f3'),('P2','/usr/lib64/b','A3','f4');
""")
c.commit()
c.close()
from agents.exproute import agent as ex  # noqa: E402


def tags(rows):
    c = sqlite3.connect(DB)
    c.execute("DELETE FROM tags")
    c.executemany("INSERT INTO tags VALUES (?, 'Owner', ?)", rows)
    c.commit()
    c.close()


def view():
    b = ex._base(DB)
    om = ex.ownership_map(DB, base=b)
    return ({r["name"]: r for r in om["routes"]}, {p["name"]: p for p in om["paths"]}, om["kpi"],
            ex.zipper(b, DB), ex.coverage(DB, base=b, om=om, users_total=0),
            {x["owner"]: x for x in om["owner_load"]})


# 1. own the route
tags([("A1", "CENTOS: alice"), ("A2", "CENTOS: alice"), ("A3", "CENTOS: alice")])
R, P, K, Z, C, L = view()
check(R["CENTOS"]["status"] == "owned" and R["CENTOS"]["coverage_pct"] == 100.0, "1: CENTOS route owned 100%")
check(all(P[p]["status"] == "owned" and P[p]["coverage_pct"] == 100.0 for p in P), "1: every CENTOS path owned 100%")
check(all(P[p].get("inherited") and P[p]["via_routes"] == ["CENTOS"] and P[p]["owners"] == ["alice"] for p in P),
      "1: …through the route (owners = alice)")
check(Z["plugins"]["owned"] == 2 and Z["findings"]["pct_owned"] == 100.0, "1: both plugins, every finding owned")
check(K["routes_owned"] == 1 and K["paths_owned"] == 2 and K["routes_assigned"] == 1 and K["paths_assigned"] == 0,
      "1: kpi — 1/1 routes, 2/2 paths covered; 1 route and 0 paths assigned directly")
check(C["closed"] == 3 and C["owned_paths"] == 2, "1: all 3 assets closed; coverage counts 2 owned paths (%s)" % C.get("owned_paths"))
check(set(L) == {"alice"} and L["alice"]["routes"] == 1 and L["alice"]["paths"] == 0, "1: alice's workload is the one route")
check(R["CENTOS"]["owner_assets"] == {"alice": 3.0} and P["/usr/lib64/a"]["owner_assets"] == {"alice": 2.0},
      "1: the Sankey shares — every asset alice's")

# 2. hand one path (on one asset) to bob
tags([("A1", "CENTOS: alice"), ("A2", "CENTOS: alice"), ("A3", "CENTOS: alice"), ("A2", "/usr/lib64/b: bob")])
R, P, K, Z, C, L = view()
check(R["CENTOS"]["status"] == "owned" and all(P[p]["status"] == "owned" for p in P) and C["closed"] == 3,
      "2: still 100% owned and closed after reassigning part of a path")
check(P["/usr/lib64/b"]["owners"] == ["alice", "bob"] and P["/usr/lib64/b"]["assigned"]
      and not P["/usr/lib64/b"].get("inherited"), "2: /usr/lib64/b — assigned to bob, covered by alice + bob")
check(K["paths_assigned"] == 1 and L["bob"]["paths"] == 1 and L["bob"]["assets"] == 1, "2: bob's workload: 1 path, 1 asset")
check(R["CENTOS"]["owners"] == ["alice"] and R["CENTOS"]["owner_assets"] == {"alice": 3.0},
      "2: the CENTOS route is still all alice's (bob's slice is on the path, not the route)")
check(P["/usr/lib64/b"]["owner_assets"] == {"alice": 1.0, "bob": 1.0},
      "2: /usr/lib64/b — bob on A2 (his own tag wins), alice on A3 through the route")

# 3. alice's tag off A3
tags([("A1", "CENTOS: alice"), ("A2", "CENTOS: alice")])
R, P, K, Z, C, L = view()
check(R["CENTOS"]["status"] == "partial" and R["CENTOS"]["findings_owned"] == 3 and R["CENTOS"]["owned_assets"] == 2,
      "3: route partial — 3 of 4 findings, 2 of 3 assets")
check(P["/usr/lib64/a"]["status"] == "owned" and P["/usr/lib64/b"]["status"] == "partial", "3: path a owned, path b partial")
check(Z["plugins"]["owned"] == 1 and Z["plugins"]["partial"] == 1 and C["closed"] == 2, "3: P1 owned, P2 partial, 2 assets closed")

# 4. no route tag — every path tagged
tags([("A1", "/usr/lib64/a: carol"), ("A2", "/usr/lib64/a: carol"), ("A2", "/usr/lib64/b: dave"), ("A3", "/usr/lib64/b: dave")])
R, P, K, Z, C, L = view()
check(R["CENTOS"]["status"] == "owned" and R["CENTOS"]["via_paths"] == ["/usr/lib64/a", "/usr/lib64/b"]
      and R["CENTOS"]["owners"] == ["carol", "dave"] and not R["CENTOS"]["assigned"],
      "4: the route is owned through its paths (carol + dave), not assigned")
check(K["routes_owned"] == 1 and K["routes_assigned"] == 0 and K["paths_assigned"] == 2, "4: kpi — covered 1, assigned 0 routes / 2 paths")
check(R["CENTOS"]["owner_assets"] == {"carol": 1.5, "dave": 1.5}, "4: the route's assets split between its path owners (A2 shared)")

shutil.rmtree(TMP, ignore_errors=True)
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
