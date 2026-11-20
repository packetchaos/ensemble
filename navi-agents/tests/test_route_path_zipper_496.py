"""Build 496 — the route / path / plugin index ("zipper") behind Exposure Routes.

A hand-built navi.db where every finding's right answer is known:
  finding    route    paths                Owner tags on the asset           →
  P1 × A1    NGINX    /etc/nginx           NGINX: alice                       owned (route)
  P1 × A2    NGINX    —                    NGINX: Accepted                    decided
  P2 × A3    NGINX    —                    (/opt/app: carol — not this one)   unowned
  P3 × A1    JENKINS  /var/lib/jenkins     —                                  unowned
  P3 × A2    JENKINS  /opt/jenkins         /opt/jenkins: bob                  owned (path)
  P4 × A3    —        /opt/app             /opt/app: carol                    owned (path, no route)
  P5 × A4    —        —                    —                                  orphan
  P6 × A1    info finding                                                     not counted
  P7 × A4    FIXED finding at /fixed/path                                     not counted (nor its path)
Checks the index (⚡ Optimize) and the navi.db fallback agree, the rollups, per-asset path
inheritance, the ownership map / coverage numbers and that a route update marks the index
stale. No navi, no network. Run: python3 tests/test_route_path_zipper_496.py"""
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


TMP = tempfile.mkdtemp(prefix="rpp496_")
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ["NAVI_TAGLOG_DB"] = os.path.join(TMP, "tag_jobs.db")

c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE vulns (finding_id TEXT PRIMARY KEY, asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT,
  plugin_family TEXT, severity TEXT, state TEXT, xrefs TEXT, output TEXT, score TEXT, cves TEXT);
CREATE TABLE assets (uuid TEXT PRIMARY KEY, hostname TEXT);
CREATE TABLE plugins (plugin_id TEXT PRIMARY KEY, name TEXT, severity TEXT, cves TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE vuln_route (route_id INTEGER PRIMARY KEY, app_name TEXT, plugin_list TEXT, total_vulns INTEGER, vuln_type TEXT);
CREATE TABLE vuln_paths (path_id INTEGER PRIMARY KEY, plugin_id TEXT, path TEXT, asset_uuid TEXT, finding_id TEXT);
""")
F = [("f1", "A1", "P1", "high", "open"), ("f2", "A2", "P1", "high", "reopened"), ("f3", "A3", "P2", "medium", "open"),
     ("f4", "A1", "P3", "critical", "open"), ("f5", "A2", "P3", "critical", "OPEN"), ("f6", "A3", "P4", "low", "open"),
     ("f7", "A4", "P5", "medium", "open"), ("f8", "A1", "P6", "info", "open"), ("f9", "A4", "P7", "high", "fixed")]
c.executemany("INSERT INTO vulns(finding_id, asset_uuid, plugin_id, plugin_name, plugin_family, severity, state, xrefs, output) "
              "VALUES (?,?,?,?, 'fam', ?, ?, '', '')", [(f, a, p, "Plugin " + p, s, st) for f, a, p, s, st in F])
c.executemany("INSERT INTO assets VALUES (?, ?)", [(a, a.lower()) for a in ("A1", "A2", "A3", "A4")])
c.executemany("INSERT INTO plugins VALUES (?, ?, ?, '')", [("P%d" % i, "Plugin P%d" % i, "high") for i in range(1, 8)])
c.executemany("INSERT INTO vuln_route VALUES (?, ?, ?, 0, 'Application')",
              [(1, "NGINX", "['P1', 'P2']"), (2, "JENKINS", "['P3']"), (3, "FIXEDAPP", "['P7']")])
c.executemany("INSERT INTO vuln_paths(plugin_id, path, asset_uuid, finding_id) VALUES (?,?,?,?)",
              [("P1", "/etc/nginx", "A1", "f1"), ("P3", "/var/lib/jenkins", "A1", "f4"),
               ("P3", "/opt/jenkins", "A2", "f5"), ("P4", "/opt/app", "A3", "f6"), ("P7", "/fixed/path", "A4", "f9")])
c.executemany("INSERT INTO tags VALUES (?, 'Owner', ?)",
              [("A1", "NGINX: alice"), ("A2", "NGINX: Accepted"), ("A2", "/opt/jenkins: bob"), ("A3", "/opt/app: carol")])
c.commit()
c.close()

from core import hx_rpp, hx_summary  # noqa: E402
from agents.exproute import agent as ex  # noqa: E402

EXPECT = {("A1", "P1"): ("NGINX", ("/etc/nginx",)), ("A2", "P1"): ("NGINX", ()), ("A3", "P2"): ("NGINX", ()),
          ("A1", "P3"): ("JENKINS", ("/var/lib/jenkins",)), ("A2", "P3"): ("JENKINS", ("/opt/jenkins",)),
          ("A3", "P4"): (None, ("/opt/app",)), ("A4", "P5"): (None, ())}


def rows():
    return {(au, pid): (app, tuple(p)) for pid, au, app, p in hx_rpp.iter_findings(DB)}


def zip_and_map():
    b = ex._base(DB)
    return b, ex.zipper(b, DB), ex.ownership_map(DB, base=b), ex.coverage(DB, base=b, users_total=0)


# 1. fallback (no index yet)
check(not hx_rpp.usable(DB), "no index yet → fallback")
check(rows() == EXPECT, "fallback zips every open non-info finding to its route + paths (no info, no fixed)")
b, z, om, cov = zip_and_map()
check(z["source"] == "navi.db", "rollup says it came from navi.db")
fb = (z["findings"], z["plugins"], z["assets"], z["ratio"])

# 2. ⚡ Optimize builds the index → same rows, same rollup
wc = sqlite3.connect(DB, isolation_level=None)
r = hx_summary.build(wc)
wc.close()
hx_summary.invalidate()
st = hx_summary.state(DB, force=True)
check(r.get("ok") and st.get("rpp") == "7" and st.get("rpp_paths") == "4" and hx_rpp.usable(DB),
      "index built: 7 findings, 4 paths (the fixed finding's path dropped)")
check(rows() == EXPECT, "index rows == fallback rows")
b, z, om, cov = zip_and_map()
check(z["source"] == "index" and (z["findings"], z["plugins"], z["assets"], z["ratio"]) == fb,
      "index rollup == fallback rollup")

# 3. the rollup
f = z["findings"]
check((f["total"], f["owned"], f["decided"], f["unowned"], f["orphan"]) == (7, 3, 1, 2, 1),
      "findings: 7 = 3 owned + 1 decided + 2 unowned + 1 orphan (%s)" % f)
check(f["pct_owned"] == 42.9 and f["pct_covered"] == 57.1, "owned 42.9%, covered (owned + decided) 57.1%")
p = z["plugins"]
check((p["total"], p["owned"], p["decided"], p["partial"], p["unowned"], p["unrouted"]) == (5, 1, 1, 1, 1, 1),
      "plugins: P4 owned, P1 decided (owned + Accepted), P3 partial, P2 unowned, P5 unrouted (%s)" % p)
check(z["links"] == {"route_only": 2, "path_only": 1, "both": 3, "neither": 1}, "reach: route only / path only / both / neither")
check(z["assets"] == {"total": 4, "closed": 0, "open": 4, "ownerless": 1},
      "assets: none closed (A2's NGINX finding is only Accepted); A4 ownerless (%s)" % z["assets"])
check({g["name"]: g["closes"] for g in z["gap_routes"]} == {"NGINX": 1, "JENKINS": 1},
      "close the gap: tagging NGINX or JENKINS closes 1 finding each")
check([(g["name"], g["closes"]) for g in z["gap_paths"]] == [("/var/lib/jenkins", 1)], "…or tagging /var/lib/jenkins")
check(z["ratio"]["routes_one_path"] == 1 and z["ratio"]["routes_many_paths"] == 1 and z["ratio"]["one_to_one"] == 1
      and z["ratio"]["paths_no_route"] == 1, "ratio: NGINX 1:1, JENKINS 1:many, /opt/app on no route")
top = {t["plugin_id"]: t for t in z["top_plugins"]}
check(set(top) == {"P1", "P2", "P3", "P5"} and top["P3"]["status"] == "partial" and top["P5"]["status"] == "unrouted"
      and top["P3"]["name"] == "Plugin P3", "unowned plugin list: P2, P3 (partial), P5 (unrouted), with names")

# 4. ownership map + coverage use the same per-finding truth
paths = {x["name"]: x for x in om["paths"]}
check(paths["/etc/nginx"]["status"] == "owned" and paths["/etc/nginx"].get("inherited")
      and paths["/etc/nginx"]["via_routes"] == ["NGINX"], "/etc/nginx owned on A1 through its plugin's route (per asset)")
check(paths["/opt/jenkins"]["status"] == "owned" and not paths["/opt/jenkins"].get("inherited"), "/opt/jenkins owned directly")
check("/fixed/path" not in paths and "FIXEDAPP" not in {x["name"] for x in om["routes"] if x["assets"]},
      "a fixed finding's path and route carry no assets")
routes_ = {x["name"]: x for x in om["routes"]}
check(routes_["NGINX"]["assets"] == 3 and routes_["JENKINS"]["assets"] == 2, "route assets count open non-info findings only")
check(om["kpi"]["unowned_assets"] == 1, "Ownerless Risk = 1 asset (A4)")
check(cov["closed"] == 0 and cov["route_findings"] == 5 and cov["path_findings"] == 4 and cov["total_paths"] == 4,
      "coverage: 0 closed, 5 route findings, 4 path findings, 4 paths (%s)"
      % {k: cov[k] for k in ("closed", "route_findings", "path_findings", "total_paths")})
load = {x["owner"]: x for x in om["owner_load"]}
check("alice" in load and load["alice"]["paths"] == 0, "inherited paths don't add to the route owner's workload")

# 5. the snapshot carries it
snap = ex.build_snapshot(DB)
check(snap.get("zip", {}).get("findings", {}).get("total") == 7, "snapshot includes the zipper")

# 6. a route rebuild makes the index stale (navi doesn't touch vulns for that) → fallback
c = sqlite3.connect(DB)
c.execute("UPDATE vuln_route SET plugin_list = \"['P1', 'P2', 'P5']\" WHERE route_id = 1")
c.commit()
c.close()
hx_summary.invalidate()
check(not hx_rpp.usable(DB) and hx_summary.usable(DB), "route update → index stale (other summaries still fresh)")
b, z, om, cov = zip_and_map()
check(z["source"] == "navi.db" and z["findings"]["orphan"] == 0 and z["plugins"]["unrouted"] == 0,
      "…and the fallback sees the new route at once (P5 now routed)")

# 7. a tag view
b = ex._base(DB, scope=("Owner", "NGINX: alice"))
z = ex.zipper(b, DB)
check(z["findings"]["total"] == 2 and z["assets"]["total"] == 1, "tag view: only that tag's asset's findings")

shutil.rmtree(TMP, ignore_errors=True)
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
