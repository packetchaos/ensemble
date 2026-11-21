"""Build 523 — Asset Ownership "At a glance" numbers agree with the data.

  * crown jewels = ACR >= 9, or a business tier / criticality tag (Crown Jewel / Mission Critical /
    Tier 1). Another specialist's label that happens to read "Crown Jewel" (Post-Quantum's
    `PQC Priority: Crown Jewel`, Scan Health's `Crown Jewel Blind Spot`) is NOT a crown jewel —
    it put ACR 7-8 assets under the "crown jewels · ACR >= 9" tile on the live navi.db.
  * "fully claimed" means every open finding: 1,999 of 2,000 handled used to round to 100.0 % and
    count as fully claimed (and show 100 % in the table).
Run: python3 tests/test_ownership_kpi_523.py"""
import os
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="own523_")
DB = os.path.join(TMP, "navi.db")
os.environ.update({"HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_DB_PATH": DB,
                   "NAVI_CACHE_DIR": os.path.join(TMP, "c"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db"),
                   "NAVI_CWD": TMP})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT);
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, state TEXT, xrefs TEXT);
CREATE TABLE vuln_route(app_name TEXT, plugin_list TEXT, route_id TEXT);
CREATE TABLE vuln_paths(asset_uuid TEXT, plugin_id TEXT, path TEXT);
""")
c.executemany("INSERT INTO assets VALUES (?,?,?,?)", [
    ("p1", "pqc", "10.0.0.1", "8"),      # PQC's own "Crown Jewel" label only -> NOT a crown jewel
    ("s1", "scan", "10.0.0.2", "7"),     # Scan Health "Crown Jewel Blind Spot" -> NOT a crown jewel
    ("b1", "tier", "10.0.0.3", "5"),     # Business Tier: Crown Jewel -> crown jewel
    ("h1", "hi", "10.0.0.4", "9"),       # ACR 9 -> crown jewel
    ("big", "big", "10.0.0.5", "4"),     # 2,000 findings, 1,999 owned -> NOT fully claimed
    ("all", "all", "10.0.0.6", "4"),     # 3 findings, all owned -> fully claimed
])
c.executemany("INSERT INTO tags VALUES (?,?,?)", [
    ("p1", "PQC Priority", "Crown Jewel"), ("s1", "Scan Health", "Crown Jewel Blind Spot"),
    ("s1", "Scan Health", "Crown Jewel"), ("b1", "Business Tier", "Crown Jewel"),
    ("big", "Owner", "Owned App: Team A"), ("all", "Owner", "Owned App: Team A")])
owned_pids = ["%d" % (100000 + i) for i in range(1999)]
c.execute("INSERT INTO vuln_route VALUES (?,?,?)", ("Owned App", str(owned_pids), "1"))
c.execute("INSERT INTO vuln_route VALUES (?,?,?)", ("Stray App", "['299999']", "2"))
c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?)",
              [("big", p, "x", "high", "open", "") for p in owned_pids] + [("big", "299999", "x", "high", "open", "")]
              + [("all", p, "x", "high", "open", "") for p in owned_pids[:3]])
c.commit()
c.close()

from core import asset_ownership as ao  # noqa: E402
r = ao.overview(DB)
k = r["kpi"]
rows = {a["uuid"]: a for a in r["assets"]}
check({a["uuid"] for a in r["crown_jewels"]} == {"b1", "h1"} and k["crown"] == 2,
      "crown jewels are ACR >= 9 or a Business Tier tag — not PQC / Scan Health labels (%s)"
      % sorted(a["uuid"] for a in r["crown_jewels"]))
check(not rows["p1"]["crown"] and not rows["s1"]["crown"], "…the PQC- and Scan-Health-labelled assets aren't flagged 👑")
check(rows["big"]["surface"] == 2000 and rows["big"]["claimed_pct"] < 100, "1,999 of 2,000 owned is not shown as 100 %% (%s)"
      % rows["big"]["claimed_pct"])
check(rows["all"]["claimed_pct"] == 100.0, "every finding owned is 100 %")
check(k["with_surface"] == 2 and k["fully_claimed"] == 1, "fully claimed counts only assets with every finding handled (%s of %s)"
      % (k["fully_claimed"], k["with_surface"]))
check(k["surface_items"] == 2003 and k["surface_owned"] == 2002, "findings: 2,003 open, 2,002 owned")
check(k["owned"] + k["no_owner"] == k["assets"] == 6, "owned + no owner = every asset")
st = ao.overview_store(DB)
full = [a for a in r["assets"] if "full" in ao._row_flags(a)]
check([a["uuid"] for a in full] == ["all"] and st["kpi"]["fully_claimed"] == len(full),
      "the 'fully claimed' table filter matches the tile")
pg = open(os.path.join(ROOT, "agents/asset_ownership/page.html"), encoding="utf-8").read()
check("dispositioned or closed" not in pg, "the findings tile no longer claims to count closed findings")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
