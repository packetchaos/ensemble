"""Build 499 — the Ownership specialist's crown-jewel triage: specialist findings grouped by what
they mean (signal_lanes), "no specialist findings" means no FINDING (context tags like Business
Tier don't count), and the crown summary strip's counts (KEV / open criticals / blind).
Run: python3 tests/test_crown_triage_499.py"""
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


from core import asset_ownership as eng  # noqa: E402

L = eng.signal_lanes({"CISA KEV": [], "Hounds-Attack Path": [], "Lifecycle EOL": [], "PQC Risk": [], "Cert Issue": [],
                      "Identity Risk": [], "NHI": [], "AI Inventory": [], "Scan Health": [], "Business Tier": [],
                      "Environment": [], "Class": []})
check(set(L["ex"]) == {"CISA KEV", "Hounds-Attack Path"}, "exploit lane: KEV + attack path (prefixed tag keys too)")
check(set(L["hy"]) == {"Lifecycle EOL", "PQC Risk", "Cert Issue"}, "lifecycle & crypto lane")
check(set(L["id"]) == {"Identity Risk", "NHI", "AI Inventory"}, "identity & AI lane")
check(L["vi"] == ["Scan Health"], "coverage lane")
check(not any(k in sum(L.values(), []) for k in ("Business Tier", "Environment", "Class")), "context tags are not findings")

TMP = tempfile.mkdtemp(prefix="cj499_")
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes INTEGER);
CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, xrefs TEXT, state TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
INSERT INTO assets VALUES ('c1','jewel1','10.0.0.1','10',0),('c2','jewel2','10.0.0.2','9',0),('c3','jewel3','10.0.0.3','9',0),('x','plain','10.0.0.9','3',0);
INSERT INTO vulns VALUES ('c1','1','k','critical','CISA-KNOWN-EXPLOITED:2024/01/01','open'),('c2','2','c','critical','','open');
INSERT INTO tags VALUES ('c1','CISA KEV','CVE-2024-1'),('c2','Lifecycle EOL','Win2012'),('c3','Business Tier','Production'),('c3','Owner','DB Team');
""")
c.commit()
c.close()
r = eng.overview(DB)
k = r["kpi"]
rows = {x["uuid"]: x for x in r["assets"]}
check(k["crown"] == 3 and k["crown_kev"] == 1 and k["crown_crit"] == 2, "crown strip: 3 jewels, 1 with KEV, 2 with open criticals")
check(k["crown_blind"] == 1 and rows["c3"]["risk_signals"] == 0 and rows["c3"]["signal_count"] == 1,
      "c3 has only a Business Tier tag → no specialist findings (blind)")
check(rows["c1"]["risk_signals"] == 1 and rows["c2"]["risk_signals"] == 1, "c1 / c2 each carry one finding")
check(all("risk_signals" in x for x in (r.get("crown_jewels") or [])), "crown rows carry risk_signals for the page")

shutil.rmtree(TMP, ignore_errors=True)
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
