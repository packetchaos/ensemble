"""Regression tests for core/acr_estate.py — the ACR page's estate metrics.

- ACR spread / bands / % match SQL truth, with navi.db's real quirks: ACR as TEXT '8.0',
  '' / ' ' / 'None' for missing values, AES NULL / 'None' (unscored) vs AES 0 (scored, no exposure).
- AES avg / top / bottom (bottom = lowest SCORED, never an unscored asset).
- Default vs changed: Ensemble-applied (ACR log) ∪ NO : UPDATE; assets in the log but gone from
  navi.db are not counted; drift only judged once navi.db is newer than the change.
- The cache: a second call is cached; a new ACR-log row or a navi.db rewrite invalidates it.
- /api/acr/metrics carries `estate` and still answers when the estate read fails.
Run: python3 tests/test_acr_estate.py  (or pytest)."""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="acr_estate_")
atexit.register(shutil.rmtree, TMP, True)
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB
os.environ["NAVI_TAGLOG_DB"] = os.path.join(TMP, "tag_jobs.db")
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")      # the estate snapshot

FAILS = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS.append(msg)


# ------------------------------------------------------------------ synthetic navi.db (navi's schema subset)
c = sqlite3.connect(DB)
c.execute("CREATE TABLE assets (ip_address text, hostname text, uuid text PRIMARY KEY, acr text, aes integer)")
c.execute("CREATE TABLE tags (asset_uuid text, tag_key text, tag_value text)")
rows = [  # uuid, acr, aes
    ("c1", "10.0", 900), ("c2", "9", 700), ("c3", "9.0", 100),          # critical: 2 AES High
    ("h1", "8.0", 500), ("h2", "7", None),                               # high (h2 unscored)
    ("m1", "5", 360), ("m2", "4.0", 0),                                  # medium (m2 AES 0 = scored)
    ("l1", "2", 800), ("l2", "1.0", "None"),                             # low: l1 AES High, l2 unscored
    ("n1", "", 50), ("n2", " ", 20), ("n3", "None", None), ("n4", None, 10),   # no ACR
]
for u, a, e in rows:
    c.execute("INSERT INTO assets VALUES (?,?,?,?,?)", ("10.0.0.%d" % len(u + str(a)), "host-" + u, u, a, e))
c.execute("INSERT INTO tags VALUES ('l1','NO','UPDATE')")             # protected, never changed by the Ensemble
c.execute("INSERT INTO tags VALUES ('c1','NO','UPDATE')")             # protected AND changed
c.execute("INSERT INTO tags VALUES ('m1','no','update')")             # NOT protection (case-sensitive)
c.commit()

from core import acr_estate as E, acrlog  # noqa: E402

r = E.estate(DB)
check(r["ok"] and r["total"] == 13 and r["with_acr"] == 9 and r["no_acr"] == 4,
      "counts: 13 assets, 9 rated, 4 with no ACR ('' / ' ' / 'None' / NULL)")
B = {b["band"]: b for b in r["acr_bands"]}
check((B["critical"]["assets"], B["high"]["assets"], B["medium"]["assets"], B["low"]["assets"]) == (3, 2, 2, 2),
      "bands: '10.0' and '9.0' parse; critical 3 · high 2 · medium 2 · low 2")
check(B["critical"]["pct"] == round(100 * 3 / 13, 1), "band % is of the whole estate (Tenable's CES panel reading)")
V = {v["acr"]: v["assets"] for v in r["acr_values"]}
check(V[9] == 2 and V[10] == 1 and V[3] == 0 and len(V) == 10, "per-value spread 10 → 1, zeros included")
check(r["avg_acr"] == round((10 + 9 + 9 + 8 + 7 + 5 + 4 + 2 + 1) / 9, 1), "average ACR over rated assets only")

A = r["aes"]
scored = [900, 700, 100, 500, 360, 0, 800, 50, 20, 10]
check(A["scored"] == 10 and A["unscored"] == 3, "AES: NULL and 'None' are unscored; 0 is scored")
check(A["avg"] == round(sum(scored) / 10) and A["max"] == 900 and A["min"] == 0, "AES avg / max / min")
check(A["zero"] == 1, "AES 0 counted separately")
check(A["top"][0]["uuid"] == "c1" and A["top"][0]["acr"] == 10, "top AES asset carries its ACR")
check(A["bottom"][0]["uuid"] == "m2" and all(x["aes"] is not None for x in A["bottom"]),
      "bottom AES = lowest scored (never an unscored asset)")
check({b["band"]: b["assets"] for b in A["bands"]} == {"high": 3, "medium": 2, "low": 5},
      "AES bands 650+ / 350–649 / 0–349")
check(r["crown_exposed"] == 2 and r["low_but_exposed"] == 1, "ACR 9–10 × AES High = 2; ACR 1–3 × AES High = 1")
check(abs(sum(b["aes_share_pct"] for b in r["acr_bands"]) - round(100 * (sum(scored) - 80) / sum(scored), 1)) < 0.5,
      "AES share by band excludes the no-ACR assets' AES")
ch = r["changed"]
check(ch["ensemble"] == 0 and ch["protected"] == 2 and ch["default"] == 7,
      "no ACR log yet: 2 protected (exact NO : UPDATE only), 7 no recorded change")
check(E.estate(DB)["cached"] is True, "second read is cached")

# ------------------------------------------------------------------ the Ensemble changes three assets
acrlog._ensure()
lc = sqlite3.connect(os.environ["NAVI_TAGLOG_DB"])
past = time.time() - 3600
for u, after in (("c1", "10"), ("h1", "9"), ("gone", "5")):     # h1 now 8 in navi.db → drift; 'gone' not in navi.db
    lc.execute("INSERT INTO acr_log(ts,batch,agent,category,value,mod,score,asset_uuid,acr_before,acr_after,"
               "status,reasons,result) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (past, "b1", "acr", "Env", "Prod", "set", after, u, "5", after, "changed", '["business"]', "applied"))
lc.commit()
os.utime(DB, None)                                               # navi.db synced after the change
r2 = E.estate(DB)
ch = r2["changed"]
check(r2["cached"] is False, "a new ACR-log row invalidates the cache")
check(ch["ensemble"] == 2 and ch["ensemble_not_in_db"] == 1, "changed: 2 in navi.db, 1 no longer in navi.db")
check(ch["either"] == 3 and ch["default"] == 6, "changed ∪ protected = c1, h1, l1 → 6 default")
check(ch["drift"] == 1 and ch["drift_checked"] == 2, "drift: h1 set to 9 but navi.db says 8")
VV = {v["acr"]: v for v in r2["acr_values"]}
check(VV[9]["assets"] == 2 and VV[9]["riskiest"]["uuid"] == "c2" and VV[10]["riskiest"]["uuid"] == "c1"
      and VV[2]["riskiest"]["aes"] == 800, "ACR values: riskiest (highest-AES) asset per value")
check(VV[10]["protected"] == 1 and VV[2]["protected"] == 1 and VV[8]["changed"] == 1 and VV[10]["changed"] == 1,
      "ACR values: protected (NO : UPDATE) and Ensemble-changed counts land on the current value")
check(VV[9]["aes_high"] == 1 and VV[9]["max_aes"] == 700 and VV[3]["assets"] == 0, "ACR values: AES mix + max per value")
B2 = {b["band"]: b for b in r2["acr_bands"]}
check(B2["critical"]["riskiest"]["uuid"] == "c1" and B2["critical"]["protected"] == 1, "bands: riskiest asset + protected")
check(len(ch["recent"]) == 3 and ch["recent"][0]["asset_uuid"] == "gone", "Who changed: latest applied changes, newest first")
from core import acr_estate as _E2  # noqa: E402
_E2._SNAP = None                                                 # a server restart: no in-memory state
check(_E2.estate(DB)["cached"] is True, "the estate snapshot survives a restart (on disk, core/snapcache)")
check(ch["by_reason"] == [{"reason": "business", "assets": 3}] and ch["by_agent"][0] == {"agent": "acr", "assets": 2},
      "reasons / agents roll up")

lc.execute("UPDATE acr_log SET ts=? WHERE asset_uuid='h1'", (time.time() + 3600,))
lc.execute("INSERT INTO acr_log(ts,asset_uuid,result) VALUES (?, '', 'no_assets')", (time.time(),))  # bump high-water
lc.commit()
check(E.estate(DB)["changed"]["drift"] == 0, "no drift claimed for a change newer than navi.db")

# ------------------------------------------------------------------ the API
from agents.acr import api  # noqa: E402
o, code = api.metrics({})
check(code == 200 and o["estate"]["ok"] and "protected" in o, "/api/acr/metrics carries estate + protection")
orig = E.estate
E.estate = lambda **k: (_ for _ in ()).throw(RuntimeError("boom"))
o, code = api.metrics({})
E.estate = orig
check(code == 200 and o["estate"]["ok"] is False and "boom" in o["estate"]["error"] and "protected" in o,
      "an estate failure never breaks the Protection metrics")

sqlite3.connect(DB).execute("CREATE TABLE x(a)").connection.close()
c2 = sqlite3.connect(os.path.join(TMP, "bare.db"))
c2.execute("CREATE TABLE assets (uuid text)")
c2.commit()
check(E.estate(os.path.join(TMP, "bare.db"))["ok"] is False, "older navi.db without acr/aes → clear error, no crash")

print("\n%d failure(s)" % len(FAILS))
sys.exit(1 if FAILS else 0)
