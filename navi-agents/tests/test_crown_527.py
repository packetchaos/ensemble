"""Build 527 — ONE crown-jewel definition on every page (core/crown.py): ACR ≥ the line in
Settings → Crown jewels (NAVI_CROWN_ACR, default 8). Before, the specialists disagreed (ACR > 7,
≥ 7, ≥ 9) so the same asset was a crown jewel on one page and not the next.
Run: python3 tests/test_crown_527.py"""
import glob
import os
import re
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="crown527_")
DB = os.path.join(TMP, "navi.db")
os.environ.update({"HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_DB_PATH": DB,
                   "NAVI_CACHE_DIR": os.path.join(TMP, "c"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db"),
                   "NAVI_CWD": TMP})
os.environ.pop("NAVI_CROWN_ACR", None)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes TEXT);
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, state TEXT, xrefs TEXT, cves TEXT);
""")
c.executemany("INSERT INTO assets VALUES (?,?,?,?,?)", [("a%d" % i, "h%d" % i, "10.0.0.%d" % i, str(i), "500") for i in range(1, 11)]
              + [("blank", "hb", "10.0.0.99", "", "")])
c.executemany("INSERT INTO tags VALUES (?,?,?)", [("a7", "Business Tier", "Crown Jewel"), ("a6", "PQC Priority", "Crown Jewel")])
c.commit()
c.close()

from core import crown  # noqa: E402
check(crown.threshold() == 8 and crown.label() == "ACR ≥ 8", "default line is ACR ≥ 8")
check(crown.is_crown(8) and crown.is_crown("9") and not crown.is_crown(7.9) and not crown.is_crown("") and not crown.is_crown(None),
      "is_crown: at or above the line; blank / missing ACR never")
for bad in ("0", "11", "x", "7.5"):
    check(not crown.valid(bad)[0], "Settings refuses %r" % bad)
os.environ["NAVI_CROWN_ACR"] = "junk"
check(crown.threshold() == 8, "a broken value falls back to the default")
os.environ.pop("NAVI_CROWN_ACR")

from core import asset_ownership as ao  # noqa: E402
k = ao.overview(DB)["kpi"]
check(k["crown"] == 3 and k["crown_acr"] == 8, "Asset Ownership: ACR 8, 9, 10 → 3 crown jewels (tags don't add any)")
from core import db  # noqa: E402
n = db.scalar("SELECT COUNT(*) FROM assets WHERE " + crown.sql("acr"), path=DB)
check(n == 3, "the SQL predicate counts the same 3 (blank ACR excluded)")
from core import dashmetrics  # noqa: E402
check(dashmetrics.expand if hasattr(dashmetrics, "expand") else True, "dashmetrics loads")

# changing the line: every cache signature moves, every count follows
from core import snapcache, launcher  # noqa: E402
s8, l8, f8 = snapcache.db_signature(DB), launcher._db_sig(), dashmetrics.fingerprint(DB)
os.environ["NAVI_CROWN_ACR"] = "6"
check(snapcache.db_signature(DB) != s8 and launcher._db_sig() != l8 and dashmetrics.fingerprint(DB) != f8,
      "a new line changes every cache signature (results rebuild)")
k = ao.overview(DB)["kpi"]
check(k["crown"] == 5 and k["crown_acr"] == 6, "…and the counts follow it (ACR ≥ 6 → 5)")
from core import widgets  # noqa: E402
t = widgets.builtin()["preset.crown_jewels"]["title"]
check("ACR ≥ 6" in t and "{CROWN}" not in t, "widget titles carry the live line (%s)" % t)
from core import evidence  # noqa: E402
from agents.ex_assets import api as eaapi  # noqa: E402
check("{CROWN}" in evidence.EVIDENCE["crown"]["label"] and "ACR ≥ 6" in crown.fill(evidence.EVIDENCE["crown"])["label"],
      "evidence labels are filled when served")
os.environ.pop("NAVI_CROWN_ACR")

# Settings: the field, validation, persistence key
from agents.settings import api as sapi  # noqa: E402
from core import config_store, gates  # noqa: E402
b, _ = sapi.status({})
check(b["crown"]["acr_min"] == 8 and any(f["key"] == "NAVI_CROWN_ACR" for f in b["env"]), "Settings reports the line and offers the field")
b, _ = sapi.set_env({"env": {"NAVI_CROWN_ACR": "12"}})
check("NAVI_CROWN_ACR" in (b.get("invalid") or {}) and crown.threshold() == 8, "Settings refuses an ACR outside 1–10")
b, _ = sapi.set_env({"env": {"NAVI_CROWN_ACR": "9"}})
check(b.get("applied") == ["NAVI_CROWN_ACR"] and crown.threshold() == 9 and b["crown"]["acr_min"] == 9, "Settings sets it live")
check("NAVI_CROWN_ACR" in config_store.MANAGED, "…and it survives a restart (config store)")
b, _ = sapi.set_env({"env": {"NAVI_CROWN_ACR": "8"}})
check(os.environ.get("NAVI_CROWN_ACR") is None and crown.threshold() == 8, "the default is stored as unset")
from core import health  # noqa: E402
check(health.health()["crown"]["acr_min"] == 8, "/api/health tells every page the line")

# no specialist keeps its own line any more
src = ""
for p in glob.glob(os.path.join(ROOT, "core", "*.py")) + glob.glob(os.path.join(ROOT, "agents", "*", "*.py")):
    if p.endswith("crown.py"):
        continue
    src += "\n".join("%s: %s" % (os.path.relpath(p, ROOT), ln) for ln in open(p, encoding="utf-8").read().splitlines()) + "\n"
own = [ln for ln in src.splitlines() if "HIGH_ACR" not in ln and re.search(r"CROWN_ACR\s*=\s*\d|crown[^\n]*acr[^\n]*(>=|>)\s*[79]\b|acr[^\n]*(>=|>)\s*[79]\b[^\n]*crown", ln, re.I)]
check(not own, "no specialist hard-codes its own crown line %s" % own[:4])
pages = ""
for p in glob.glob(os.path.join(ROOT, "agents", "*", "*.html")) + [os.path.join(ROOT, "web", "assets", "console.js")]:
    pages += open(p, encoding="utf-8").read()
pages = pages.replace("unclaimed crown jewels or high ACR (≥ 7)", "")    # Ownership's blind-spot rule, not the crown line
bad = re.findall(r"[^\n]{0,40}crown[^\n]{0,60}(?:ACR (?:≥|>|&gt;) ?[79]\b|ACR&nbsp;≥&nbsp;9|ACR 9–10)[^\n]{0,20}", pages, re.I)
check(not bad, "no page labels crown jewels with a fixed ACR %s" % bad[:3])
js = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
check("function crownAcr()" in js and "function crownTxt(" in js and "data-crown-txt" in js, "console.js: crownAcr() / crownTxt() for every page")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
