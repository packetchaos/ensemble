"""Build 522 — the IoT specialist's "Done so far" panel sees the tags it actually writes
(Asset Inventory : 'Device Type: <device>'), never the Classifier's other Asset Inventory values,
and every specialist's panel offers Details ▾. Run: python3 tests/test_iot_panel_522.py"""
import os
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="iot522_")
os.environ.update(NAVI_DB_PATH=os.path.join(TMP, "navi.db"), NAVI_TAGLOG_DB=os.path.join(TMP, "tag.db"),
                  NAVI_CACHE_DIR=os.path.join(TMP, "c"))
c = sqlite3.connect(os.environ["NAVI_DB_PATH"])
c.executescript("""CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
INSERT INTO tags VALUES ('a1','Asset Inventory','Device Type: Camera'),('a2','Asset Inventory','Device Type: Camera'),
 ('a3','Asset Inventory','Device Type: Printer'),('a1','Asset Inventory','OS: Linux'),('a4','Asset Inventory','Role: Web'),
 ('a5','IoT','Hikvision'),('a6','Owner','bob');""")
c.commit()
c.close()
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import activity  # noqa: E402
fn = activity.summary
o = fn("iot_squad")
other = {(x["category"], x["value"]): x["assets"] for x in o["other"]}
check(other.get(("Asset Inventory", "Device Type: Camera")) == 2 and ("Asset Inventory", "Device Type: Printer") in other,
      "IoT panel lists the Device Type values it writes, with asset counts")
check(("IoT", "Hikvision") in other, "…and its own IoT category")
check(not any(v.startswith(("OS:", "Role:")) for (_c, v) in other) and ("Owner", "bob") not in other,
      "…but never the Classifier's other Asset Inventory values or other categories")
check(not activity.allowed_category("iot_squad", "Asset Inventory") or "Asset Inventory" in activity.DEFAULT_CATEGORIES["iot_squad"],
      "the panel scope doesn't widen what the IoT squad may write")
js = open(os.path.join(ROOT, "web/assets/console.js"), encoding="utf-8").read()
check("const hasDetail = true;" in js and "No tags yet in" in js, "every specialist's Done so far panel offers Details ▾ (with an empty state)")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
