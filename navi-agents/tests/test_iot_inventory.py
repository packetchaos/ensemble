"""Regression tests for the IoT device inventory (build 503, core/iot_inventory.py) — the
At a glance → table → Argos / CSV / tag flow on the IoT Discovery page.

- A real squad run over the sample navi.db, inflated with 200 clones of its Ubiquiti device and 30
  cameras seen only by Ethernet OUI (Hikvision) + Device Type 'camera' (plugin 54615):
  the inventory has 1 row per device asset, Ubiquiti = 201 confirmed, the cameras are PREDICTED
  'Camera · Hikvision' (Device Type now parses 'camera' — it read 'unknown' before build 503).
- build_rows(): strongest status wins (confirmed > identified > predicted), the rest go to `also`;
  cross-term proposals (kind new / cross) add predicted rows from the FULL asset set (not the 200
  the payload keeps); kind 'confirm' adds nothing.
- drill / inventory_export / inventory_tag work by run + filter KEY only (no UUIDs from the page),
  validate filters, scheme and value, refuse without confirm, answer an expired run cleanly, and
  the CSV defuses formula cells. The run payload stays small (no UUID arrays in `inventory`).
Run: python3 tests/test_iot_inventory.py  (or pytest)."""
import atexit
import csv
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import uuid as _uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-iotinv-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ["NAVI_TAGLOG_DB"] = os.path.join(TMP, "tag_jobs.db")
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB
REG = os.path.join(TMP, "iot_detections.json")
shutil.copy(os.path.join(ROOT, "data", "iot_detections.json"), REG)
os.environ["IOT_REGISTRY_PATH"] = REG
shutil.copy(os.path.join(ROOT, "sample_navi.db"), DB)

FAILS = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS.append(msg)


# ------------------------------------------------------------------ inflate the sample navi.db
c = sqlite3.connect(DB)
cols = lambda t: [r[1] for r in c.execute("pragma table_info(%s)" % t)]  # noqa: E731
ac, vc, cc = cols("assets"), cols("vulns"), cols("certs")
UBI = c.execute("SELECT asset_uuid FROM certs WHERE lower(common_name||organization) LIKE '%ubnt%' "
                "OR lower(common_name||organization) LIKE '%ubiquiti%' LIMIT 1").fetchone()[0]
arow = c.execute("SELECT * FROM assets WHERE uuid=?", (UBI,)).fetchone()
vrows = c.execute("SELECT * FROM vulns WHERE asset_uuid=?", (UBI,)).fetchall()
crows = c.execute("SELECT * FROM certs WHERE asset_uuid=?", (UBI,)).fetchall()
ui, ipi, hi = ac.index("uuid"), ac.index("ip_address"), ac.index("hostname")
vu, cu = vc.index("asset_uuid"), cc.index("asset_uuid")
vip = vc.index("asset_ip") if "asset_ip" in vc else None
ins = lambda t, r: c.execute("INSERT INTO %s VALUES (%s)" % (t, ",".join("?" * len(r))), r)  # noqa: E731
for i in range(200):
    nu, ip = str(_uuid.uuid4()), "10.50.%d.%d" % (i // 250, i % 250 + 1)
    a = list(arow); a[ui], a[ipi], a[hi] = nu, ip, "unifi-cam-%03d" % i
    ins("assets", a)
    for v in vrows:
        v = list(v); v[vu] = nu
        if vip is not None:
            v[vip] = ip
        ins("vulns", v)
    for x in crows:
        x = list(x); x[cu] = nu
        ins("certs", x)
CAMS = []
pid, out = vc.index("plugin_id"), vc.index("output")
for i in range(30):
    nu, ip = str(_uuid.uuid4()), "10.60.0.%d" % (i + 1)
    CAMS.append(nu)
    a = list(arow); a[ui], a[ipi], a[hi] = nu, ip, "=cam-lobby-%02d" % i     # '=' → CSV formula guard
    ins("assets", a)
    for p_, text in (("35716", "The following card manufacturers were identified :\n\n44:19:b6:00:00:%02x : "
                               "Hangzhou Hikvision Digital Technology Co.,Ltd." % i),
                     ("54615", "Remote device type : camera\nConfidence level : 65")):
        v = list(vrows[0]); v[vu], v[pid], v[out] = nu, p_, text
        if "plugin_name" in vc:          # never inherit the Ubiquiti plugin's name (the registry matches on it)
            v[vc.index("plugin_name")] = "Ethernet Card Manufacturer Detection" if p_ == "35716" else "Device Type"
        if "severity" in vc:
            v[vc.index("severity")] = "info"
        if vip is not None:
            v[vip] = ip
        ins("vulns", v)
c.commit()

# ------------------------------------------------------------------ Device Type parsing (signals)
from core import signals, iot_inventory as INV, payload  # noqa: E402
check(signals._DEVTYPE.search("Remote device type : camera\nConfidence level : 65").group(1) == "camera"
      and signals._DEVTYPE.search("Remote device type : wireless-access-point").group(1) == "wireless-access-point"
      and signals._DEVTYPE.search("a switch somewhere in text") is None,
      "54615 Device Type: camera / wireless-access-point parse; a stray word no longer does")
check(INV.vendor_short("Hangzhou Hikvision Digital Technology Co.,Ltd.") == "Hikvision"
      and INV.vendor_short("Ubiquiti Inc") == "Ubiquiti", "vendor_short trims city / corporate words")
check(INV.type_label("camera") == "Camera" and INV.type_label("wireless-access-point") == "Wireless Access Point",
      "Tenable Device Type → the Classifier's label")

# ------------------------------------------------------------------ the squad run → inventory
from agents.iot_squad import api  # noqa: E402
from core import navi_cli  # noqa: E402

o, code = api.run({"use_pack": False})
inv = o["result"]["inventory"]
check(code == 200 and o["ok"] and inv.get("run") and not inv.get("error"), "▶ Run publishes the inventory")
check(inv["total"] == 8 + 200 + 30, "one row per device asset: 8 sample + 200 Ubiquiti + 30 cameras (%s)" % inv["total"])
D = {d["name"]: d for d in inv["devices"]}
check(D.get("Ubiquiti", {}).get("assets") == 201 and D["Ubiquiti"]["status"] == "confirmed",
      "Ubiquiti: 201 confirmed by the registry")
check(D.get("Camera · Hikvision", {}).get("predicted") == 30 and D["Camera · Hikvision"]["type_label"] == "Camera",
      "30 signal-only cameras → predicted 'Camera · Hikvision', tag default 'Camera'")
check([d["name"] for d in inv["predicted"]] == ["Camera · Hikvision"], "predicted list = what you didn't know")
P = inv["predicted"][0]
check(P["assets"] == 30 and P["predicted"] == 30 and inv["predicted_total"] == 1 and P["types"] == ["Camera"]
      and P["why"].startswith("signals:") and inv["predicted_conf"] == {"High": 30, "Medium": 0, "Low": 0},
      "🔮 predicted rollup: predicted assets only, type, evidence, confidence mix")
U = D["Ubiquiti"]
check(U["top"]["uuid"] and U["top"]["aes"] == U["max_aes"] and U["related"] == ["Ubiquiti"] and U["types"] == ["Switch"]
      and U["crit"] == 201 and U["avg_acr"] is not None,
      "🧭 device rollup: riskiest asset (Dossier link), vendors, type, exposure, max AES / avg ACR")
V = {v["name"]: v for v in inv["vendors"]}
check(V["Ubiquiti"]["related"] == ["Ubiquiti"] and V["Hangzhou Hikvision Digital Technology Co.,Ltd."]["related"]
      == ["Camera · Hikvision"], "🧭 vendor rollup lists the vendor's devices")
T = {d["name"]: d["assets"] for d in inv["types"]}
check(T.get("camera") == 30 and T.get("switch") == 201, "device types from 54615 (camera 30, switch 201)")
check(inv["status"]["predicted"] == 30 and inv["status"]["confirmed"] >= 201, "status counts")
blob = json.dumps(inv)
check(len(blob) < 200_000 and not any(isinstance(v, list) and len(v) > payload.TOP_MAX for v in inv.values()),
      "inventory payload small; no list over TOP_MAX")
check(len(inv["first"]["top"]) <= 50 and inv["first"]["total"]["value"] == inv["total"], "first page ships, total exact")

RUN = inv["run"]
d, code = api.drill({"run": RUN, "section": "devices", "filter": ["dev:Ubiquiti"], "limit": 200})
check(code == 200 and d["total"]["value"] == 201 and all(r["device"] == "Ubiquiti" for r in d["top"]),
      "drill dev:Ubiquiti → 201 rows")
d, _ = api.drill({"run": RUN, "section": "devices", "filter": ["type:camera", "st:predicted"], "limit": 5})
check(d["total"]["value"] == 30 and d["top"][0]["why"].startswith("signals:"), "type + status filters AND; row says why")
d, _ = api.drill({"run": RUN, "section": "devices", "filter": ["vendor:Ubiquiti"], "q": "unifi-cam-01", "limit": 50})
check(d["total"]["value"] == 10, "vendor filter + server-side search (unifi-cam-010…019)")
check(api.drill({"run": RUN, "section": "devices", "filter": ["evil"]})[1] == 400, "unknown filter refused")

# CSV — every row of the list, formula cells defused
e, code = api.inventory_export({"run": RUN, "filter": ["dev:Camera · Hikvision"]})
rows = list(csv.reader(io.StringIO(e["csv"])))
check(code == 200 and e["rows"] == 30 and rows[0] == INV.CSV_COLS and len(rows) == 31, "CSV: header + all 30 rows")
check(all(r[0].startswith("'=") for r in rows[1:]), "CSV: '=…' hostnames are defused")

# tag — by KEY; stub navi so nothing runs
seen = {}
navi_cli.tag_set = lambda cat, val, uuids=None, **k: (seen.update(cat=cat, val=val, uuids=list(uuids), k=k)
                                                    or [{"ok": True, "queued": True, "job_id": 7, "message": "queued"}])
check(api.inventory_tag({"run": RUN, "filter": ["dev:Ubiquiti"], "value": "Camera"})[1] == 400, "tag needs confirm")
t, code = api.inventory_tag({"run": RUN, "filter": ["dev:Ubiquiti"], "value": "Camera", "confirm": True})
check(code == 200 and t["ok"] and seen["cat"] == "Asset Inventory" and seen["val"] == "Device Type: Camera"
      and len(seen["uuids"]) == 201 and seen["k"].get("agent") == "iot_squad",
      "device_type scheme → Asset Inventory : Device Type: Camera on all 201 (tag_set pages it)")
t, code = api.inventory_tag({"run": RUN, "filter": ["st:predicted"], "scheme": "iot", "value": "Hikvision Camera",
                             "confirm": True})
check(code == 200 and seen["cat"] == "IoT" and seen["val"] == "Hikvision Camera" and sorted(seen["uuids"]) == sorted(CAMS),
      "iot scheme → IoT : <name> on exactly the 30 predicted cameras")
check(api.inventory_tag({"run": RUN, "filter": [], "value": "x'; drop", "confirm": True})[1] == 400, "quotes refused")
check(api.inventory_tag({"run": RUN, "filter": [], "scheme": "Vendor", "value": "x", "confirm": True})[1] == 400,
      "unknown scheme refused")
check(api.inventory_tag({"run": RUN, "filter": [], "uuids": ["x"], "value": "x", "confirm": True})[0]["asset_count"]
      == inv["total"], "a uuids field from the page is ignored — the set is the run's list")
x, code = api.inventory_export({"run": "iot_squad-0000000000000000"})
check(code == 200 and x.get("expired"), "expired run → {expired:true}, press ▶ Run")

# ------------------------------------------------------------------ build_rows (crafted run)
res = {"discovery": {"detected": [
    {"asset_uuid": "a1", "iot_name": "UniFi AP", "vendor": "Ubiquiti", "hostname": "ap1", "ip": "1.1.1.1"},
    {"asset_uuid": "a1", "iot_name": "Camera / Ubiquiti", "fused": True, "klass": "Camera / Ubiquiti",
     "signals": ["cert"], "type": "camera"},
    {"asset_uuid": "a2", "iot_name": "Axis", "fused": True, "klass": "Embedded / candidate", "signals": ["OUI:Axis"],
     "type": "unknown", "vendor": "Axis Communications AB", "conf": "Medium"},
    {"asset_uuid": "a3", "iot_name": "x", "fused": True, "klass": "Chromecast / Nest", "signals": ["cert", "mDNS"]}]},
    "proposals": [
        {"key": "k1", "kind": "new", "iot_name": "Sonos", "plugin_id": "24260", "term": "sonos", "asset_uuids": ["s1"],
         "warnings": []},
        {"key": "k2", "kind": "confirm", "iot_name": "UniFi AP", "plugin_id": "1", "term": "unifi", "asset_uuids": ["z9"]},
        {"key": "k3", "kind": "cross", "iot_name": "Chromecast", "plugin_id": "2", "term": "cast", "asset_uuids": ["a3"],
         "warnings": ["broad"]}]}
R = {r["uuid"]: r for r in INV.build_rows(res, {"k1": ["s1", "s2", "s3"]})}
check(R["a1"]["status"] == "confirmed" and R["a1"]["device"] == "UniFi AP" and R["a1"]["also"] == ["Camera / Ubiquiti"]
      and R["a1"]["device_type"] == "camera", "strongest status wins; the other finding goes to `also`, type kept")
check(R["a2"]["status"] == "predicted" and R["a2"]["device"] == "Axis" and R["a2"]["vendor"] == "Axis Communications AB",
      "signal-only, no device type → predicted under the squad's name")
check(R["a3"]["status"] == "identified" and R["a3"]["also"] == ["Chromecast"], "certificate → identified; x-term adds `also`")
check(all(R.get(u, {}).get("status") == "predicted" and R[u]["device"] == "Sonos" for u in ("s1", "s2", "s3"))
      and "24260" in R["s1"]["why"], "x-term 'new' → predicted from the FULL set, with the plugin as the why")
check("z9" not in R, "x-term 'confirm' adds no row")

print("\n%d failure(s)" % len(FAILS))
sys.exit(1 if FAILS else 0)
