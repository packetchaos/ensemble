"""Regression tests — build 500: Asset Classification learns from every agent's classification tags.

  · The IoT Discovery Squad tags what it FOUND — usually a vendor or product ('Device Type:
    Ubiquiti', 'IoT: pfSense', 'Device Type: Raspberry Pi Foundation'). Those used to land in
    Other; they now map through the Squad's vendor groups (pfSense → Network, Hikvision → IoT
    Camera, Siemens → OT, Draeger → Medical).
  · Keys other agents / customers write are read: IoT, OT, Network, Cloud, Mobile, Medical,
    Asset Type, Hounds- test-run names, and WAS tags (a web app known only through WAS).
  · New classes: Unix (AIX / Solaris / BSD), Medical, Web Application, Mainframe; an OS tag of
    Cisco IOS / iOS / ESXi lands in Network / Mobile / Virtual Infrastructure.
Run: python3 tests/test_classify_500.py"""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-500-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


c = sqlite3.connect(DB)
c.execute("CREATE TABLE assets (uuid text, hostname text, ip_address text, operating_system text, acr text, aes text)")
c.execute("CREATE TABLE vulns (asset_uuid text, plugin_id text, plugin_name text, output text, severity text, "
          "state text, xrefs text, cves text)")
c.execute("CREATE TABLE tags (asset_uuid text, tag_key text, tag_value text)")
# the tags the live navi.db actually carries (IoT Squad vendor names) + every other agent's keys
T = [("ubq", "Asset Inventory", "Device Type: Ubiquiti"),
     ("pfs", "Asset Inventory", "Device Type: pfSense"),
     ("rpi", "Asset Inventory", "Device Type: Raspberry Pi Foundation"),
     ("tv", "Asset Inventory", "Device Type: Samsung SmartTV"),
     ("nin", "Asset Inventory", "Device Type: Nintendo Co."),
     ("emb", "Asset Inventory", "Device Type: embedded"),
     ("xref", "IoT", "pfSense"),
     ("hik", "Hounds-IoT", "Hikvision"),
     ("plc", "OT", "PLC"),
     ("med", "Asset Inventory", "Device Type: Draeger"),
     ("sol", "Asset Inventory", "OS: Solaris 11"),
     ("rtr", "Asset Inventory", "OS: Cisco IOS 15.2"),
     ("esx", "Operating System", "VMware ESXi 8.0"),
     ("cos", "Asset Inventory", "OS: CentOS"),
     ("web", "WAS Technology", "Apache (v2.4.38)"),
     ("webl", "WAS Technology", "PHP (v7.2.34)"), ("webl", "Asset Inventory", "OS: Ubuntu"),
     ("mac", "Asset Inventory", "Device Type: Apple"), ("mac", "Asset Inventory", "OS: macOS"),
     ("old", "Asset Inventory", "Class: Network"),
     ("at", "Asset Type", "Firewall")]
for u in sorted({t[0] for t in T} | {"none"}):
    c.execute("INSERT INTO assets (uuid, hostname, operating_system) VALUES (?,?,?)", (u, u + "-host", ""))
c.executemany("INSERT INTO tags VALUES (?,?,?)", T)
c.commit()
c.close()

from core import classify  # noqa: E402
r = classify.classify()
by = {x["uuid"]: x for x in r["assets"]}
want = {"ubq": "Network", "pfs": "Network", "rpi": "IoT", "tv": "IoT", "nin": "IoT", "emb": "IoT",
        "xref": "Network", "hik": "IoT", "plc": "OT", "med": "Medical", "sol": "Unix", "rtr": "Network",
        "esx": "Virtual Infrastructure", "cos": "Linux", "web": "Web Application", "webl": "Linux",
        "mac": "macOS", "old": "Network", "at": "Network", "none": "Unclassified"}
got = {u: by[u]["cls"] for u in want}
for u, w in want.items():
    check(got[u] == w, "%s → %s (got %s, sub %r, via %s)" % (u, w, got[u], by[u]["sub"], by[u]["method"]))
check(not any(x["cls"] == "Other" for x in r["assets"]), "no IoT Squad vendor tag falls into Other")
check(by["pfs"]["sub"].startswith("Firewall") and by["hik"]["sub"].startswith("Camera"),
      "the sub names the kind of device and keeps the vendor: %r / %r" % (by["pfs"]["sub"], by["hik"]["sub"]))
names = [x["cls"] for x in r["classes"]]
check(names.index("Unix") < names.index("Medical") < names.index("Network") < names.index("Unclassified"),
      "new classes sit in the class order %s" % names)
check(r["stats"].get("medical") == 1 and r["stats"].get("webapps") == 1, "stats count Medical / Web Application")

# vocabulary
check(classify.vendor_type("Schneider APC")[0] == "UPS / Power" and classify.vendor_type("Schneider Modicon")[1] == "OT",
      "APC is power; Schneider otherwise OT")
check(classify.device_kind("Cisco SPA 504G")[0] == "VoIP" and classify.device_kind("Cisco")[1] == "Network",
      "a Cisco SPA phone is VoIP, a bare Cisco is network gear")
check(classify.vendor_type("Weird Gizmo") is None and classify._tag_class({"iot": "Weird Gizmo"})[0] == "IoT",
      "an unknown name under the IoT key is still IoT")
check([classify._os_to_class(o) for o in ("iOS 17", "Cisco IOS XE", "FreeBSD 14", "AIX 7.2", "z/OS 2.5", "Windows 11", "macOS 14")]
      == ["Mobile", "Network", "Unix", "Unix", "Mainframe", "Windows", "macOS"], "OS families")

# signals: a Solaris box is not 'Embedded'
c = sqlite3.connect(DB)
c.execute("INSERT INTO assets (uuid, hostname, operating_system) VALUES ('s10','sun-db','Oracle Solaris 10')")
c.execute("INSERT INTO assets (uuid, hostname, operating_system) VALUES ('ph','ph-1','Apple iOS 17.1')")
c.commit(); c.close()
sig = {(x["facet"], x["value"]) for x in classify.os_signals()["cohorts"]}
check(("OS", "Oracle Solaris 10") in sig and ("Device Type", "Embedded") not in sig,
      "Solaris is suggested as its OS, not Embedded %s" % sig)

pg = open(os.path.join(ROOT, "agents", "classify", "page.html"), encoding="utf-8").read()
check(all(('"%s":' % k) in pg for k in ("Unix", "Medical", "Web Application", "Mainframe")), "page has colours for the new classes")
print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
