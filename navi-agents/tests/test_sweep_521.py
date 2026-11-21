"""Build 521 — bug + security sweep fixes (each one was reproduced by a reviewer AND an independent
validator before it was fixed). Run: python3 tests/test_sweep_521.py"""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="sweep521_")
os.environ.update({"HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "tag.db"),
                   "NAVI_BOARDS_DB": os.path.join(TMP, "boards.db"), "NAVI_CACHE_DIR": os.path.join(TMP, "c"),
                   "NAVI_DB_PATH": os.path.join(TMP, "navi.db"), "IOT_REGISTRY_PATH": os.path.join(TMP, "iot.json"),
                   "NAVI_BOARDS_DAILY": "0", "NAVI_CWD": TMP})
for k in ("NAVI_ALLOW_WRITES", "NAVI_REMOTE_CODE_EXECUTION", "NAVI_EMAIL", "NAVI_SCAN_LAUNCH"):
    os.environ.pop(k, None)
c = sqlite3.connect(os.environ["NAVI_DB_PATH"])
c.executescript("CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT); INSERT INTO assets VALUES ('a1','h','10.0.0.1');"
                "CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, output TEXT, state TEXT);"
                "CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);")
c.commit()
c.close()
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ── S1: one truth table for the gates ─────────────────────────────────────────────────────
from core import gates, navi_cli  # noqa: E402
from agents.settings import api as sapi  # noqa: E402
_real_lo = gates.client_is_loopback
GATES = ("NAVI_ALLOW_WRITES", "NAVI_REMOTE_CODE_EXECUTION", "NAVI_EMAIL", "NAVI_SCAN_LAUNCH")
gates.client_is_loopback = lambda: False                           # a remote token-holder
for val in ("t", "y", "enabled", "TRUE", "On"):
    b, _ = sapi.set_env({"env": {k: val for k in GATES}})
    check(not b.get("applied") and set((b.get("refused") or {})) == set(GATES) and not navi_cli.allow_writes(),
          "S1: remote %r can't raise any gate (was the bypass)" % val)
    b, _ = sapi.set_env({"env": {k: val for k in GATES}, "confirm": True})
    check(not b.get("applied"), "S1: …not even with confirm from a remote peer (%r)" % val)
gates.client_is_loopback = lambda: True                            # this machine
b, _ = sapi.set_env({"env": {"NAVI_REMOTE_CODE_EXECUTION": "enabled"}})
check(not b.get("applied") and "confirm" in str(b.get("refused")), "S1: loopback still needs confirm:true to raise a gate")
b, _ = sapi.set_env({"env": {"NAVI_ALLOW_WRITES": "enabled"}, "confirm": True})
check(b.get("applied") == ["NAVI_ALLOW_WRITES"] and os.environ.get("NAVI_ALLOW_WRITES") == "1",
      "S1: an ON value is stored as exactly \"1\"")
b, _ = sapi.set_env({"env": {"NAVI_EMAIL": "maybe"}, "confirm": True})
check(not b.get("applied") and "NAVI_EMAIL" in (b.get("invalid") or {}), "S1: anything that isn't on/off is refused")
gates.client_is_loopback = lambda: False
b, _ = sapi.set_env({"env": {"NAVI_ALLOW_WRITES": "0"}})
check(b.get("applied") == ["NAVI_ALLOW_WRITES"] and not navi_cli.allow_writes(), "S1: turning a gate OFF is still always allowed")
gates.client_is_loopback = _real_lo
b, _ = sapi.status({})
check("other_users" in b and "token_required" in b, "S2: Settings reports other logged-in users (shared-machine warning)")
check("Shared machine" in open(os.path.join(ROOT, "web/settings.html"), encoding="utf-8").read(), "S2: …and shows the warning chip")

# ── S4: IoT plugin ids are digits only ─────────────────────────────────────────────────────
from core import iot_common, iot_registry  # noqa: E402
PAY = "0') OR substr((SELECT access_key FROM keys),1,1)='A')--"
r = iot_registry.apply_decisions([{"iot_name": "ProbeA", "plugin_id": PAY, "approve": True},
                                  {"iot_name": "Cam", "plugin_id": "12345", "approve": True}])
reg = iot_registry.load()
pids = [p for d in reg["detections"] for p in d.get("plugins") or []]
check(PAY not in pids and "12345" in pids and r.get("rejected", 0) >= 1, "S4: a non-numeric plugin id is never stored")
json.dump({"detections": [{"iot_name": "X", "plugins": [PAY, "222"], "signal_plugins": [PAY]}]},
          open(os.environ["IOT_REGISTRY_PATH"], "w"))
check(iot_registry.load()["detections"][0]["plugins"] == ["222"], "S4: a swapped-in registry file is cleaned on load")
w = iot_common._detection_where({"iot_name": "X", "plugins": [PAY, "222"], "signal_plugins": [PAY]})
check(w is None or ("keys" not in w and "'222'" in w), "S4: the SQL builder ignores non-numeric ids")

# ── B1 / B2 / B8 / B9: Scan Confirmation ──────────────────────────────────────────────────
from core import scan_confirm as sc  # noqa: E402
con = sc._con()
now = time.time()
for rid, state, launched, status in (("20261001-000000-aaaaaa", "VERIFIED", now - 40 * 86400, "completed"),
                                     ("20261120-000000-bbbbbb", "RUNNING", now - 600, "running"),
                                     ("20261002-000000-cccccc", "VERIFIED", now - 40 * 86400, "completed")):
    con.execute("INSERT INTO scan_runs(run_id, created, updated, state, request_json) VALUES (?,?,?,?,?)",
                (rid, launched, launched, state, "{}"))
con.execute("INSERT INTO scan_run_scans(run_id, plan_index, scan_id, status, launched) VALUES (?,?,?,?,?)",
            ("20261001-000000-aaaaaa", 0, "4242", "completed", now - 40 * 86400))
con.execute("INSERT INTO scan_run_scans(run_id, plan_index, scan_id, status, launched) VALUES (?,?,?,?,?)",
            ("20261120-000000-bbbbbb", 0, "4242", "running", now - 600))           # the SAME scan, reused, live
con.execute("INSERT INTO scan_run_scans(run_id, plan_index, scan_id, status, launched) VALUES (?,?,?,?,?)",
            ("20261002-000000-cccccc", 0, "5151", "completed", now - 40 * 86400))
con.commit()
con.close()
ids = {r["scan_id"] for r in sc.deletable_scans(30)}
check("4242" not in ids and "5151" in ids, "B1: a reused scan a live run still uses is never offered for deletion")

from core import cli_jobs  # noqa: E402
bad = 0
for i in range(25):
    rid = "20261121-%06d-dddddd" % i
    con = sc._con()
    con.execute("INSERT INTO scan_runs(run_id, created, updated, state, request_json) VALUES (?,?,?,?,?)",
                (rid, now, now, "PREFLIGHT", "{}"))
    con.commit()
    con.close()

    def fn(_rid, emit, live, ev):
        sc.set_state(_rid, "LAUNCHING")
        time.sleep(0.3)
        return {"ok": True}
    sc.start(rid, fn=fn)
    time.sleep(0.05)
    if sc.get_run(rid)["state"] != "LAUNCHING":
        bad += 1
check(bad == 0, "B2: starting a run never writes the old state back over the worker's (%d/25 wrong)" % bad)
check("PREFLIGHT" in open(os.path.join(ROOT, "core/scan_confirm.py"), encoding="utf-8").read().split("def nonterminal_runs")[1][:400],
      "B2: a run interrupted in PREFLIGHT can be resumed")
check(sc.SYNC_TIMEOUT_S >= 7200 and "threads=1" not in open(os.path.join(ROOT, "core/scan_confirm.py"), encoding="utf-8").read(),
      "B8: a scoped sync gets ≥ 2 hours, and there's no slower threads=1 retry")
from agents.scan_confirm import api as scapi  # noqa: E402
rid = "20261121-999999-eeeeee"
con = sc._con()
con.execute("INSERT INTO scan_runs(run_id, created, updated, state, request_json) VALUES (?,?,?,?,?)", (rid, now, now, "VERIFIED", "{}"))
con.executemany("INSERT INTO scan_run_verdicts VALUES (?,?,?,?,?,?,?)",
                [(rid, "u%06d" % i, 1001, "t", "NOT_VULNERABLE", "R7", "{}") for i in range(120)])
con.commit()
con.close()
scapi.EXPORT_PAGE = 50
got, off, pages = [], 0, 0
while off is not None:
    b, _ = scapi.export({"run_id": rid, "offset": off})
    got += [ln for ln in b["csv"].splitlines() if ln and not ln.startswith("asset_uuid")]
    off, pages = b["next_offset"], pages + 1
check(len(got) == 120 and len(set(got)) == 120 and pages == 3, "B9: the CSV export pages through every row (no silent cap, no repeats)")

# ── B3 / B5: dashboards ───────────────────────────────────────────────────────────────────
from core import boards  # noqa: E402
bd = boards.create(name="race")
res = []
barrier = threading.Barrier(2)


def save(n):
    barrier.wait()
    res.append(boards.save(dict(bd, name=n))[1])
ts = [threading.Thread(target=save, args=(n,)) for n in ("one", "two")]
[t.start() for t in ts]
[t.join() for t in ts]
check(sorted(x or "ok" for x in res) == ["conflict", "ok"], "B3: two saves with the same rev — exactly one wins (%s)" % res)
pg = open(os.path.join(ROOT, "web/dashboards.html"), encoding="utf-8").read()
check("while(_saving)" in pg and "saveSoon(0)" in pg, "B3: the page sends one save at a time and keeps edits made while saving")
b2 = boards.create(name="comment")
sw = boards.save_sql_widget({"title": "n", "sql": "SELECT COUNT(*) AS n FROM assets -- total assets", "viz": "table"})
sw_ref = sw if isinstance(sw, str) else ((sw[0] if isinstance(sw, tuple) else sw).get("ref") or "sql." + str((sw[0] if isinstance(sw, tuple) else sw)["id"]))
w_ = {"iid": "w1", "ref": sw_ref if sw_ref.startswith("sql.") else "sql." + sw_ref, "w": 4, "h": 3}
b2 = boards.save(dict(b2, widgets=[w_]))[0]
try:
    d = boards.data(b2, b2["widgets"][0]["iid"], 0, 10)
    check(bool(d), "B5: a widget whose SQL ends in a -- comment still opens its data / CSV")
except Exception as e:
    check(False, "B5: trailing -- comment breaks widget data: %s" % e)

# ── B4: the streamed navi runner works without a pty (the Windows path) ───────────────────
fake = os.path.join(TMP, "navi")
open(fake, "w").write("#!/usr/bin/env python3\nfor i in range(3000): print('line', i)\nprint('I started your scan, your scan ID is: 7')\n")
os.chmod(fake, 0o755)
os.environ["NAVI_BIN"] = fake
_had = cli_jobs._HAS_PTY
cli_jobs._HAS_PTY = False
r = cli_jobs.run_navi_streamed([], lambda _l: None, None, None, 30)
cli_jobs._HAS_PTY = _had
check(r["rc"] == 0 and len(r["lines"]) == 3001 and r["lines"][-1].endswith("is: 7") and not r["timed_out"],
      "B4: the pipe (no-pty / Windows) path streams every line")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
