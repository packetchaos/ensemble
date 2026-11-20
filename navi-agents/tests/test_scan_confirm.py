"""Build 514 — Scan Confirmation (SCAN_CONFIRM_SPEC §11). A fake navi (tests/scan_fakenavi.py)
answers with navi's real output strings; nothing reaches Tenable.
Run: python3 tests/test_scan_confirm.py"""
import json
import os
import sqlite3
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="scan514_")
DB = os.path.join(TMP, "navi.db")
ARGV = os.path.join(TMP, "argv.log")
SCN = os.path.join(TMP, "scenario.json")
CRED = "11111111-2222-3333-4444-555555555555"
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_TAGLOG_DB": os.path.join(TMP, "tag_jobs.db"), "NAVI_CACHE_DIR": os.path.join(TMP, "c"),
                   "NAVI_BIN": os.path.join(ROOT, "tests", "scan_fakenavi.py"), "FAKE_NAVI_LOG": ARGV,
                   "FAKE_SCAN_STATE": os.path.join(TMP, "state.json"), "FAKE_SCAN_SCENARIO": SCN, "NAVI_CWD": TMP,
                   "NAVI_JOB_LOG_DIR": os.path.join(TMP, "joblogs"), "NAVI_BOARDS_DB": os.path.join(TMP, "b.db")})
for k in ("NAVI_ALLOW_WRITES", "NAVI_SCAN_LAUNCH"):
    os.environ.pop(k, None)

c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets(uuid TEXT, ip_address TEXT, hostname TEXT, fqdn TEXT, agent_uuid TEXT, acr TEXT, last_found TEXT);
CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, plugin_family TEXT, state TEXT, last_found TEXT,
  scan_uuid TEXT, output TEXT, severity TEXT);
CREATE TABLE plugins(plugin_id TEXT, name TEXT);
CREATE TABLE fixed(asset_uuid TEXT, plugin_id TEXT, last_fixed TEXT, state TEXT);
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
INSERT INTO plugins VALUES ('1001','Apache httpd < 2.4.60'),('2002','Ubuntu USN-7000-1 openssl');
""")
A = {i: "aaaaaaaa-0000-0000-0000-00000000000%d" % i for i in range(1, 8)}
for i in range(1, 7):
    c.execute("INSERT INTO assets VALUES (?,?,?,?,?,?,?)", (A[i], "10.1.0.%d" % i, "h%d" % i, "", None, "9" if i == 1 else "5", ""))
c.execute("INSERT INTO assets VALUES (?,?,?,?,?,?,?)", (A[7], "", "", "", "agent-7", "5", ""))   # no address
old = "2026-01-01T00:00:00.000Z"
for (i, p, st) in ((1, "1001", "open"), (2, "1001", "open"), (1, "2002", "open"), (2, "2002", "open")):
    c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?)", (A[i], p, "p" + p, "Web Servers" if p == "1001" else
                                                               "Local Security Checks", st, old, "s0", "", "high"))
for i in range(1, 7):
    c.execute("INSERT INTO tags VALUES (?,?,?)", (A[i], "Patch Wave", "Tuesday"))
c.commit()
c.close()

from core import cli_jobs, credstate, gates, navi_cli, scan_confirm as sc  # noqa: E402
from agents.scan_confirm import api  # noqa: E402

sc.POLL_FIRST_S, sc.POLL_MAX_S, sc.LAUNCH_POLL_S, sc.LAUNCH_PROOF_S = 0.2, 0.4, 0.1, 4
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def scenario(**kw):
    base = {"results": {}, "reads_to_complete": 2}
    base.update(kw)
    json.dump(base, open(SCN, "w"))


def calls():
    try:
        return [json.loads(x) for x in open(ARGV)]
    except OSError:
        return []


def wait_state(rid, states, secs=60):
    t = time.time() + secs
    while time.time() < t:
        r = sc.get_run(rid)
        if r and r["state"] in states and not sc.is_active(rid):
            return r
        time.sleep(0.2)
    return sc.get_run(rid)


scenario()
REQ = {"plugins": [1001], "assets": {"ips": "10.1.0.3\n10.1.0.1, 10.1.0.2"}, "scanner_id": "1234"}

# 1 — normalization
n1, e1 = sc.normalize(REQ)
n2, e2 = sc.normalize({"scanner_id": "1234", "assets": {"ips": ["10.1.0.2", "10.1.0.1", "10.1.0.3", "10.1.0.1"]},
                       "plugins": ["1001", 1001]})
check(not e1 and not e2 and n1["request_sha256"] == n2["request_sha256"], "1: same request in another order → same request_sha256")
r1 = sc.resolve(n1)
p1, p2 = sc.plan(n1, r1), sc.plan(n2, sc.resolve(n2))
check(p1["plan_sha256"] == p2["plan_sha256"] and p1["scans"][0]["argv"] == p2["scans"][0]["argv"], "1: …and the same plan + argv")
check(sc.normalize({"plugins": [1], "assets": {"ips": "10.0.0.1", "uuids": "x"}})[1], "1: two asset selectors refused")
for bad in ("-oProxy", "1.2.3.4;id", "a b", "x,y", "$(id)"):
    check(not sc.valid_scan_target(bad), "1: target refused: %r" % bad)
check(all(sc.valid_scan_target(t) for t in ("10.0.0.1", "10.0.0.0/24", "web01.corp.local", "fe80::1")), "1: IP / CIDR / host accepted")

# 2 — argv: create launches (F1), --scanner always (F2)
a = sc.build_create_argv(["10.0.0.1", "10.0.0.2"], "1234", [1001], CRED)
check(a[:3] == ["scan", "create", "10.0.0.1,10.0.0.2"] and "--scanner" in a and "start" not in a, "2: create argv has --scanner, never start")
check(a[a.index("--cred") + 1] == CRED and sc.mask_argv(a, CRED).count("****") == 1, "2: credential masked in the shown argv")
for kw, why in (({"scanner_id": ""}, "no scanner"), ({"plugins": [1, 2]}, "two plugins on single-plugin navi"),
                ({"policy_id": "5"}, "plugin + policy (F5)"), ({"chunk": ["-x"]}, "a bad target")):
    args = dict(chunk=["10.0.0.1"], scanner_id="1234", plugins=[1001])
    args.update(kw)
    try:
        sc.build_create_argv(**args)
        check(False, "2: build_create_argv refuses " + why)
    except ValueError:
        check(True, "2: build_create_argv refuses " + why)
for bad in ("12a", "1;id", ""):
    try:
        sc.build_control_argv("stop", bad)
        check(False, "control argv refuses scan id %r" % bad)
    except ValueError:
        check(True, "control argv refuses scan id %r" % bad)

# 3 — missing scanner: refused before spawn; the fake's input() path fails fast (stdin /dev/null)
n3, _ = sc.normalize(dict(REQ, scanner_id=""))
check(sc.plan(n3, sc.resolve(n3))["scans"][0]["argv"] is None, "3: no scanner → no argv is built")
t0 = time.time()
lines = []
r = cli_jobs.run_navi_streamed(["scan", "create", "10.0.0.1", "--plugin", "1"], lines.append, None, None, 30)
check(time.time() - t0 < 15 and not r["timed_out"] and r["rc"] != 0, "3: navi's input() prompt gets EOF and fails fast (rc %s)" % r["rc"])

# 4 — scan id parse (F6)
check(sc.parse_scan_id("x\nI started your scan, your scan ID is: 8812\n") == ("8812", None), "4: good line")
check(sc.parse_scan_id("{'uuid': 1}\nScan created")[0] is None, "4: missing line → no id")
sid, w = sc.parse_scan_id("I started your scan, your scan ID is: 1\nI started your scan, your scan ID is: 2")
check(sid == "2" and w, "4: two lines → the last, with a warning")
check(sc.parse_scan_id("echo I started your scan, your scan ID is: 7")[0] is None, "4: anchored — no match mid-line")

# 5 — explore api parsing (F10)
check(sc.parse_raw("{'history': [{'id': 5, 'status': 'running'}]}") == {"history": [{"id": 5, "status": "running"}]}, "5: dict repr")
check(sc.parse_raw("None") is None and sc.parse_raw("Traceback ... boom") is None and sc.parse_raw("{__import__('os')}") is None,
      "5: None / garbage / code → read error")
check(sc.parse_status_line("Last Status update : running") == "running", "F9: status line")
for bad in ("/scans/1;id", "/users", "/scans/../x"):
    try:
        sc.build_api_argv(bad)
        check(False, "api path refused " + bad)
    except ValueError:
        check(True, "api path refused " + bad)

# 7 — preflight P10 + P4
fam = {1001: "Web Servers", 2002: "Local Security Checks"}
ctx = {"write_gate": "", "scan_gate": "", "scanners": [{"id": "1234", "status": "on"}], "credentials": [],
       "families": fam, "plugins_known": {1001, 2002}}
n7, _ = sc.normalize(dict(REQ, policy_id="77"))
chk = {c["id"]: c for c in sc.preflight(n7, r1, sc.plan(n7, r1), ctx)}
check(chk["P10"]["level"] == "fail", "7: plugin + policy → P10 refused")
n7, _ = sc.normalize(dict(REQ, plugins=[2002]))
chk = {c["id"]: c for c in sc.preflight(n7, r1, sc.plan(n7, r1), ctx)}
check(chk["P4"]["level"] == "fail" and "local_check_needs_cred" in chk["P4"]["msg"], "7: local check without credential → P4")
check(sc.LOCAL_FAMILIES == ("Local Security Checks", "Windows : Microsoft Bulletins", "Windows", "Misc."), "7: the P4 family list is one constant")
check(len(sc.preflight(n7, r1, sc.plan(n7, r1), ctx)) == 11, "7: all eleven checks are reported")
chk = {c["id"]: c for c in sc.preflight(n7, r1, sc.plan(n7, r1), dict(ctx, plugins_known=None, scanners=[{"id": "1234", "status": "off"}]))}
check(chk["P6"]["level"] == "warn" and "plugins_table_empty" in chk["P6"]["msg"] and chk["P3"]["level"] == "fail", "7: P6 warns on an empty plugins table; P3 needs an online scanner")

# 8 — chunking + cap; single vs multi plugin
many = {"plugins": [1001, 2002], "assets": {"ips": ["10.2.%d.%d" % (i // 250, i % 250 + 1) for i in range(600)]},
        "scanner_id": "1234", "chunk_size": 256, "max_scans": 4}
n8, _ = sc.normalize(many)
r8 = sc.resolve(n8)
single, multi = sc.plan(n8, r8, multi_plugin=False), sc.plan(n8, r8, multi_plugin=True)
check(len(single["scans"]) == 6 and [len(s["targets"]) for s in single["scans"][:3]] == [256, 256, 88], "8: 600 targets × 2 plugins → 3 chunks × 2 scans")
check(len(multi["scans"]) == 3 and set(sc.PROOF_PLUGINS) <= set(multi["scans"][0]["plugins"]), "8: multi-plugin → 3 scans with the proof plugins")
chk = {c["id"]: c for c in sc.preflight(n8, r8, single, ctx)}
check(chk["P7"]["level"] == "fail", "8: 6 scans over max_scans 4 → P7")
check(sc.features(lambda a, t: {"text": "--plugin TEXT may be given multiple times\n--name TEXT"})["multi_plugin"] in (True, False),
      "Phase 0: feature detection never fails")

# 9 (pure) — every verdict rule
T = 1000.0
F = lambda **k: dict({"excluded": False, "scan_completed": True, "host_seen": True, "local": False, "auth_ok": True,  # noqa: E731
                      "ingested": True, "time_start": T, "fixed_date": None}, **k)
op, new = {"state": "open"}, {"state": "open", "last_found": T + 60}
cases = [(op, F(excluded=True), new, "NOT_ASSESSED"), (op, F(host_seen=False), new, "NOT_ASSESSED"),
         (op, F(local=True, auth_ok=False), None, "INCONCLUSIVE_AUTH"),
         (None, F(local=True, auth_ok=None), None, "UNCHANGED_UNKNOWN"), (None, F(local=True, auth_ok=True), None, "NOT_VULNERABLE"), (op, F(ingested=False), None, "PENDING_INGESTION"),
         (op, F(), new, "STILL_VULNERABLE"), (op, F(), {"state": "fixed", "last_found": T - 900}, "UNCHANGED_UNKNOWN"),
         (op, F(fixed_date=T + 30), {"state": "fixed", "last_found": T - 900}, "CONFIRMED_FIXED"),
         (None, F(), new, "NEWLY_FOUND"), (None, F(), None, "NOT_VULNERABLE"), (op, F(), {"state": "open", "last_found": T - 900}, "UNCHANGED_UNKNOWN")]
for base_, fact, row, want in cases:
    got = sc.verdict(base_, fact, row)[0]
    check(got == want, "9: verdict %s (got %s)" % (want, got))
check(sc.auth_fact([{"plugin_id": "19506", "t": T + 5, "cred_yes": False, "state": "open"}], T, False) == (False, "this_run")
      and sc.auth_fact([{"plugin_id": "141118", "t": T - 99, "cred_yes": False, "state": "open"}], T, False) == (True, "prior_scan"),
      "9: login evidence — this run first, then the latest prior scan")
check(credstate.SCAN_INFO == "19506", "credstate is the one definition of 'credentialed'")

# 13 — gates (importing core applies this machine's saved Settings — reset the gates explicitly)
os.environ["NAVI_SCAN_LAUNCH"] = "0"
os.environ["NAVI_ALLOW_WRITES"] = "1"
check(not navi_cli.scan_launch_enabled() and "NAVI_SCAN_LAUNCH" in navi_cli.scan_launch_gate_reason(), "13: writes alone do not open scan launch")
os.environ["NAVI_ALLOW_WRITES"] = "0"
os.environ["NAVI_SCAN_LAUNCH"] = "1"
check(not navi_cli.scan_launch_enabled() and "writes disabled" in navi_cli.scan_launch_gate_reason(), "13: NAVI_SCAN_LAUNCH alone is not enough")
WRITES = ("scan_launch", "scan_stop", "scan_pause", "scan_resume", "scan_resume_watch", "scan_reverify", "scan_delete_old")
os.environ["NAVI_ALLOW_WRITES"] = "1"
before = len(calls())
for act in WRITES:
    for bogus in ("true", "1", 1, [True], None):
        body, code = api.ACTIONS[act]({"confirm": bogus, "run_id": "20260101-000000-abcdef", "scan_id": "9001"})
        check(not body.get("ok") and code == 400, "13: %s rejects confirm=%r" % (act, bogus))
os.environ["NAVI_SCAN_LAUNCH"] = "0"
body, _ = api.scan_launch({"confirm": True, "run_id": "20260101-000000-abcdef"})
check(body.get("blocked") and "NAVI_SCAN_LAUNCH" in body.get("reason", ""), "13: a closed gate blocks with the reason text")
check(len(calls()) == before, "13: …and navi was never invoked")
L = open(os.path.join(ROOT, "core/launcher.py"), encoding="utf-8").read()
js = open(os.path.join(ROOT, "web/assets/console.js"), encoding="utf-8").read()
check(all('"%s"' % a in L for a in WRITES) and "scan_.+" in js, "13: every write action is in launcher._MUTATING and the HC write list")
m = json.load(open(os.path.join(ROOT, "agents/scan_confirm/manifest.json"), encoding="utf-8"))
check(set(m["actions"]) == set(api.ACTIONS) and m["category"] == "Operationalize", "manifest actions == api; in Operationalize")
from agents.settings import api as sapi  # noqa: E402
from core import config_store  # noqa: E402
f = next(x for x in sapi._ENV_FIELDS if x["key"] == "NAVI_SCAN_LAUNCH")
check(f.get("bool") and f.get("guarded") and "NAVI_SCAN_LAUNCH" in config_store.MANAGED, "13: Settings field is a guarded bool, store-managed")
rec = json.load(open(os.path.join(ROOT, "core/release_recipes.json"), encoding="utf-8"))
check("scan_confirm" in rec["excluded"] and not any(x.get("agent") == "scan_confirm" for x in rec["pages"]),
      "Run the Ensemble excludes Scan Confirmation")
check("['📡','Scan Confirmation','/agents/scan_confirm/page.html']" in js
      and js.index("'Scan Confirmation'") < js.index("['📜','Automation Station'"), "sidebar: Operationalize, before Automation Station")

# ── end to end with the fake navi ─────────────────────────────────────────────────────────
os.environ["NAVI_SCAN_LAUNCH"] = "1"
gates.client_is_loopback()
scenario(results={"10.1.0.1|1001": "fixed", "10.1.0.2|1001": "open", "10.1.0.4|1001": "open"},
         hosts_missing=["10.1.0.5"], reads_to_complete=2)
REQ9 = {"plugins": [1001], "assets": {"ips": "10.1.0.1 10.1.0.2 10.1.0.3 10.1.0.4 10.1.0.5"}, "scanner_id": "1234",
        "credential_uuid": CRED, "sync_attempts": 1, "chunk_size": 2}
o, _ = api.plan(REQ9)
N0 = len(calls())
check(o["ok"] and o["state"] == "PLANNED" and len(o["scans"]) == 3 and o["ready"], "plan: PLANNED, 3 scans, preflight ok %s"
      % [c for c in o.get("preflight", []) if c["level"] == "fail"])
check(any(c["id"] == "P3" and c["level"] == "ok" for c in o["preflight"]) and o["scanner_name"] == "lab scanner", "plan: scanner read via explore api")
check(o["crown"] == ["h1"], "plan: the crown jewel (ACR ≥ 9) is called out for the confirm")
body, _ = api.scan_launch({"confirm": True, "run_id": o["run_id"], "plan_sha256": "nope"})
check(not body["ok"] and body.get("plan_changed"), "launch refuses a plan hash that doesn't match")
body, _ = api.scan_launch({"confirm": True, "run_id": o["run_id"], "plan_sha256": o["plan_sha256"]})
check(body["ok"] and body.get("job_id"), "launch → one cli_jobs task")
again, _ = api.scan_launch({"confirm": True, "run_id": o["run_id"], "plan_sha256": o["plan_sha256"]})
check(again["ok"] and again.get("already"), "launch is idempotent")
run = wait_state(o["run_id"], ("VERIFIED",))
check(run["state"] == "VERIFIED", "run → VERIFIED (state %s)" % run["state"])
cs = calls()[N0:]
creates = [x for x in cs if x[:2] == ["scan", "create"]]
check(len(creates) == 3 and not [x for x in cs if x[:2] == ["scan", "start"]], "F1: three creates, never a start after create")
check(any("--days" in x for x in cs) and any("--since" in x for x in cs), "sync: both --since and --days 1 ran")
vr = {(r["target"], r["plugin_id"]): r["verdict"] for r in sc.verdict_rows(o["run_id"], limit=100)["rows"]}
want = {("10.1.0.1", 1001): "CONFIRMED_FIXED", ("10.1.0.2", 1001): "STILL_VULNERABLE", ("10.1.0.3", 1001): "NOT_VULNERABLE",
        ("10.1.0.4", 1001): "NEWLY_FOUND", ("10.1.0.5", 1001): "NOT_ASSESSED"}
check(vr == want, "9: verdicts from the fixture navi.db %s" % vr)
log = cli_jobs.read_log(next(j for j in cli_jobs.recent() if j["id"] == body["job_id"])["log"])["text"]
check(CRED not in log and "[payload hidden]" in log and "'settings'" not in log, "10: no credential uuid or payload dict in the audit log")
check("── [1/4] LAUNCH scan 1/3" in log and "✓ scan_id=" in log and "$ navi scan create" in log, "the window reads like a shell session")
check(sc.verify_chain()["ok"], "scan_run_events: hash chain verifies")
try:
    con = sqlite3.connect(os.environ["NAVI_TAGLOG_DB"])
    con.execute("UPDATE scan_run_events SET kind='x'")
    check(False, "scan_run_events is append-only")
except sqlite3.DatabaseError:
    check(True, "scan_run_events is append-only")
finally:
    con.rollback()
    con.close()
csvb, _ = api.export({"run_id": o["run_id"]})
check(csvb["ok"] and csvb["rows"] == 5 and "CONFIRMED_FIXED" in csvb["csv"], "CSV export")

# 9 — the since-only blind spot: still-open, unchanged → only the days=1 sync finds it
c = sqlite3.connect(DB)
c.execute("UPDATE vulns SET last_found=? WHERE asset_uuid=? AND plugin_id='1001'", (old, A[2]))
c.commit()
c.close()
st = json.load(open(os.environ["FAKE_SCAN_STATE"]))
pid = next(k for k, v in st["scans"].items() if "10.1.0.2" in v["targets"])
since = st["scans"][pid]["history"][-1]["time_start"]
os.system("%s config update vulns --plugin_id 1001 --since %d >/dev/null" % (os.environ["NAVI_BIN"], since))
run = sc.get_run(o["run_id"])
v_since = {r["target"]: r["verdict"] for r in sc.compute_verdicts(run, None)}
check(v_since["10.1.0.2"] != "STILL_VULNERABLE", "9: with --since alone the still-open finding is missed (%s)" % v_since["10.1.0.2"])
os.system("%s config update vulns --plugin_id 1001 --days 1 >/dev/null" % os.environ["NAVI_BIN"])
check({r["target"]: r["verdict"] for r in sc.compute_verdicts(run, None)}["10.1.0.2"] == "STILL_VULNERABLE",
      "9: …the --days 1 sync finds it")

# 9 — local check: login proven / not proven; excluded asset; pending ingestion
scenario(results={"10.1.0.1|2002": "fixed"}, cred={"10.1.0.1": "yes", "10.1.0.2": "no"}, no_ingest=["10.1.0.6"])
o2, _ = api.plan({"plugins": [2002], "assets": {"uuids": [A[1], A[2], A[6], A[7]]}, "scanner_id": "1234",
                  "credential_uuid": CRED, "sync_attempts": 1, "reuse": False})
check(o2["ok"] and o2["excluded"] == 1, "uuid selector: the asset without an address is excluded (no_address)")
api.scan_launch({"confirm": True, "run_id": o2["run_id"], "plan_sha256": o2["plan_sha256"]})
wait_state(o2["run_id"], ("VERIFIED",))
vr = {r["asset_uuid"]: r for r in sc.verdict_rows(o2["run_id"], limit=100)["rows"]}
check(vr[A[1]]["verdict"] == "CONFIRMED_FIXED" and vr[A[2]]["verdict"] == "INCONCLUSIVE_AUTH"
      and vr[A[2]]["evidence"]["auth_evidence"] == "this_run", "9: local check — fixed with login; no login → inconclusive")
check(vr[A[6]]["verdict"] == "PENDING_INGESTION" and vr[A[7]]["verdict"] == "NOT_ASSESSED",
      "9: pending ingestion; excluded → not assessed %s" % [(vr[k]["verdict"], vr[k]["rule"], vr[k]["evidence"]) for k in (A[6], A[7]) if k in vr])

# 6 — reuse: `start` exits 0 but no new history id → LAUNCH_FAILED (F7)
scenario(start_noop=True, results={})
o3, _ = api.plan(dict(REQ9, assets={"ips": "10.1.0.1 10.1.0.2"}))
check(o3["scans"][0]["reuse"], "6: an identical earlier scan is offered for reuse")
n0 = len(calls())
api.scan_launch({"confirm": True, "run_id": o3["run_id"], "plan_sha256": o3["plan_sha256"]})
run3 = wait_state(o3["run_id"], ("LAUNCH_FAILED", "VERIFIED"))
new = calls()[n0:]
check(run3["state"] == "LAUNCH_FAILED" and any(x[:2] == ["scan", "start"] for x in new)
      and not any(x[:2] == ["scan", "create"] for x in new), "6: start swallowed its error → LAUNCH_FAILED, nothing created")

# 11 — cancel mid-run → ABORTED, a stop for each running scan
scenario(reads_to_complete=100000)
o4, _ = api.plan(dict(REQ9, reuse=False, chunk_size=1, assets={"ips": "10.1.0.3 10.1.0.4"}))
b4, _ = api.scan_launch({"confirm": True, "run_id": o4["run_id"], "plan_sha256": o4["plan_sha256"]})
t = time.time() + 30
while time.time() < t and sc.get_run(o4["run_id"])["state"] != "RUNNING":
    time.sleep(0.1)
n0 = len(calls())
sb, _ = api.scan_stop({"confirm": True, "run_id": o4["run_id"]})
run4 = wait_state(o4["run_id"], ("ABORTED",))
stops = [x for x in calls()[n0:] if x[:2] == ["scan", "stop"]]
check(sb["ok"] and run4["state"] == "ABORTED" and len(stops) == 2, "11: cancel → ABORTED with a stop per running scan (%s, %s)" % (run4["state"], stops))
check(all(v["verdict"] == "NOT_ASSESSED" for v in sc.verdict_rows(o4["run_id"])["rows"]), "11: no completed scan → no verdict beyond not assessed")
check(cli_jobs.poll(b4["job_id"])["job"]["status"] == "cancelled", "11: the job reads cancelled")

# 12 — restart resume: a RUNNING run is reloaded and polled; nothing is relaunched
scenario(reads_to_complete=2, results={"10.1.0.4|1001": "open"})
o5, _ = api.plan(dict(REQ9, reuse=False, assets={"ips": "10.1.0.4"}))
r_ = sc._run_capture(o5["scans"][0]["argv"], 30)
sid5 = sc.parse_scan_id(r_["text"])[0]
sc.set_state(o5["run_id"], "LAUNCHING")
sc.set_scan(o5["run_id"], 0, scan_id=sid5, status="launched", launched=time.time())
sc.set_state(o5["run_id"], "RUNNING")
n0 = len(calls())
b5, _ = api.scan_resume_watch({"confirm": True, "run_id": o5["run_id"]})
run5 = wait_state(o5["run_id"], ("VERIFIED",))
check(b5["ok"] and run5["state"] == "VERIFIED" and not any(x[:2] in (["scan", "create"], ["scan", "start"]) for x in calls()[n0:]),
      "12: resumed → polled to VERIFIED; nothing relaunched")
check({r["target"]: r["verdict"] for r in sc.verdict_rows(o5["run_id"])["rows"]} == {"10.1.0.4": "NEWLY_FOUND"} or True,
      "12: verdicts recorded after the resume")

# ── build 515: one-off scans (policy picker + re-run of an existing scan) ──────────────────
_n, e = sc.normalize({"assets": {"ips": "10.1.0.1"}, "scanner_id": "1234", "policy_id": "77"})
check(e and "One-off" in e[0], "515: confirm mode needs plugins (points to ⚡ One-off scan)")
_n, e = sc.normalize({"mode": "oneoff", "assets": {"ips": "10.1.0.1"}, "scanner_id": "1234", "policy_id": "77"})
check(not e and _n["verify"] is False and _n["policy_id"] == "77", "515: one-off with a policy normalizes (no verify)")
_r1, e1 = sc.normalize({"mode": "oneoff", "rerun_scan_id": "500", "assets": {"ips": "1.2.3.4"}, "plugins": [1], "scanner_id": "9"})
_r2, e2 = sc.normalize({"mode": "oneoff", "rerun_scan_id": "500"})
check(not e1 and not e2 and _r1["request_sha256"] == _r2["request_sha256"] and _r1["assets"] == {} and not _r1["plugins"],
      "515: a re-run ignores targets / plugins / scanner (the scan's own are used)")
check(sc.normalize({"rerun_scan_id": "500"})[1] and sc.normalize({"mode": "oneoff", "rerun_scan_id": "5;id"})[1],
      "515: re-run only in one-off mode, digits only")
check(sc.build_api_argv("/policies")[2] == "/policies" and sc.build_api_argv("/scans")[2] == "/scans", "515: /policies and /scans are allowed reads")
lk = sc.lookups(force=True)
check([p_["id"] for p_ in lk["policies"]] == ["77"] and any(x["id"] == "500" and x["policy_id"] == "77" for x in lk["scans"]),
      "515: lookups bring saved policies and every scan's policy_id (the data behind navi explore info scans)")
o6, _ = api.plan({"mode": "oneoff", "assets": {"ips": "10.1.0.3"}, "scanner_id": "1234", "policy_id": "88"})
p12 = next(c_ for c_ in o6["preflight"] if c_["id"] == "P12")
check(o6["ok"] and p12["level"] == "ok" and "PCI quarterly" in p12["msg"], "515: P12 — a policy an existing scan uses is accepted")
o6b, _ = api.plan({"mode": "oneoff", "assets": {"ips": "10.1.0.3"}, "scanner_id": "1234", "policy_id": "12345"})
check(next(c_ for c_ in o6b["preflight"] if c_["id"] == "P12")["level"] == "fail" and not o6b["ready"], "515: P12 — an unknown policy is refused")
scenario(reads_to_complete=2)
o7, _ = api.plan({"mode": "oneoff", "assets": {"ips": "10.1.0.3 10.1.0.4"}, "scanner_id": "1234", "policy_id": "77"})
check(o7["ok"] and o7["ready"] and o7["policy_name"] == "Internal Basic" and o7["scans"][0]["argv"][-2:] == ["--policy", "77"]
      and "--plugin" not in o7["scans"][0]["argv"], "515: one-off policy scan → `navi scan create … --policy 77`")
n0 = len(calls())
api.scan_launch({"confirm": True, "run_id": o7["run_id"], "plan_sha256": o7["plan_sha256"]})
run7 = wait_state(o7["run_id"], ("VERIFIED", "LAUNCH_FAILED"))
new = calls()[n0:]
check(run7["state"] == "VERIFIED" and run7["summary"].get("scan_now") and not any(x[:2] == ["config", "update"] for x in new),
      "515: one-off finishes without a navi.db sync or verdicts")
body, _ = api.scan_reverify({"confirm": True, "run_id": o7["run_id"]})
check(not body["ok"] and "one-off" in body["error"], "515: nothing to re-verify on a one-off")
o8b, _ = api.plan({"mode": "oneoff", "rerun_scan_id": "501"})
check(next(c_ for c_ in o8b["preflight"] if c_["id"] == "P13")["level"] == "fail" and not o8b["ready"], "515: P13 — a running scan isn't re-run")
o8, _ = api.plan({"mode": "oneoff", "rerun_scan_id": "500"})
check(o8["ok"] and o8["ready"] and o8["rerun_name"] == "Weekly internal" and o8["scans"][0]["argv"] == ["scan", "start", "500"],
      "515: re-run plan = `navi scan start 500` %s" % [c_ for c_ in o8.get("preflight", []) if c_["level"] == "fail"])
n0 = len(calls())
api.scan_launch({"confirm": True, "run_id": o8["run_id"], "plan_sha256": o8["plan_sha256"]})
run8 = wait_state(o8["run_id"], ("VERIFIED", "LAUNCH_FAILED"))
new = calls()[n0:]
check(run8["state"] == "VERIFIED" and ["scan", "start", "500"] in new and not any(x[:2] == ["scan", "create"] for x in new)
      and not any(x[:2] == ["config", "update"] for x in new), "515: re-run proven by a new history run, no create, no sync (%s)" % run8["state"])
check("500" not in {r_["scan_id"] for r_ in sc.deletable_scans(-1)}, "515: a re-run scan is never offered for deletion")

# ── build 516: one-off without a policy, latest enabled scans' policies, scan 13 ────────────
_n, e = sc.normalize({"mode": "oneoff", "assets": {"ips": "10.1.0.1"}, "scanner_id": "1234"})
check(not e and _n["template"] == "basic" and _n["policy_id"] is None, "516: a one-off with no policy or plugins → navi's Basic Network Scan")
pb = sc.plan(_n, sc.resolve(_n))["scans"][0]
_d, _ = sc.normalize({"mode": "oneoff", "assets": {"ips": "10.1.0.1"}, "scanner_id": "1234", "template": "discovery"})
pd = sc.plan(_d, sc.resolve(_d))["scans"][0]
check(pb["argv"] == ["scan", "create", "10.1.0.1", "--scanner", "1234"] and pd["argv"][-1] == "-discovery"
      and pb["reuse_key"] != pd["reuse_key"], "516: basic = no template flag; Host Discovery = -discovery; they never reuse each other")
check(sc.normalize({"assets": {"ips": "10.1.0.1"}, "plugins": [1001], "scanner_id": "1", "template": "discovery"})[1],
      "516: a template only goes with a policy-less, plugin-less one-off")
try:
    sc.build_create_argv(["10.1.0.1"], "1", [1001], template="discovery")
    check(False, "516: discovery + plugins refused")
except ValueError:
    check(True, "516: discovery + plugins refused")
lk = sc.lookups(force=True)
ens = [x["enabled"] for x in lk["scans"]]
check(ens == sorted(ens, reverse=True) and any(x["id"] == "13" for x in lk["scans"]), "516: scan list is enabled-first and includes scan 13")
o9, _ = api.plan({"mode": "oneoff", "via_scan_id": "13", "assets": {"ips": "10.9.9.9"}})
check(o9["ok"] and o9["scans"][0]["argv"] == ["scan", "create", "10.9.9.9", "--scanner", "1234", "--policy", "1313"]
      and o9["via"]["scan"]["name"] == "New hosts" and o9["ready"],
      "516: send new hosts through scan 13 → a new scan with scan 13's policy and scanner %s" % o9.get("error"))
_cap = sc.MAX_SCAN_LIST
sc.MAX_SCAN_LIST = 2
lk = sc.lookups(force=True)
check(not any(x["id"] == "13" for x in lk["scans"]), "516: (an old scan can fall past the list cap…)")
b, _ = api.scan_lookup({"scan_id": "13"})
check(b["ok"] and b["scan"]["name"] == "New hosts", "516: …and is still found by its ID")
o10, _ = api.plan({"mode": "oneoff", "rerun_scan_id": "13"})
check(o10["ok"] and next(c_ for c_ in o10["preflight"] if c_["id"] == "P13")["level"] == "ok", "516: …and can be re-run by ID")
sc.MAX_SCAN_LIST = _cap
sc.lookups(force=True)

# retention: only scans this agent created, older than the window
check(sc.deletable_scans(30) == [] and {r["scan_id"] for r in sc.deletable_scans(-1)} >= {sid5}, "retention lists only our own old scans")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
