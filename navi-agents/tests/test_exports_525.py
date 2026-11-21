"""Build 525 — the Compliance Drill-down at scale, and CSV exports that pull EVERY row.

  * Compliance Overview → Drill-down: a 6,000-asset "failing a check" group used to ship every
    asset (plus a name lookup with an IN over every uuid) to the page, which never finished. Now
    the group streams into the result store once; a page call returns ≤ 500 rows (the page shows
    20 at a time and asks for the next 500 only when you page past them).
  * Every CSV export: ≤ 5,000 rows come back at once; more run as a background export job
    (core/exports.py) the page downloads in pieces. No 5,000 / 50,000 / 2,000 caps.
  * SQL the server built runs through `navi export query` (a fake navi here); SQL a person or a
    model wrote never does — it stays on the guarded engine (navi's credential tables unreadable).
Run: python3 tests/test_exports_525.py"""
import csv
import io
import json
import os
import random
import sqlite3
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="exp525_")
DB = os.path.join(TMP, "navi.db")
CWD = os.path.join(TMP, "navicwd")
os.makedirs(CWD)
os.environ.update({"HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_DB_PATH": DB,
                   "NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db"),
                   "NAVI_BOARDS_DB": os.path.join(TMP, "boards.db"), "NAVI_BOARDS_DAILY": "0", "NAVI_CWD": CWD})
for k in ("NAVI_ALLOW_WRITES", "NAVI_EMAIL", "NAVI_EXPORT_ENGINE", "NAVI_BIN"):
    os.environ.pop(k, None)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ── fixture: 6,000 audited assets, 12 checks each ──────────────────────────────────────────
N, C = 6000, 12
random.seed(5)
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, operating_system TEXT);
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE compliance(asset_uuid TEXT, check_id TEXT, check_name TEXT, audit_file TEXT, status TEXT,
                        reference TEXT, solution TEXT, actual_value TEXT, expected_value TEXT, check_info TEXT);
CREATE TABLE vulns(asset_uuid TEXT, asset_hostname TEXT, asset_ip TEXT, plugin_id TEXT, plugin_name TEXT,
                   plugin_family TEXT, severity TEXT, state TEXT, synopsis TEXT);
CREATE TABLE fixed(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, state TEXT, pass_fail TEXT,
                   first_found TEXT, last_fixed TEXT);
CREATE TABLE keys(access_key TEXT, secret_key TEXT);
INSERT INTO keys VALUES ('AK-SECRET','SK-SECRET');
""")
U = ["u%05d" % i for i in range(N)]
c.executemany("INSERT INTO assets VALUES (?,?,?,?,?)",
              [(u, ("=cmd|host%d" % i) if i == 7 else ("host%d" % i), "10.0.%d.%d" % (i // 250, i % 250), "5", "Linux")
               for i, u in enumerate(U) if i % 50])                      # every 50th asset: name only in vulns
c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?)",
              [(u, "vh%d" % i, "10.9.%d.%d" % (i // 250, i % 250), "1", "x", "f", "high", "open", "")
               for i, u in enumerate(U) if not i % 50])
FW = ["[{'framework': '800-53', 'control': 'AC-%d'}]", "[{'framework': ' CIS', 'control': '1.%d'}]"]
rows = []
for i, u in enumerate(U):
    for k in range(C):
        st = random.choices(["FAILED", "PASSED", "WARNING"], [0.25, 0.65, 0.10])[0]
        rows.append((u, "c%02d" % k, "Ensure setting %d" % k, "A.audit" if k % 2 else "B.audit", st,
                     FW[k % 2] % k, "fix", "a", "b", "info"))
c.executemany("INSERT INTO compliance VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
c.executemany("INSERT INTO fixed VALUES (?,?,?,?,?,?,?,?)",
              [("u%05d" % (i % N), str(1000 + i), ("=evil" if i == 3 else "p%d" % i), "high", "fixed",
                "pass" if i % 3 else "fail", "2026-01-01", "2026-02-01") for i in range(7000)])
c.commit()
c.close()

from core import compliance as comp, exports, payload  # noqa: E402
from agents.compliance_asset import api as capi  # noqa: E402
from agents.explore import api as xapi  # noqa: E402


def wait(eid, t=120):
    end = time.time() + t
    while time.time() < end:
        s, _ = xapi.export_status({"id": eid})
        if s.get("export", {}).get("status") != "running":
            return s.get("export") or {}
        time.sleep(0.1)
    return {}


def fetch_all(eid):
    parts, off = [], 0
    while off is not None:
        f, _ = xapi.export_fetch({"id": eid, "offset": off})
        if not f.get("ok"):
            return None
        parts.append(f["text"])
        off = f["next"]
    return "".join(parts)


# ── 1. the cohort list is the old cohort, worst first, ≤ 500 rows a call ────────────────────
for f in ("st:failed", "st:warning", "st:clean", "pct:lt50", "check:c03", "audit:A.audit", "fw:800-53", "fw:CIS", ""):
    old = comp.cohort(f)["uuids"] if f else {r["asset_uuid"] for r in comp.assets_list()}
    new = [r["asset_uuid"] for r in comp.cohort_rows(f)]
    check(set(new) == old and len(new) == len(old), "cohort %r: the streamed list is exactly the old group (%d)" % (f, len(old)))
rws = list(comp.cohort_rows("st:failed"))
check(all((a["failed"], a["warning"]) >= (b["failed"], b["warning"]) for a, b in zip(rws, rws[1:])), "…worst first")
check(all(r["hostname"] for r in rws), "every asset has a name — the ones missing from `assets` from vulns, in batches")
b, _ = capi.cohort({"f": "st:failed"})
nf = len(comp.cohort("st:failed")["uuids"])
check(b["ok"] and len(b["top"]) == 500 and b["summary"]["count"] == nf and b["total"]["value"] == nf and b["page"]["next"],
      "cohort: the first 500 of %d + a next token" % nf)
check(len(json.dumps(b)) < 200_000, "…a page payload, not the whole group (%d bytes)" % len(json.dumps(b)))
seen, nxt, calls = [r["asset_uuid"] for r in b["top"]], b["page"]["next"], 1
while nxt:
    d, _ = capi.drill({"run": b["drill"]["run"], "section": "assets", "limit": 500, "next": nxt})
    seen += [r["asset_uuid"] for r in d["top"]]
    nxt = d["page"]["next"]
    calls += 1
check(len(seen) == nf == len(set(seen)) and calls == -(-nf // 500), "drill pages every asset once, 500 a call (%d calls)" % calls)
d, _ = capi.drill({"run": b["drill"]["run"], "section": "assets", "limit": 5000})
check(len(d["top"]) == 500, "a drill call never returns more than 500")
d, _ = payload.drill("asset_ownership", {"run": b["drill"]["run"], "section": "assets"}, capi.SECTIONS)
check(d.get("expired"), "another agent can't drill this run")
au = b["top"][0]["asset_uuid"]
x, _ = capi.detail({"asset_uuid": au, "f": "st:failed", "list": False})
check(x["ok"] and x["result"]["in_cohort"] and "assets" not in x["result"] and x["result"]["detail"]["available"],
      "detail list:false: no asset list, in_cohort answered for the one asset")
clean = next(r["asset_uuid"] for r in comp.cohort_rows("st:clean"))
x, _ = capi.detail({"asset_uuid": clean, "f": "st:failed", "list": False})
check(not x["result"]["in_cohort"], "…an asset outside the group says so")
for f in ("check:c03", "fw:800-53"):
    inn = next(iter(comp.cohort(f)["uuids"]))
    out = next(u for u in U if u not in comp.cohort(f)["uuids"])
    check(comp.in_cohort(f, inn) and not comp.in_cohort(f, out), "in_cohort %s matches the group" % f)

# ── 2. the group's CSV: > 5,000 → a background job; every row; formula cells neutralised ──
e, _ = capi.export({"f": "", "run": None})
check(e["ok"] and not e["inline"] and e["export"]["status"] == "running", "every-asset export (6,000 rows) runs as a background job")
ex = wait(e["export"]["id"])
check(ex.get("status") == "done" and ex.get("rows") == N - 0, "…and finishes with every row (%s)" % ex.get("rows"))
txt = fetch_all(e["export"]["id"])
data = list(csv.reader(io.StringIO(txt)))
check(len(data) - 1 == N and data[0][:3] == ["asset_uuid", "hostname", "ip"], "the downloaded file has all %d rows" % N)
check(any(r[1] == "'=cmd|host7" for r in data[1:]), "a cell starting with = is neutralised ('=…)")
exports.CHUNK_BYTES = 4096
txt2 = fetch_all(e["export"]["id"])
check(txt2 == txt, "fetched in 4 KB pieces, the file reassembles byte for byte")
exports.CHUNK_BYTES = 4 * 1024 * 1024
e, _ = capi.export({"f": "pct:lt50", "run": None})
small = len(comp.cohort("pct:lt50")["uuids"])
check(small <= 5000 and (e.get("inline") or wait(e["export"]["id"]).get("rows") == small),
      "a small group comes back at once (or as a tiny job when its size isn't known yet)")
b2, _ = capi.cohort({"f": "check:c03"})
e, _ = capi.export({"f": "check:c03", "run": b2["drill"]["run"]})
check(e.get("inline") and len(list(csv.reader(io.StringIO(e["csv"])))) - 1 == b2["summary"]["count"],
      "a group under 5,000 (known from its run) downloads at once with every row")
e, _ = capi.export({"f": "st:failed", "run": b["drill"]["run"], "q": "host12"})
rows_q = list(csv.reader(io.StringIO(e["csv"]))) if e.get("inline") else []
check(e.get("inline") and len(rows_q) > 1 and all("host12" in (r[1] + r[2] + r[0]) for r in rows_q[1:]),
      "a searched list exports what the search matched")

# ── 3. the navi engine: server-built SQL → `navi export query` in a private folder ─────────
fake = os.path.join(TMP, "navi")
with open(fake, "w") as fh:
    fh.write("#!/usr/bin/env python3\nimport sys, sqlite3, csv\n"
             "a = sys.argv[1:]\n"
             "assert a[:2] == ['export', 'query'], a\n"
             "c = sqlite3.connect('navi.db'); cur = c.execute(a[2])\n"
             "w = csv.writer(open('query_data.csv', 'w', newline=''))\n"
             "w.writerow([d[0] for d in cur.description]); n = 0\n"
             "for r in cur: w.writerow(r); n += 1\n"
             "print('Wrote query_data.csv - %d rows' % n)\n")
os.chmod(fake, 0o755)
os.environ["NAVI_BIN"] = fake
check(exports.navi_ready("SELECT 1"), "navi engine ready with navi installed and a real navi.db")
e, _ = capi.export({"f": "st:failed", "run": None})
check(e["export"]["engine"] == "navi", "the group's full list runs through navi")
ex = wait(e["export"]["id"])
txt = fetch_all(e["export"]["id"])
data = list(csv.reader(io.StringIO(txt)))
check(ex.get("status") == "done" and len(data) - 1 == nf, "navi exported the entire group (%d rows)" % (len(data) - 1))
check(not [f for f in os.listdir(CWD) if f.endswith(".csv")] and not [d for d in os.listdir(exports._dir()) if d.startswith("nv-")],
      "navi ran in its own folder — nothing left in the navi folder or behind in the exports dir")
from agents.ex_fixed import api as fxapi  # noqa: E402
e, _ = fxapi.export({})
ex = wait(e["export"]["id"])
data = list(csv.reader(io.StringIO(fetch_all(e["export"]["id"]))))
check(e["export"]["engine"] == "navi" and len(data) - 1 == 7000, "Fixed explorer: every row (7,000) via navi export query")
check(any("'=evil" in r for r in data) and not any("=evil" == x for r in data for x in r),
      "navi's raw cells are neutralised on the way out")
# a person's / a model's SQL never goes through navi, and can't read navi's keys
e, _ = xapi.export_start({"source": "sql", "sql": "SELECT * FROM keys"})
bad = (not e.get("ok")) or (e.get("export") and wait(e["export"]["id"]).get("status") == "error")
check(bad and "SK-SECRET" not in json.dumps(e), "user SQL reading navi's keys is refused (guarded engine)")
e, _ = xapi.export_start({"source": "sql", "sql": "SELECT uuid, hostname FROM assets"})
check((e.get("export") or {}).get("engine", "python") == "python", "user SQL stays on the python engine even with navi installed")
os.environ.pop("NAVI_BIN", None)

# ── 4. generic: any server-paged table's every row; explorers; logs ─────────────────────────
e, _ = xapi.export_start({"source": "store", "run": b["drill"]["run"], "section": "assets"})
ex = wait(e["export"]["id"]) if e.get("export") else {}
check(e.get("ok") and ex.get("rows") == nf, "store export: every row of a stored section (%s)" % ex.get("rows"))
e, _ = xapi.export_start({"source": "store", "run": "nope-0000000000000000", "section": "assets"})
check(e.get("expired"), "store export of an unknown run → expired, nothing exported")
e, _ = xapi.export_start({"source": "store", "run": b["drill"]["run"], "section": "../x"})
check(not e.get("ok"), "bad section names are refused")
from core import search  # noqa: E402
sql, args = search.export_sql(search.assets, "host1", 0, None)
check(sql and "LIMIT" not in sql.upper() and args, "explorer SQL without LIMIT/OFFSET")
pg = search.assets("host1", 0, 50)["rows"]
from core import db  # noqa: E402
check([r["uuid"] for r in db.query(sql, args)][:50] == [r["uuid"] for r in pg], "…same rows, same order as the page")
from agents.ex_assets import api as eaapi  # noqa: E402
e, _ = eaapi.search_export({"q": ""})
check(e.get("ok") and not e.get("inline"), "Asset Explorer: every asset (>5,000) as a background job")
from agents.ex_compliance import api as ecapi  # noqa: E402
e, _ = ecapi.export({})
ex = wait(e["export"]["id"])
check(ex.get("rows") == N * C, "Compliance Explorer: every result — no 50,000 cap (%s of %d)" % (ex.get("rows"), N * C))
from core import acrlog  # noqa: E402
_orig = acrlog.export_source
acrlog.export_source = lambda f=None: (["a"], lambda: ([i] for i in range(7000)), 7000)
from agents.acr import api as acrapi  # noqa: E402
e, _ = acrapi.log_export({})
check(not e.get("inline") and wait(e["export"]["id"]).get("rows") == 7000, "ACR log: 7,000 rows → background job, every row")
acrlog.export_source = _orig
from core import tagq  # noqa: E402
check("limit=2000" in open(os.path.join(ROOT, "core/tagq.py")).read() and "list_jobs(limit=-1)" in open(os.path.join(ROOT, "agents/explore/api.py")).read(),
      "Tagging log export reads every job, not the newest 2,000")
check(len(exports.recent()) >= 3, "recent exports are listed")
xapi.export_cancel({"id": "zz"})
f, _ = xapi.export_fetch({"id": "../../etc/passwd"})
check(not f["ok"], "export ids are validated (no path tricks)")

# ── 5. the pages ─────────────────────────────────────────────────────────────────────────
js = open(os.path.join(ROOT, "web/assets/console.js"), encoding="utf-8").read()
check("function hExport" in js and "function hCsvMenu" in js and "_hDrillChunked" in js and "export_fetch" in js,
      "console.js: hExport (inline / background job / download), the ⤓ CSV ▾ menu, chunked hDrill")
check("t.__exportSpec=()=>({source:'store'" in js, "every hDrill table offers 'every row'")
pg = open(os.path.join(ROOT, "agents/compliance_asset/page.html"), encoding="utf-8").read()
check("chunk:500" in pg and "'X-Hounds-Budget':'run-bg'" in pg and "list:false" in pg and "APPS=r.assets" not in pg,
      "Drill-down: 500-row chunks, a background-capable group build, no whole list from detail")
dsh = open(os.path.join(ROOT, "web/dashboards.html"), encoding="utf-8").read()
check("up to 5,000" not in dsh and "widget_export" in dsh, "Dashboards: widget CSV exports every row")
for p_ in ("agents/ex_compliance/page.html", "agents/ex_software/page.html", "agents/ex_apps/page.html",
           "agents/ex_fixed/page.html", "agents/scan_eval/page.html", "web/acr-log.html", "web/c2-log.html"):
    s_ = open(os.path.join(ROOT, p_), encoding="utf-8").read()
    check("hExport(" in s_ and "capped" not in s_.split("hExport(")[1][:400], "%s exports through hExport (no cap)" % p_)
for a_ in ("ex_vulns", "ex_plugins", "ex_routes", "ex_paths", "ex_tags", "ex_assets"):
    s_ = open(os.path.join(ROOT, "agents/%s/page.html" % a_), encoding="utf-8").read()
    check("hTableExport(" in s_, "%s: the table's ⤓ CSV ▾ → every row of the search" % a_)
from core import launcher  # noqa: E402
check(all(launcher.request_scope(ag, ac, {}, "open") == "run" for ag, ac in
          (("compliance_asset", "export"), ("compliance_asset", "cohort"), ("explore", "export_start"),
           ("dashboard", "widget_export"), ("ex_vulns", "export"))),
      "an export never runs under the 5 s page-open budget (the page's hint is ignored)")
check(launcher.request_scope("compliance_asset", "detail", {}, "open") == "open", "…other page-open reads keep it")
ov = comp.overview()
check(len(ov["assets_rows"]) == 500 and ov["assets_rows_total"] == N and ov["asset_counts"]["failed"] == nf,
      "Compliance Overview: worst 500 rows, counts over all %d assets" % N)
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
