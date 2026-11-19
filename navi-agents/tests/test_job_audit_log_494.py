"""Build 494 — every console navi job writes its full output to an audit log on the server, and
Automation Station can show any step's output live (or replay it from that log).

Checks, with a fake navi (no network): one log file per job with header, every line (even past
the in-memory window cap) and an exit/duration footer; who-started-it notes; in-process jobs
(⚡ Optimize) logged too; the per-run summary log; the pipeline records each step's job + log;
the read API only opens names the runner writes (no traversal); retention; an unwritable log
folder never stops the job. Run: python3 tests/test_job_audit_log_494.py"""
import os
import re
import shutil
import stat
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
from _sample import ensure_sample  # noqa: E402
sys.path.insert(0, ROOT)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


_TMP = tempfile.mkdtemp(prefix="al494_")
LOGS = os.path.join(_TMP, "logs")
os.environ["NAVI_JOB_LOG_DIR"] = LOGS
os.environ["NAVI_CACHE_DIR"] = os.path.join(_TMP, "cache")
os.environ.pop("NAVI_CWD", None)
real = os.path.join(_TMP, "navi.db")
shutil.copy(ensure_sample(ROOT), real)
os.environ["NAVI_DB_PATH"] = real
fake = os.path.join(_TMP, "navi")
with open(fake, "w") as f:
    f.write("#!%s\nimport sys\nprint('Requesting export', flush=True)\n"
            "for i in range(200):\n    print('chunk %%d downloaded' %% i, flush=True)\n"
            "print('Export complete', flush=True)\n" % sys.executable)
os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)
os.environ["NAVI_BIN"] = fake

from core import cli_jobs, db, release_pipeline  # noqa: E402
db._DISCOVERED = None


def wait(jid, limit=30):
    for _ in range(limit * 10):
        j = (cli_jobs.poll(jid, since=0) or {}).get("job") or {}
        if j.get("status") != "running":
            return j
        time.sleep(0.1)
    return j


# 1. a navi job → one audit log with header, every line, footer
cli_jobs.MAX_LINES = 50                                  # the window caps; the log must not
r = cli_jobs.start_update("assets", refresh_summaries=False)
jid = r["job"]["id"]
cli_jobs.note(jid, "started by a test")
j = wait(jid)
name = j.get("log")
check(bool(name) and re.match(r"^\d{8}-\d{6}-job%d-assets\.log$" % jid, name), "job reports its audit log name (%s)" % name)
p = os.path.join(LOGS, name or "x")
txt = open(p, encoding="utf-8").read() if os.path.isfile(p) else ""
check("# command   %s config update assets" % fake in txt, "header records the exact command")
check("cwd: " + _TMP in txt, "the working folder is in the log")
check("started by a test" in txt, "who-started-it note is in the log")
check(sum(1 for ln in txt.splitlines() if ln.startswith("chunk ")) == 200 and "Export complete" in txt,
      "every output line is in the log, past the window cap")
check(len(j["lines"]) <= 51, "the in-memory window stays capped (%d lines)" % len(j["lines"]))
check(re.search(r"# result    done · exit 0 · took \d", txt) is not None, "footer records result, exit code and duration")
check(any(ln.startswith("audit log: ") and ln.endswith(name) for ln in j["lines"]), "the window shows where the log is")
cli_jobs.MAX_LINES = 5000

# 2. read API: real names only
rl = cli_jobs.read_log(name)
check(rl.get("ok") and "Export complete" in rl.get("text", ""), "read_log opens it")
for bad in ("../" + name, "/etc/passwd", "x.log", name.replace(".log", ".txt"), "", None,
            "..\\" + name, os.path.join(LOGS, name)):
    check(cli_jobs.read_log(bad).get("ok") is False, "read_log refuses %r" % (bad,))

# 3. in-process jobs (⚡ Optimize) are logged and closed too
t = cli_jobs.start_task("unit task", "hx_optimize", lambda emit, live, ev: (emit("step one"), emit("step two"), {"ok": True})[-1])
tj = wait(t["job"]["id"])
tt = open(os.path.join(LOGS, tj["log"]), encoding="utf-8").read()
check("step two" in tt and "exit 0" in tt, "in-process task logged with its footer")

# 4. the API the page uses
from agents.contract import api as capi  # noqa: E402
o, code = capi.ACTIONS["navi_poll"]({"job_id": jid, "since": 0})
check(code == 200 and o.get("ok") and o["job"]["log"] == name, "contract navi_poll streams the job")
o, code = capi.ACTIONS["navi_log"]({"name": name})
check(code == 200 and "chunk 199 downloaded" in o.get("text", ""), "contract navi_log replays the log")
o, code = capi.ACTIONS["navi_log"]({"name": "../../hounds.config.json"})
check(code == 404 and o.get("ok") is False, "contract navi_log refuses a path")

# 5. the pipeline records each step's job + log and writes a run summary
cfg = release_pipeline.normalize({"updates": ["assets"], "navi_optimize": False, "hx_optimize": False, "release": False})
release_pipeline.start(trigger="manual", cfg=cfg)
for _ in range(300):
    if release_pipeline.state().get("status") != "running":
        break
    time.sleep(0.1)
st = release_pipeline.state()
step = next((s for s in st.get("steps", []) if s["key"] == "update:assets"), {})
check(st.get("status") == "done" and step.get("job") is not None and step.get("log"), "pipeline step carries its job id and log (%s)" % step.get("log"))
slog = open(os.path.join(LOGS, step.get("log") or "x"), encoding="utf-8").read() if step.get("log") else ""
check("started by Automation Station ▸ Run the Ensemble" in slog, "step log says Automation Station started it")
check(st.get("log") == st.get("id") + "-ensemble-run.log", "run summary log named after the run")
summ = cli_jobs.read_log(st.get("log")).get("text", "")
check("[done]" in summ and step.get("log") in summ, "run summary lists each step with its log")

# 6. retention
cli_jobs.LOG_KEEP = 2
cli_jobs.start_update("vulns", refresh_summaries=False)
time.sleep(1)
check(len([n for n in os.listdir(LOGS) if n.endswith(".log")]) <= 3, "old logs pruned to LOG_KEEP (+ the new one)")
cli_jobs.LOG_KEEP = 1000
time.sleep(1.5)

# 7. an unwritable log folder never stops the job
os.environ["NAVI_JOB_LOG_DIR"] = os.path.join(real, "not-a-dir")       # a FILE path → makedirs fails
r = cli_jobs.start_update("agents", refresh_summaries=False)
j = wait(r["job"]["id"])
check(j.get("status") == "done" and j.get("log") is None, "job still runs without a log folder")
check(any("audit log unavailable" in ln for ln in j["lines"]), "and says the audit log is unavailable")

shutil.rmtree(_TMP, ignore_errors=True)
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
