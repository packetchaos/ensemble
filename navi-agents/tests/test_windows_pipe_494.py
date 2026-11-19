"""Build 494 — a console navi job on Windows runs to its real end and keeps all its output.

Windows has no pty, so cli_jobs reads navi through a plain pipe. The reader used select(), which
on Windows only accepts sockets: it raised at once, the reader gave up and CLOSED the pipe, navi
died on its next write, and Automation Station reported a multi-hour assets/vulns sync finished
in ~4 s. This simulates Windows (no pty + a select() that raises WinError 10038) with a fake navi
that writes, waits, and writes again, and checks the job lasts as long as navi and loses nothing.
Also re-checks the pty path. No navi, no network. Run: python3 tests/test_windows_pipe_494.py"""
import os
import select
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


_TMP = tempfile.mkdtemp(prefix="wp494_")
os.environ["NAVI_CACHE_DIR"] = os.path.join(_TMP, "cache")
os.environ.pop("NAVI_CWD", None)
real = os.path.join(_TMP, "navi.db")                 # not the sample → the sample guard stays out
shutil.copy(ensure_sample(ROOT), real)
os.environ["NAVI_DB_PATH"] = real

fake = os.path.join(_TMP, "navi")
with open(fake, "w") as f:
    f.write("#!%s\nimport sys, time\n"
            "print('Requesting export', flush=True)\n"
            "time.sleep(3)\n"
            "for i in range(200):\n    print('chunk %%d downloaded' %% i, flush=True)\n"
            "print('Export complete', flush=True)\n" % sys.executable)
os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)
os.environ["NAVI_BIN"] = fake

from core import cli_jobs, db  # noqa: E402
db._DISCOVERED = None


def run_one(label):
    t0 = time.time()
    r = cli_jobs.start_update("assets", refresh_summaries=False)
    check(r.get("ok") is True, "%s: job starts (%s)" % (label, r.get("error", "")))
    jid = (r.get("job") or {}).get("id")
    for _ in range(300):
        j = (cli_jobs.poll(jid, since=0) or {}).get("job") or {}
        if j.get("status") != "running":
            break
        time.sleep(0.1)
    took = time.time() - t0
    lines = j.get("lines") or []
    check(j.get("status") == "done" and j.get("returncode") == 0, "%s: navi exits 0 (%s)" % (label, j.get("status")))
    check(took >= 2.9, "%s: the job lasts as long as navi does (%.1fs, navi takes 3s)" % (label, took))
    check("Export complete" in lines and sum(1 for ln in lines if ln.startswith("chunk ")) == 200,
          "%s: every output line arrives, through the last one" % label)


# 1. the real (pty) path on this machine
if cli_jobs._HAS_PTY:
    run_one("pty")

# 2. simulated Windows: no pty, and select() refuses a pipe like Windows does
_real_select = select.select


def _win_select(r, w, x, t=None):
    if any(not hasattr(o, "fileno") for o in r):   # a raw fd (pipe), not a socket object
        raise OSError(10038, "An operation was attempted on something that is not a socket")
    return _real_select(r, w, x, t)


cli_jobs._HAS_PTY = False
select.select = _win_select
try:
    run_one("windows pipe")
finally:
    select.select = _real_select

shutil.rmtree(_TMP, ignore_errors=True)
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
