"""Build 494 — navi CLI jobs refuse to run against the bundled SAMPLE database.

navi keeps its API keys and data in the navi.db of the folder it runs in, and console jobs run in
the folder of the database the console reads. On sample_navi.db that is the repo itself — no keys —
so every Tenable sync failed ("exit 1") and navi left an empty navi.db behind. Now:
  1. cli_jobs.start_update / optimize refuse with a message that names NAVI_DB_PATH;
  2. the Run the Ensemble schedule skips its navi steps with that reason (⚡ Optimize still runs);
  3. NAVI_CWD set on purpose lifts the guard;
  4. a failed step's note carries navi's last output line, not just the exit code.
No navi, no network. Run: python3 tests/test_sample_guard_494.py"""
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
from _sample import ensure_sample  # noqa: E402  (builds sample_navi.db on a fresh clone)
sys.path.insert(0, ROOT)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


_TMP = tempfile.mkdtemp(prefix="sg494_")
os.environ["NAVI_CACHE_DIR"] = os.path.join(_TMP, "cache")
os.environ.pop("NAVI_CWD", None)
os.environ["NAVI_DB_PATH"] = ensure_sample(ROOT)

from core import cli_jobs, db, release_pipeline  # noqa: E402

# 1. on the sample database every navi job is refused, with the fix in the message
db._DISCOVERED = None
reason = cli_jobs.sample_block_reason()
check("NAVI_DB_PATH" in reason and "SAMPLE" in reason, "sample database → a reason that names NAVI_DB_PATH")
r = cli_jobs.start_update("assets")
check(r.get("ok") is False and "NAVI_DB_PATH" in r.get("error", ""), "start_update('assets') refused on the sample database")
r = cli_jobs.start_update("certificates")
check(r.get("ok") is False and "SAMPLE" in r.get("error", ""), "start_update('certificates') refused too")
check("job" not in r and "id" not in r, "no navi process was started (nothing to leave an empty navi.db behind)")

# 2. a real navi.db (any other file name) is not blocked
real = os.path.join(_TMP, "navi.db")
shutil.copy(os.environ["NAVI_DB_PATH"], real)
os.environ["NAVI_DB_PATH"] = real
check(cli_jobs.sample_block_reason() == "", "a real navi.db → no sample guard")
os.environ["NAVI_DB_PATH"] = ensure_sample(ROOT)

# 3. NAVI_CWD set on purpose lifts the guard
os.environ["NAVI_CWD"] = _TMP
check(cli_jobs.sample_block_reason() == "", "NAVI_CWD set → the guard steps aside")
os.environ.pop("NAVI_CWD")

# 4. the schedule skips navi steps with the reason, and still runs the local ones
cfg = release_pipeline.normalize({"updates": ["assets", "vulns"], "navi_optimize": True,
                                  "hx_optimize": False, "release": False})
r = release_pipeline.start(trigger="manual", cfg=cfg)
check(r.get("ok") is not False, "pipeline starts")
import time  # noqa: E402
for _ in range(100):
    st = release_pipeline.state()
    if st.get("status") != "running":
        break
    time.sleep(0.1)
steps = {s["key"]: s for s in release_pipeline.state().get("steps", [])}
for k in ("update:assets", "update:vulns", "navi_optimize"):
    s = steps.get(k) or {}
    check(s.get("status") in ("error", "failed", "skipped") and "NAVI_DB_PATH" in (s.get("note") or ""),
          "%s skipped with the NAVI_DB_PATH fix in its note (%s)" % (k, s.get("status")))

# 5. a failed job's note carries navi's last line
class _FakeJobs:
    @staticmethod
    def poll(jid, since=0):
        return {"ok": True, "job": {"lines": ["cwd: /x", "Requesting export", "", "Error: 401 Unauthorized — check your keys"]}}


note = release_pipeline._last_line(_FakeJobs, 1)
check(note == " — Error: 401 Unauthorized — check your keys", "failed step note = navi's last output line: %r" % note)

shutil.rmtree(_TMP, ignore_errors=True)
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
