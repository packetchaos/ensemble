"""Build 529 — no silent `except Exception: pass` in the console's Python: every deliberately
ignored exception goes through core/errors.swallowed (counted per call site, logged, reported in
/api/health). Run: python3 tests/test_swallowed_529.py"""
import glob
import logging
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


pat = re.compile(r"^[ \t]*except Exception:[ \t]*(?:#[^\n]*)?\n[ \t]+pass\b|^[ \t]*except Exception:[ \t]*pass\b", re.M)
left = []
for p in glob.glob(os.path.join(ROOT, "core", "*.py")) + glob.glob(os.path.join(ROOT, "agents", "*", "*.py")) \
        + glob.glob(os.path.join(ROOT, "app_*.py")) + [os.path.join(ROOT, "hounds_mcp.py")]:
    if os.path.exists(p) and pat.search(open(p, encoding="utf-8").read()):
        left.append(os.path.relpath(p, ROOT))
check(not left, "no silent `except Exception: pass` left %s" % left[:5])

from core import errors  # noqa: E402
recs = []


class H(logging.Handler):
    def emit(self, r):
        recs.append(r)


logging.getLogger("hounds.swallowed").addHandler(H())
logging.getLogger("hounds.swallowed").setLevel(logging.DEBUG)
for i in range(12):
    try:
        raise ValueError("boom %d" % i)
    except Exception as e:
        errors.swallowed(e)
site = [k for k in errors.counts() if k.startswith("tests")]
check(len(site) == 1 and errors.counts()[site[0]] == 12, "counted per call site (%s)" % errors.counts())
check(len(recs) == 2 and "ValueError" in recs[0].getMessage(), "logged on the 1st and 10th time only (%d)" % len(recs))
check(recs[0].levelno == logging.DEBUG, "quiet (DEBUG) by default")
os.environ["HOUNDS_LOG_SWALLOWED"] = "1"
try:
    raise KeyError("x")
except Exception as e:
    errors.swallowed(e)
check(recs[-1].levelno == logging.WARNING, "HOUNDS_LOG_SWALLOWED=1 turns them up to WARNING")
errors.swallowed(None)
check(True, "never raises, even with nothing to record")
from core import launcher  # noqa: E402
check(launcher.health().get("swallowed_errors", -1) >= 13, "/api/health reports the total")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
