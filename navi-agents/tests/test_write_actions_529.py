"""Build 529 — which actions WRITE is declared once, on the server (core/launcher.write_actions),
and served to every page in /api/health; console.js's hIsWrite() asks that list, keeping its old
regex only as the fallback. Run: python3 tests/test_write_actions_529.py"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="wa529_")
os.environ.update({"HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_DB_PATH": os.path.join(TMP, "navi.db"),
                   "NAVI_CACHE_DIR": os.path.join(TMP, "c"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db"), "NAVI_CWD": TMP})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import launcher  # noqa: E402
wa = launcher.health().get("write_actions") or []
check(set(launcher._MUTATING - {"load"}) <= set(wa) and set(launcher.DESTRUCTIVE) <= set(wa),
      "/api/health serves every mutating + destructive action")
check("load" not in wa and "contract.load" in wa, "a bare 'load' stays a read; the AI Contract's load is a write")
check("overview" not in wa and "tag_plan" not in wa, "reads aren't listed")
js = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
check("function hIsWrite(" in js and "h.write_actions" in js and "hWriteActions" in js,
      "console.js reads the server's list (and caches it per browser)")
check("WRITE_RE.test(action) && !READ_OK" not in js and "H_WRITE_RE.test(ap.action)" not in js,
      "no page keeps a private write classifier any more")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
