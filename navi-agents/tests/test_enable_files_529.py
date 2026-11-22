"""Build 529 — an enable file (ALLOW_WRITES / ALLOW_EMAIL / ALLOW_REMOTE_EXEC / ALLOW_SCAN_LAUNCH)
only switches a gate on when it is a regular file owned by the server's user and not writable by
group or others; anything else is ignored and reported. Run: python3 tests/test_enable_files_529.py"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="gatecfg529_")
os.environ.update({"HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_CACHE_DIR": os.path.join(TMP, "c"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db"), "NAVI_CWD": TMP})
GATES = ("NAVI_ALLOW_WRITES", "NAVI_MCP_ALLOW_WRITES", "NAVI_EMAIL", "NAVI_MCP_ALLOW_EMAIL", "NAVI_MAIL",
          "NAVI_REMOTE_CODE_EXECUTION", "NAVI_MCP_ALLOW_REMOTE_CODE_EXECUTION", "NAVI_RCE", "NAVI_SCAN_LAUNCH")
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import navi_cli  # noqa: E402
for k in GATES:                 # after the import: the operator's own config / .env must not leak in
    os.environ.pop(k, None)
R = tempfile.mkdtemp(prefix="gate529_")
navi_cli._REPO_ROOT = R
W = os.path.join(R, "ALLOW_WRITES")

check(not navi_cli.allow_writes() and navi_cli.enable_file_warnings() == [], "no file, no env: writes off, nothing to report")
open(W, "w").close()
os.chmod(W, 0o600)
check(navi_cli.allow_writes(), "a private ALLOW_WRITES owned by this user switches writes on")
check(any("switching a gate ON" in w for w in navi_cli.enable_file_warnings()), "…and startup says a file did it")
if os.name == "posix":
    os.chmod(W, 0o666)
    check(not navi_cli.allow_writes(), "a world-writable ALLOW_WRITES is ignored")
    check(any("IGNORED" in w and "group or others" in w for w in navi_cli.enable_file_warnings()), "…and reported")
    os.chmod(W, 0o620)
    check(not navi_cli.allow_writes(), "a group-writable one is ignored too")
    os.remove(W)
    real = os.path.join(R, "elsewhere")
    open(real, "w").close()
    os.chmod(real, 0o600)
    os.symlink(real, W)
    check(not navi_cli.allow_writes(), "a symlinked ALLOW_WRITES is ignored")
    os.remove(W)
    if hasattr(os, "geteuid"):
        open(W, "w").close()
        os.chmod(W, 0o600)
        real_uid = os.geteuid
        navi_cli.os.geteuid = lambda: real_uid() + 4242
        try:
            check(not navi_cli.allow_writes(), "a file owned by another user is ignored")
        finally:
            navi_cli.os.geteuid = real_uid
for fn, fnc in (("ALLOW_EMAIL", navi_cli._email_enable_file), ("ALLOW_REMOTE_EXEC", navi_cli._rce_enable_file),
                ("ALLOW_SCAN_LAUNCH", navi_cli._scan_enable_file)):
    p = os.path.join(R, fn)
    open(p, "w").close()
    os.chmod(p, 0o666)
    check(fnc() == "", "%s: the same rule applies" % fn)
    os.chmod(p, 0o600)
    check(fnc() == p, "%s: honored when private" % fn)
gi = open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read().split()
check(all(n in gi for n in ("ALLOW_WRITES", "ALLOW_EMAIL", "ALLOW_REMOTE_EXEC", "ALLOW_SCAN_LAUNCH")),
      ".gitignore keeps every enable file out of git")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
