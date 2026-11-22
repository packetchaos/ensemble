"""Build 529 — the loopback-only rule is enforced on EVERY destructive action, not just Settings.

When HOUNDS_BIND opens the console to the LAN, a browser on another host may read, preview and
stop work — but a Tenable write (tag / ACR), mail, remote execution, scan launch or an armed run
answers 403 remote_refused unless the server was started with HOUNDS_REMOTE_WRITES=1.
Run: python3 tests/test_remote_writes_529.py"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="rw529_")
os.environ.update({"HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_DB_PATH": os.path.join(TMP, "navi.db"),
                   "NAVI_CACHE_DIR": os.path.join(TMP, "c"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db"),
                   "NAVI_CWD": TMP})
for k in ("HOUNDS_REMOTE_WRITES", "NAVI_ALLOW_WRITES", "NAVI_MCP_ALLOW_WRITES"):
    os.environ.pop(k, None)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import launcher  # noqa: E402

REMOTE, LOCAL = "10.1.2.3", "127.0.0.1"
WRITES = [("acr", "apply", {"confirm": True, "uuids": ["u1"], "acr": 9}),
          ("email", "send", {"confirm": True, "to": "a@b.c"}),
          ("c2", "campaign", {"armed": True, "hosts": ["10.0.0.1"], "command": "id"}),
          ("scan_confirm", "scan_launch", {"confirm": True}),
          ("explore", "tag_retry", {"confirm": True}),
          ("asset_ownership", "tag", {"uuids": ["u1"]})]            # destructive name, no dry-run flag
for agent, action, p in WRITES:
    b, code = launcher.dispatch(agent, action, dict(p), peer=REMOTE, http=True)
    check(code == 403 and b.get("remote_refused"), "remote %s.%s is refused (%s)" % (agent, action, code))
    b, code = launcher.dispatch(agent, action, dict(p), peer=LOCAL, http=True)
    check(not (isinstance(b, dict) and b.get("remote_refused")), "loopback %s.%s isn't refused by this rule" % (agent, action))

# previews, reads and stops still work from another host
check(not launcher.is_destructive("acr", "apply", {"confirm": False}), "an explicit dry run (confirm:false) is a preview")
check(not launcher.is_destructive("kev", "overview", {}), "reads aren't destructive")
check(not launcher.is_destructive("contract", "release_cancel", {}), "stopping work isn't destructive")
check(not launcher.is_destructive("settings", "set_env", {"confirm": True}), "Settings keeps its own (stricter) per-field rules")
check(launcher.is_destructive("kev", "anything", {"confirm": True}), "any confirm:true payload counts")

# the in-process / CLI caller (no HTTP peer) is never refused
b, code = launcher.dispatch("acr", "apply", {"confirm": True, "uuids": ["u1"], "acr": 9}, peer=None, http=False)
check(not (isinstance(b, dict) and b.get("remote_refused")), "in-process callers aren't affected")

# opt-in from the environment only
os.environ["HOUNDS_REMOTE_WRITES"] = "1"
b, code = launcher.dispatch("acr", "apply", {"confirm": True, "uuids": ["u1"], "acr": 9}, peer=REMOTE, http=True)
check(not (isinstance(b, dict) and b.get("remote_refused")), "HOUNDS_REMOTE_WRITES=1 lets a remote browser through to the normal gates")
os.environ.pop("HOUNDS_REMOTE_WRITES")
from core import config_store  # noqa: E402
check("HOUNDS_REMOTE_WRITES" not in getattr(config_store, "MANAGED", ()), "the opt-in can't be set from the browser (Settings)")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
