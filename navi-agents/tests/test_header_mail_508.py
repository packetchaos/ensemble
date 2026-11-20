"""Build 508 — every agent page mounts the standard header (indicator chips), and tool pages get no
email buttons.

- Every agents/*/page.html that loads console.js calls mountAgentHeader (Audit Authoring never did, so
  its top strip — version · data · AI · assets · db · writes, Next agent, ⚙ — was missing).
- console.js hMailAuto() returns early on the no-email tool pages (_HM_NO_EMAIL), keyed by the page URL;
  report pages are unaffected.
Run: python3 tests/test_header_mail_508.py"""
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FAILS = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS.append(msg)


missing = []
for p in sorted(glob.glob(os.path.join(ROOT, "agents", "*", "page.html"))):
    html = open(p, encoding="utf-8").read()
    if "/static/console.js" in html and "mountAgentHeader(" not in html:
        missing.append(os.path.basename(os.path.dirname(p)))
check(not missing, "every agent page mounts the standard header (missing: %s)" % missing)
ca = open(os.path.join(ROOT, "agents", "custom_audit", "page.html"), encoding="utf-8").read()
check("mountAgentHeader({id:'custom_audit'" in ca, "Audit Authoring mounts its header")

js = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
m = re.search(r"const _HM_NO_EMAIL = new Set\(\[([^\]]*)\]\)", js)
no = set(re.findall(r"'([a-z0-9_]+)'", m.group(1))) if m else set()
check({"tagremoval", "alert", "custom_audit", "c2", "mcpcmp", "contract"} <= no, "tool pages are on the no-email list")
check(not no & {"acr", "iot_squad", "dashboard", "certificate", "insights", "fused_score", "sla", "ex_assets"},
      "report pages keep their email buttons")
body = js[js.index("function hMailAuto(opts){"):js.index("function hMailAuto(opts){") + 400]
check("_HM_NO_EMAIL.has(_hmPageAgent())" in body and "return;" in body, "hMailAuto returns early on a no-email page")
check("location.pathname" in js[js.index("function _hmPageAgent"):js.index("function _hmPageAgent") + 200],
      "the page agent comes from the URL, not window.__AGENT_ID")
for a in no:
    check(os.path.isdir(os.path.join(ROOT, "agents", a)), "no-email entry %s is a real agent" % a)

print("\n%d failure(s)" % len(FAILS))
sys.exit(1 if FAILS else 0)
