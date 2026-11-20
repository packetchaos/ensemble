"""Build 503 — Exposure Routes and SLA Tracker show their last run as the SAME separate banner
the page cache draws for every other specialist (console.js hSnapBanner → #hcBanner), not a line
inside the page's header card. Static check. Run: python3 tests/test_snap_banner_503.py"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


js = open(os.path.join(ROOT, "web/assets/console.js"), encoding="utf-8").read()
check("function hSnapBanner(o)" in js and "d.id='hcBanner'; d.className='hc-banner'" in js,
      "console.js: hSnapBanner draws the page cache's own #hcBanner / .hc-banner")
check("Restored your last run" in js[js.index("function hSnapBanner"):], "hSnapBanner says 'Restored your last run' like the page cache")
for page in ("agents/exproute/page.html", "agents/sla/page.html"):
    s = open(os.path.join(ROOT, page), encoding="utf-8").read()
    check('id="snapMeta"' not in s and "getElementById('snapMeta')" not in s, page + ": no cache line inside the header card")
    check(re.search(r"hSnapBanner\(\{at:m\.built_at", s) is not None, page + ": last run shown with hSnapBanner")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
