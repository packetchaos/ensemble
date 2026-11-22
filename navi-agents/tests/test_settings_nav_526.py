"""Build 526 → 527 — Settings is simple to find your way around: one card per job (the Scan
Confirmation intent pattern), and only that job's sections show. Every section belongs to a job;
deep links to a card (#secTables, #secHx, #secSla — Run the Ensemble's preflight) open its job.
Run: python3 tests/test_settings_nav_526.py"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
s = open(os.path.join(ROOT, "web/settings.html"), encoding="utf-8").read()
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


groups = re.findall(r'class="intent" data-g="([a-z]+)"', s)
check(groups == ["ai", "safety", "policy", "data", "external", "about"], "six intent cards (%s)" % groups)
cards = re.findall(r'<section class="card"[^>]*>', s)
inner = [c for c in cards if 'id="setTop"' not in c]
check(inner and all('data-g="' in c for c in inner), "every section belongs to a job (%d sections)" % len(inner))
used = {g for c in inner for g in re.search(r'data-g="([^"]+)"', c).group(1).split()}
check(used == set(groups), "every job has sections, and no section points at a missing job")
ids = re.findall(r'<section class="card"[^>]*id="([^"]+)"', s)
check(len(ids) == len(set(ids)), "section ids are unique")
for sec in ("secTables", "secHx", "secSla"):
    check('id="%s"' % sec in s, "deep link target #%s still exists" % sec)
check("function fromHash" in s and "hashchange" in s and "section.card[data-g]:not(.gshow){display:none}" in s,
      "a deep link opens its job; other jobs' sections are hidden")
check('id="crownInp"' in s and "NAVI_CROWN_ACR" in s, "Crown jewels card sets NAVI_CROWN_ACR")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
