"""Build 528 — Exposure Score: the "Act now" glance card and the Act now section read one helper
(actView), so their numbers can't disagree. With no asset over the line both show 0 and say the
worst 10 are listed instead, with that list's own unowned / crown+KEV / blind counts.
Run: python3 tests/test_act_now_528.py"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
s = open(os.path.join(ROOT, "agents/fused_score/page.html"), encoding="utf-8").read()
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


check("function actView()" in s, "one act-now view")
glance = s.split("{title:'Act now ≥ '+THR")[1].split("{title:'Convergence'")[0]
check("actView()" in glance and "st.unowned" not in glance, "the glance card reads actView, not the raw ≥-line stats")
draw = s.split("function drawAct(){")[1].split("document.getElementById('actbtns')")[0]
check("actView()" in draw and "N(V.n)" in draw, "the section reads actView; its big number is the same count as the card")
check("none yet — the worst" in glance and "the worst ${S.length} are listed instead" in draw, "both say when the worst 10 are listed instead")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
