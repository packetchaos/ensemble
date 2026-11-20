"""Build 512 — small tweaks: Run the Ensemble grid without mission headings, header icon tiles
(Dashboards · Explorer · Settings), ACR ▶ Run, Software Inventory doesn't auto-scroll and the
Ensemble runs all four of its sections, "Asset Ownership", act-now defaults to Critical.
Run: python3 tests/test_tweaks_512.py"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


P = lambda f: open(os.path.join(ROOT, f), encoding="utf-8").read()

idx = P("web/index.html")
r = idx[idx.index("function render(){"):idx.index("function cardEls(")]
check('class="mhead"' not in r and 'data-cat="__all">All</button>' in idx and "curCat='__all'" in idx,
      "Run the Ensemble: one even grid, no hard mission headings; the chips filter (default All)")

js = P("web/assets/console.js")
check("function mountDashIcon(hdr)" in js and "mountDashIcon(hdr); mountSearchIcon(hdr); hdr.appendChild(g)" in js,
      "header: Dashboards icon, then Explorer, then Settings")
for f in ("dashboard.png", "search.png", "settings.png"):
    check(os.path.getsize(os.path.join(ROOT, "web/assets/icons", f)) > 1000 and f"/static/icons/{f}" in js,
          f"header uses the purple icon tile {f}")
check(".hgear.lvl-red i" in js and "<i></i>" in js, "the settings light still sits on the gear tile")

acr = P("agents/acr/page.html")
check(">▶ Run</button>" in acr and "▶ Load" not in acr.replace("▶ Load fetches", ""), "ACR: ▶ Run (not Load)")

sw = P("agents/software/page.html")
crown = sw[sw.index("async function runCrown(){"):sw.index("/* ===== Software risk leaderboard")]
risk = sw[sw.index("async function runSwRisk(){"):sw.index("/* ===== NL → SQL ask")]
check("scrollIntoView" not in crown and "scrollIntoView" not in risk,
      "Software: Run all / the Ensemble replay no longer scroll the page to the bottom")
check("API.post('lifecycle',{run:SW.run, server:true})" in sw and "function _eolDone(o, f)" in sw,
      "Software: lifecycle asks the server first (what the Ensemble records)")
rec = json.load(open(os.path.join(ROOT, "core/release_recipes.json"), encoding="utf-8"))
items = rec if isinstance(rec, list) else (rec.get("pages") or [])
s = next(x for x in items if x.get("agent") == "software")
check(s["steps"] == ["swRun", "swEol", "swCrown", "swRisk"], "Software: the Ensemble replays all four sections")
from agents.software import api as swapi  # noqa: E402
calls = []
fake = lambda a, act, b: (calls.append(act) or ({"ok": True, "drill": {"run": "r1"}}, 200))
out = swapi.release_requests(fake)
check([a for a, _b, _o in out] == ["inventory", "lifecycle", "crown", "risk"], "Software: the release records all four")

from core import brand  # noqa: E402
check(brand.ROSTER["asset_ownership"][0] == "Asset Ownership", "specialist renamed: Asset Ownership")
check('"name": "Asset Ownership"' in P("web/assets/brand.js") and '"name": "Asset Ownership"' in P("agents/asset_ownership/manifest.json")
      and "Asset Ownership</h2>" in P("agents/asset_ownership/page.html"), "…in brand.js, its manifest and its page")

fs = P("agents/fused_score/page.html")
check("if(!THR_USER){ THR=80; }" in fs and '<button data-t="80" class="on">Critical' in fs, "Exposure Score act now opens on Critical")
from core import insights  # noqa: E402
p = insights.recommended_play({"kpi": {"act": {"60": {"n": 1}}}, "assets": [{"score": 70, "factors": {}, "applies": {}}]})
check(p["threshold"] == 80, "Ensemble Report: the act-now play uses Critical (≥ 80)")
check('"Act on the critical set"' in P("core/insights.py") and 'act = g(fk, "act", "80"' in P("core/insights.py"),
      "Ensemble Report: What to do next — act on the critical set (≥ 80)")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
