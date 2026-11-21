"""Build 519 — the SBOM (sbom/navi-ensemble.cdx.json + .spdx.json, written by tools/sbom.py).
It must not go stale or miss a dependency:
  * the committed files match what the generator produces now (version included — regenerate on a bump),
  * every requirements*.txt line is a component,
  * every third-party module the code imports is a known component (a new dependency fails here),
  * no third-party JavaScript / CSS is vendored, and the only remote asset the pages load is Google Fonts.
Run: python3 tests/test_sbom_519.py"""
import ast
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import sbom  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


check(sbom.main(["--check"]) == 0, "committed SBOM is current (run python3 tools/sbom.py after a version bump or dependency change)")
cdx = json.load(open(sbom.CDX_PATH, encoding="utf-8"))
spdx = json.load(open(sbom.SPDX_PATH, encoding="utf-8"))
from core import version  # noqa: E402
check(cdx["metadata"]["component"]["version"] == version.version_string() == spdx["packages"][0]["versionInfo"],
      "the SBOM describes this version (%s)" % version.version_string())
check(cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.6" and spdx["spdxVersion"] == "SPDX-2.3", "formats: CycloneDX 1.6 + SPDX 2.3")
names = {c["name"].lower() for c in cdx["components"]}
for name in sbom._requirements():
    check(name in names, "requirement %s is in the SBOM" % name)
navi = next(c for c in cdx["components"] if c["name"] == "navi-pro")
check(navi["scope"] == "required" and {d for d, _r, _l in sbom.NAVI["deps"]} <= {c["name"] for c in cdx["components"]},
      "the navi CLI is a required component, with its own dependencies")
check(len({x["license"]["id"] for x in navi["licenses"]}) == 2, "navi's license conflict (setup.py GPLv3 vs LICENSE MIT) is recorded, not hidden")

# every third-party import is known
std = set(sys.stdlib_module_names)
local = set()
for root, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git", "logs", "artifacts", "node_modules")]
    for f in files:
        if f.endswith(".py"):
            local.add(f[:-3])
    for d in dirs:
        local.add(d)
known = {m for f in sbom.PACKAGES.values() for m in f["imports"]}
unknown = {}
for root, dirs, files in os.walk(ROOT):
    dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git", "logs", "artifacts", "node_modules")]
    for f in files:
        if not f.endswith(".py"):
            continue
        p = os.path.join(root, f)
        try:
            tree = ast.parse(open(p, encoding="utf-8").read())
        except (SyntaxError, UnicodeDecodeError):
            continue
        for n in ast.walk(tree):
            mods = [a.name for a in n.names] if isinstance(n, ast.Import) else (
                [n.module] if isinstance(n, ast.ImportFrom) and n.level == 0 and n.module else [])
            for m in mods:
                t = m.split(".")[0]
                if t in std or t in local or t.startswith("_") or t in known:
                    continue
                unknown.setdefault(t, os.path.relpath(p, ROOT))
check(not unknown, "every third-party import is in the SBOM %s" % unknown)

# no vendored third-party front-end code; remote assets are only Google Fonts
remote = set()
for root, dirs, files in os.walk(os.path.join(ROOT, "web")):
    for f in files:
        if f.endswith((".html", ".js", ".css")):
            txt = open(os.path.join(root, f), encoding="utf-8", errors="ignore").read()
            remote |= set(re.findall(r'<script[^>]+src="(https?://[^"]+)"', txt))
            remote |= set(re.findall(r'<link[^>]+href="(https?://[^"]+)"', txt))
            remote |= set(re.findall(r'@import\s+url\(["\']?(https?://[^"\')]+)', txt))
for root, dirs, files in os.walk(os.path.join(ROOT, "agents")):
    for f in files:
        if f.endswith(".html"):
            txt = open(os.path.join(root, f), encoding="utf-8", errors="ignore").read()
            remote |= set(re.findall(r'<script[^>]+src="(https?://[^"]+)"', txt))
check(all("fonts.googleapis.com" in u for u in remote), "the only remote asset the pages load is Google Fonts %s" % sorted(remote))
check(any(c["name"].startswith("Inter") for c in cdx["components"]), "…and the fonts are in the SBOM")
svc = {s["name"] for s in cdx["services"]}
for src, needle in (("core/kev.py", "CISA Known Exploited Vulnerabilities feed"), ("core/advisory.py", "NVD CVE API 2.0"),
                    ("core/llm.py", "Anthropic API"), ("core/software.py", "endoflife.date")):
    check(needle in svc, "service from %s is listed: %s" % (src, needle))
from agents.settings import api as sapi  # noqa: E402
b, st = sapi.sbom({"installed": True})
check(st == 200 and b["ok"] and json.loads(b["json"])["metadata"]["component"]["version"] == version.version_string(),
      "Settings serves this install's SBOM")
b, _ = sapi.sbom({"format": "spdx"})
check(json.loads(b["json"])["spdxVersion"] == "SPDX-2.3" and b["filename"].endswith(".spdx.json"), "…and the SPDX view")
st_html = open(os.path.join(ROOT, "web/settings.html"), encoding="utf-8").read()
check('<details id="sbomView"' in st_html and "pre.textContent=o.json" in st_html and "toggle" in st_html,
      "520: Settings shows the SBOM JSON in a collapsed viewer (loaded on open, as text)")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
