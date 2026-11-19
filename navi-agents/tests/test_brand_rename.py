"""Build 490 — the UI rename "The Hounds" → navi Ensemble: retired terms are gone from what users see.

Scans web/ (except the generated one-pagers' embedded images), agents/*/page.html, agents/*/manifest.json
and tools/hound_pages/*.json for retired brand words, codenames and dog breeds. Stable identifiers that
users' saved state, scripts and dashboards depend on are ALLOWED (see ALLOW — each has a reason).
Also checks: core/brand.py ⇄ web/assets/brand.js agree, every manifest matches the roster, only the nine
heroes carry a codename, Argos now names Device Discovery (iot_squad), and the version is 2.<n>.<build>.
Run: python3 tests/test_brand_rename.py"""
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import brand, version  # noqa: E402

# ── 1. the retired-term sweep ───────────────────────────────────────────────────────────────
RETIRED = [r"\bhounds?\b", r"Release the Hounds", r"\bthe pack\b", r"On the Scent", r"AI Contract", "🐾",
           r"Command (?:&amp;|&) Control", r"Standing Orders", r"\bBriefing\b", r"Route Mapping"]
RETIRED += [r"\b%s\b" % w for w in (
    "Covenant Cerberus Anubis Orthrus Cavall Janus Mimir Chronos Terminus Sköll Skoll Nemesis Sphinx Daedalus "
    "Gabriel Minos Tiresias Draco Amarok Garmr Sirius Atlas Bloodhound Hellhound Foxhound Wolfhound Greyhound "
    "Deerhound Beagle Basset Saluki Plott Vizsla Harrier").split()] + [r"Alert Raven", r"Sk\\u00f6ll"]
# allowed: identifiers that must not change (reason in the comment)
ALLOW = [
    r"HOUNDS_[A-Z_]+",                 # env vars (HOUNDS_CONFIG, HOUNDS_BIND …)
    r"X-Hounds-[\w-]+",                # request headers the server reads
    r"\bhounds[A-Z]\w*",               # localStorage keys (houndsRelOff, houndsCache…)
    r"hounds:(?:ran|wrote)",           # browser event names
    r"hounds-[\w-]+",                  # element ids / file names (hounds-c2-…, hounds-dash-…)
    r"/web/hounds/[\w./-]*", r"web/hounds/",   # one-pager URLs (kept for old links)
    r"hounds_mcp\w*", r"test_hound\w*", r"hound_pages\w*",   # module / test / tool names
    r"hounds\.config\.json",           # the config file name
    r"the-hounds-repo",                # the repo name
    r"Hounds-[A-Z][\w ]*",             # the test-run tag PREFIX default ('Hounds-Owner' …) — a Tenable tag value
    r"Default Hounds\.",               # …and the Settings help that names that default
    r"[\w.]+\.hounds?\b", r"\bhounds?(?=\s*[=:,)\]}])", r"\{hounds?\b", r"\$\{hounds?\}",   # JS / Py code
    r"\bhounds?\.(?:length|every|forEach|slice|map|join|includes|filter|push)\b",
    r"\bconst hounds?\b", r"\blet hounds?\b", r"source_hound", r"\bhound\(", r"hounds\[",
    r"MITRE ATLAS", r"\bATLAS\b",      # MITRE ATLAS (Pythia's AI attack matrix) — not the old Atlas
]
FILES = ([f for f in glob.glob(os.path.join(ROOT, "web", "**", "*.html"), recursive=True)]
         + glob.glob(os.path.join(ROOT, "web", "assets", "*.js"))
         + glob.glob(os.path.join(ROOT, "agents", "*", "page.html"))
         + [f for f in glob.glob(os.path.join(ROOT, "agents", "*", "manifest.json")) if "_template" not in f]
         + glob.glob(os.path.join(ROOT, "tools", "hound_pages", "*.json")))
_allow = re.compile("|".join("(?:%s)" % a for a in ALLOW))
_comment = re.compile(r"/\*.*?\*/|<!--.*?-->|(?<![:\"'\\])//[^\n]*", re.S)
hits = []
for f in FILES:
    s = open(f, encoding="utf-8").read()
    s = re.sub(r"data:image/[a-z]+;base64,[A-Za-z0-9+/=]+", "", s)
    s = _comment.sub(" ", s)                       # code comments aren't shown to users
    s = _allow.sub(" ", s)
    rel = os.path.relpath(f, ROOT)
    for pat in RETIRED:
        for m in re.finditer(pat, s, re.I if pat.startswith(r"\bhound") else 0):
            w = m.group(0)
            # "Argos" is allowed only where it now means Device Discovery (iot_squad)
            # "Argos" now names Device Discovery (iot_squad): allowed, EXCEPT on the old asset deep-dive's own
            # files or next to a link to it (that one is "Asset Dossier" now)
            if w == "Argos" and "agents/argos/" not in rel and "/agents/argos/" not in s[max(0, m.start() - 160):m.end() + 160]:
                continue
            hits.append("%s: %r … %s" % (rel, w, s[max(0, m.start() - 40):m.end() + 30].replace("\n", " ")))
for h in hits[:40]:
    print("   ", h)
check(not hits, "no retired brand word, codename or breed in the UI (%d hit(s))" % len(hits))

# ── 2. brand.js ⇄ brand.py ──────────────────────────────────────────────────────────────────
js = open(os.path.join(ROOT, "web", "assets", "brand.js"), encoding="utf-8").read()
m = re.search(r"window\.BRAND = (\{.*?\});\n", js, re.S)
check(m and json.loads(m.group(1)) == brand.as_dict(), "web/assets/brand.js is generated from core/brand.py (run tools/brand_js.py)")
check(brand.BRAND == "navi Ensemble" and brand.HOME_ACTION == "Run the Ensemble", "brand + home action")
check(brand.ORCHESTRATOR == "Automation" and brand.OVERVIEW == "Ensemble Report"
      and brand.name("contract") == "Automation" and brand.name("insights") == "Ensemble Report",
      "build 491: Standing Orders → Automation, Briefing → Ensemble Report")
check(brand.name("exproute") == "Exposure Routes", "build 491: Route Mapping → Exposure Routes")
check(len(brand.HEROES) == 9 and set(brand.HEROES) == {"cisakev", "attackpath", "classify", "eol", "certificate",
                                                      "postquantum", "iot_squad", "ai", "was"}, "nine heroes")
check(brand.ROSTER["iot_squad"][1] == "Argos" and brand.ROSTER["argos"][0] == "Asset Dossier",
      "Argos now names Device Discovery; the asset deep-dive is Asset Dossier")
check(brand.display("eol") == "Charon · End of Life" and brand.display("acr") == "Criticality Calibration",
      "display rule: heroes 'Codename · Plain job', others the plain name")

# ── 3. manifests follow the roster; ids unchanged ───────────────────────────────────────────
for f in sorted(glob.glob(os.path.join(ROOT, "agents", "*", "manifest.json"))):
    mf = json.load(open(f, encoding="utf-8"))
    i = mf["id"]
    check(i == os.path.basename(os.path.dirname(f)), "%s: id still matches its folder" % i)
    r = brand.ROSTER.get(i)
    if not r:
        continue
    ok = (mf["name"] == r[0] and mf.get("mission") == r[2] and mf.get("hero") == (r[4] == "hero")
          and mf.get("codename", "") == (r[1] if r[4] == "hero" else ""))
    check(ok, "%s: name / mission / hero / codename from the roster" % i)
    if r[4] == "explorer":
        check(mf.get("grid") is False, "%s: an Explorer tab, off the home grid (page still routable)" % i)

# ── 4. codename banner + crests ─────────────────────────────────────────────────────────────
cjs = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
cm = re.search(r"const CODENAMES = \{(.*?)\n\};", cjs, re.S)
keys = set(re.findall(r"^\s*([a-z_0-9]+):\{name:", cm.group(1), re.M)) if cm else set()
check(keys == set(brand.HEROES), "CODENAMES holds exactly the nine heroes")
check("_isHero(id)" in cjs and "_NO_CODENAME" not in cjs, "the codename banner shows only for heroes (manifest.hero)")
check("function crestSrc(id)" in cjs, "crestSrc() kept as is (test_security_client checks it)")
check(".hcrest{display:inline-block;background:url('/static/brand-mark.png" in
      open(os.path.join(ROOT, "web", "assets", "console.css"), encoding="utf-8").read(), "the brand mark replaces the pack crest")

# ── 5. stable identifiers survived ──────────────────────────────────────────────────────────
ver = version.version_string()
check(re.fullmatch(r"2\.\d+\.%d" % version.BUILD, ver) is not None and version.MAJOR == 2, "version 2.<specialists>.<build>: " + ver)
check(os.path.exists(os.path.join(ROOT, "web", "hounds", "cisakev.html")), "/web/hounds/<id>.html one-pagers still exist")
check("https://github.com/packetchaos/ensemble/tree/main/navi-agents/agents/" in cjs and "packetchaos/the-hounds-repo" not in cjs,
      "‹ › Code buttons point at the ensemble repo")
check(os.path.exists(os.path.join(ROOT, "hounds_mcp.py")), "hounds_mcp.py (MCP tool names) unchanged")
idx = open(os.path.join(ROOT, "web", "index.html"), encoding="utf-8").read()
check("get('release')==='1'" in idx, "/?release=1 deep link still opens the run dialog")

print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
