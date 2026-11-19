"""Brand — the single source of truth for the console's user-facing names (build 490).

The UI was renamed from "The Hounds" to **navi Ensemble**. Only what a user SEES changed:
agent ids, folders, API routes, /web/hounds/<id>.html URLs, Tenable tag categories, env vars
(HOUNDS_*), localStorage keys (hounds*), MCP tool names and module names are unchanged.

web/assets/brand.js carries the same data for the browser; tools/brand_js.py writes it from
this file, and tests/test_brand_rename.py checks the two agree. Change the brand here, then
run `python3 tools/brand_js.py`.

Display rule: a HERO shows "Codename · Plain job" (e.g. "Charon · End of Life"); everyone else
shows the plain name only — no codename banner, no lore, no crest.
"""
BRAND = "navi Ensemble"
SHORT = "Ensemble"
TAGLINE = "Specialist AI agents for exposure management, grounded in your Tenable data"
HOME_ACTION = "Run the Ensemble"          # was "Release the Hounds"
ORCHESTRATOR = "Automation"               # 491; was "Standing Orders" (490), "Covenant · AI Contract" before
ORCHESTRATOR_RUNNER = "the Lead"
OVERVIEW = "Ensemble Report"              # 491; was "Briefing" (490), "Sphinx · On the Scent" before
MEMBER = "specialist"                     # never "hound"; together they are "the Ensemble"
BRAND_MARK = "/static/brand-mark.png"     # the iris mark (web/assets/brand-logo.png is the full logo)

MISSIONS = ["Exploited Now", "Asset Truth", "Coverage", "Ownership & SLA", "Crypto & Certificates",
            "OT, IoT & Unmanaged", "AI Exposure", "Web Apps", "Compliance", "Platform"]

# id: (display name, codename (heroes only), mission, icon, kind)
#   kind: "hero" | "specialist" | "instrument" (grid order inside a mission) | "explorer"
ROSTER = {
    "cisakev":          ("CISA KEV", "Laelaps", "Exploited Now", "🛡️", "hero"),
    "attackpath":       ("Attack Paths", "Fenrir", "Exploited Now", "🕸️", "hero"),
    "mitre":            ("ATT&CK Mapping", "", "Exploited Now", "🎯", "specialist"),
    "fused_score":      ("Exposure Score", "", "Exploited Now", "🎯", "instrument"),
    "classify":         ("Classification", "Linnaeus", "Asset Truth", "📇", "hero"),
    "eol":              ("End of Life", "Charon", "Asset Truth", "🔩", "hero"),
    "identity":         ("Identity Inventory", "", "Asset Truth", "🪪", "specialist"),
    "software":         ("Software Inventory", "", "Asset Truth", "📦", "specialist"),
    "customapp":        ("Custom App Discovery", "", "Asset Truth", "🏷️", "specialist"),
    "argos":            ("Asset Dossier", "", "Asset Truth", "🔦", "instrument"),
    "scan_eval":        ("Scan Health", "", "Coverage", "🩺", "specialist"),
    "agentgroup":       ("Agent Group Sync", "", "Coverage", "🛰️", "specialist"),
    "asset_ownership":  ("Ownership", "", "Ownership & SLA", "📌", "specialist"),
    "exproute":         ("Exposure Routes", "", "Ownership & SLA", "🧭", "specialist"),
    "sla":              ("SLA Tracker", "", "Ownership & SLA", "⏱", "specialist"),
    "acr":              ("Criticality Calibration", "", "Ownership & SLA", "⚖️", "specialist"),
    "email":            ("Notify & Reports", "", "Ownership & SLA", "📧", "instrument"),
    "certificate":      ("Certificates", "Certania", "Crypto & Certificates", "🔐", "hero"),
    "postquantum":      ("Post-Quantum", "Heimdall", "Crypto & Certificates", "⚛️", "hero"),
    "iot_squad":        ("Device Discovery", "Argos", "OT, IoT & Unmanaged", "📡", "hero"),
    "ai":               ("AI Inventory", "Pythia", "AI Exposure", "🤖", "hero"),
    "was":              ("Web App Scanning", "Arachne", "Web Apps", "🕸️", "hero"),
    "was_asset":        ("Web App Dossier", "", "Web Apps", "🔬", "instrument"),
    "compliance":       ("Compliance Overview", "", "Compliance", "⚖️", "specialist"),
    "compliance_asset": ("Compliance Drill-down", "", "Compliance", "🔍", "instrument"),
    "custom_audit":     ("Audit Authoring", "", "Compliance", "📜", "specialist"),
    "contract":         ("Automation", "", "Platform", "📜", "instrument"),
    "insights":         ("Ensemble Report", "", "Platform", "📰", "instrument"),
    "c2":               ("Remote Remediation", "", "Platform", "🐺", "instrument"),
    "tagremoval":       ("Tag Removal", "", "Platform", "🗑️", "instrument"),
    "alert":            ("Alerts", "", "Platform", "🐦‍⬛", "instrument"),
    "dashboard":        ("Dashboard Builder", "", "Platform", "📊", "instrument"),
    "mcpcmp":           ("MCP Routing Reference", "", "Platform", "⚖", "instrument"),
    "ex_assets":        ("Explorer › Assets", "", "Platform", "🔎", "explorer"),
    "ex_vulns":         ("Explorer › Vulnerabilities", "", "Platform", "🔎", "explorer"),
    "ex_plugins":       ("Explorer › Plugins", "", "Platform", "🔎", "explorer"),
    "ex_routes":        ("Explorer › Routes", "", "Platform", "🔎", "explorer"),
    "ex_paths":         ("Explorer › Paths", "", "Platform", "🔎", "explorer"),
    "ex_software":      ("Explorer › Software", "", "Platform", "💿", "explorer"),
    "ex_tags":          ("Explorer › Tags", "", "Platform", "🏷️", "explorer"),
    "ex_fixed":         ("Explorer › Fixed", "", "Platform", "🩹", "explorer"),
    "ex_compliance":    ("Explorer › Compliance", "", "Platform", "📋", "explorer"),
    "ex_apps":          ("Explorer › Web Apps", "", "Platform", "🌐", "explorer"),
    "advanced":         ("Explorer › Advanced", "", "Platform", "🔎", "explorer"),
    "hub":              ("Run the Ensemble", "", "Platform", "", "instrument"),
}
HEROES = [i for i, r in ROSTER.items() if r[4] == "hero"]
KIND_ORDER = {"hero": 0, "specialist": 1, "instrument": 2, "explorer": 3}


def name(agent_id):
    r = ROSTER.get(agent_id)
    return r[0] if r else agent_id


def display(agent_id):
    """"Codename · Plain job" for a hero, the plain name for everyone else."""
    r = ROSTER.get(agent_id)
    if not r:
        return agent_id
    return f"{r[1]} · {r[0]}" if r[4] == "hero" and r[1] else r[0]


def is_hero(agent_id):
    r = ROSTER.get(agent_id)
    return bool(r and r[4] == "hero")


def title(page):
    return f"{page} — {BRAND}" if page else BRAND


def as_dict():
    """What brand.js carries (tools/brand_js.py)."""
    return {"brand": BRAND, "short": SHORT, "tagline": TAGLINE, "home": HOME_ACTION,
            "orchestrator": ORCHESTRATOR, "runner": ORCHESTRATOR_RUNNER, "overview": OVERVIEW,
            "member": MEMBER, "mark": BRAND_MARK, "missions": MISSIONS,
            "roster": {i: {"name": r[0], "codename": r[1], "mission": r[2], "icon": r[3], "kind": r[4],
                           "hero": r[4] == "hero"} for i, r in ROSTER.items()}}
