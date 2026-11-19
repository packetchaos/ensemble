"""One-off: the build-490 prose rename "The Hounds" → "navi Ensemble" (kept for review / re-runs).

Applies an ordered list of replacements to USER-FACING text only:
  · HTML pages: text and attribute values (never /web/hounds/ paths, ids, data-* keys …)
  · JS: string text, guarded so identifiers stay (hounds:ran events, X-Hounds-* headers,
    .hound properties, {hound:…} keys, hounds-* ids, the-hounds-repo …)
  · JSON: string values only (keys untouched)
Stable identifiers (agent ids, routes, env vars, localStorage keys, tag categories, MCP tool
names) are never touched. ONE-SHOT — already applied in build 490; never run it again on renamed files: "Argos"
names the asset deep-dive BEFORE the rename and Device Discovery AFTER it, so a second pass would
turn the new Argos into "Asset Dossier" and nothing in a file can tell the two apart. Run:  python3 tools/brand_rename.py <file> …
"""
import json
import re
import sys

# codename (with an optional " Hound" suffix) → the new display name. ORDER MATTERS: the old
# "Argos" (asset deep-dive) becomes "Asset Dossier" BEFORE "Cerberus" becomes "Argos".
CODENAMES = [
    ("Argos", "Asset Dossier"), ("Cerberus", "Argos"),
    ("Covenant", "Standing Orders"), ("Anubis", "Criticality Calibration"), ("Orthrus", "ATT&CK Mapping"),
    ("Cavall", "Custom App Discovery"), ("Janus", "Identity Inventory"), ("Mimir", "Software Inventory"),
    ("Chronos", "Scan Health"), ("Terminus", "Ownership"), ("Sköll", "SLA Tracker"), ("Sk\\u00f6ll", "SLA Tracker"),
    ("Skoll", "SLA Tracker"), ("Nemesis", "Exposure Score"), ("Sphinx", "Briefing"), ("Daedalus", "Dashboard Builder"),
    ("Gabriel", "Notify & Reports"), ("Minos", "Compliance Overview"), ("Tiresias", "Compliance Drill-down"),
    ("Draco", "Audit Authoring"), ("Amarok", "Remote Remediation"), ("Alert Raven", "Alerts"), ("Garmr", "Tag Removal"),
    ("Sirius", "Agent Group Sync"), ("Atlas", "Route Mapping"),
    ("Bloodhound", "Explorer › Assets"), ("Hellhound", "Explorer › Vulnerabilities"), ("Foxhound", "Explorer › Plugins"),
    ("Wolfhound", "Explorer › Routes"), ("Greyhound", "Explorer › Paths"), ("Deerhound", "Explorer › Advanced"),
    ("Beagle", "Web App Dossier"), ("Basset", "Explorer › Tags"), ("Saluki", "Explorer › Compliance"),
    ("Plott", "Explorer › Fixed"), ("Vizsla", "Explorer › Web Apps"), ("Harrier", "Explorer › Software"),
    # heroes keep their codename, just lose the "Hound" suffix
    ("Laelaps", "Laelaps"), ("Fenrir", "Fenrir"),
]
PHRASES = [
    (r"Release[ -]the[ -]Hounds", "Run the Ensemble"), (r"release the hounds", "run the Ensemble"),
    (r"Search Hounds", "Explorer"), (r"[Ss]earch hounds", "Explorer"),
    (r"Meet the Hound", "Meet the specialist"),
    (r"🐾\s*On the Scent", "Briefing"), (r"On the Scent", "Briefing"),
    (r"the AI (?:Navi )?Contract(?= (?:page|widget|card|tab|loop|run|plan|panel|section|schedule|adapter))", "the Standing Orders"),
    (r"the AI (?:Navi )?Contract", "Standing Orders"), (r"The AI (?:Navi )?Contract", "Standing Orders"),
    (r"AI (?:Navi )?Contract", "Standing Orders"),
    (r"Command (?:&amp;|&) Control", "Remote Remediation"),
    (r"The Hound Pack", "The Ensemble"), (r"the Hound Pack", "the Ensemble"),
    (r"The Hounds'(?!s)", "navi Ensemble's"), (r"the Hounds'(?!s)", "the Ensemble's"),
    (r"The Hounds", "navi Ensemble"), (r"the Hounds", "the Ensemble"),
    (r"\bThe Pack\b", "The Ensemble"), (r"\bThe pack\b", "The Ensemble"), (r"\bthe pack\b", "the Ensemble"),
    (r"\bpack's\b", "Ensemble's"),
    (r"Per-hound", "Per-specialist"), (r"per-hound", "per-specialist"), (r"Cross-hound", "Cross-specialist"),
    (r"cross-hound", "cross-specialist"), (r"Hound-created", "specialist-created"), (r"<hound>", "<specialist>"),
    (r"Search-Hounds", "Explorer"), (r"Meet-the-Hound", "Meet-the-specialist"),
]
# a "hound" word that is code, not prose: guarded by the character before / after it
_PREV_OK = set(" \t\n>(\"'`…“‘[") | {""}
_NEXT_OK = set(" \t\n<,.;)!?'\"`…”’\\]$") | {""}


def _hound_sub(text):
    out, i = [], 0
    for m in re.finditer(r"\b([Hh]ound)(s?)\b", text):
        a, b = m.start(), m.end()
        prev = text[a - 1] if a else ""
        nxt = text[b] if b < len(text) else ""
        nxt2 = text[b + 1] if b + 1 < len(text) else ""
        if prev not in _PREV_OK:
            continue
        if not (nxt in _NEXT_OK or (nxt == ":" and nxt2 in " \n")):
            continue
        # capital at a sentence / label start, lower case mid-sentence
        before = text[max(0, a - 3):a]
        start = (a == 0 or prev in ">\"'`“‘(" or re.search(r"[.!?:]\s$", before))
        word = ("Specialist" if (m.group(1)[0] == "H" and start) else "specialist") + m.group(2)
        out.append(text[i:a]); out.append(word); i = b
    out.append(text[i:])
    return "".join(out)


def rename(text, html=False):
    amp = "&amp;" if html else "&"
    for pat, rep in PHRASES:
        text = re.sub(pat, rep.replace("&", amp), text)
    for old, new in CODENAMES:
        o = re.escape(old).replace("\\\\u00f6", "\\\\u00f6")
        text = re.sub(r"(?<![\w/.-])" + o + r"(?: Hound)?(?![\w/-])", new.replace("&", amp), text)
    text = _hound_sub(text)
    text = text.replace("🐾 ", "").replace("🐾", "")
    # collapse what the codename swap duplicated: "Exposure Score · Exposure Score", "X (X)"
    text = re.sub(r"\b([A-Z][\w&;›\- ]{2,40}?) · \1\b", r"\1", text)
    text = re.sub(r"\b([A-Z][\w&;›\- ]{2,40}?) \(\1\)", r"\1", text)
    return text


_PROTECT = [r"hounds\.config\.json", r"/web/hounds/[\w./-]*", r"hound_pages[\w./-]*", r"test_hound[\w./-]*", r"hounds_mcp[\w./-]*",
            r"HOUNDS[_-][A-Z_]+", r"[Hh]ounds[A-Z]\w*", r"the-hounds-repo", r"X-Hounds-[\w-]+", r"hounds[:\-_][\w-]+",
            r"MITRE ATLAS", r"ATLAS"]


def rename_protected(text, html=False):
    keep = []

    def _k(m):
        keep.append(m.group(0))
        return "\x00%d\x00" % (len(keep) - 1)
    for p in _PROTECT:
        text = re.sub(p, _k, text)
    text = rename(text, html)
    return re.sub("\x00(\\d+)\x00", lambda m: keep[int(m.group(1))], text)


def rename_json_values(obj):
    if isinstance(obj, dict):
        return {k: rename_json_values(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [rename_json_values(v) for v in obj]
    if isinstance(obj, str):
        return rename_protected(obj)
    return obj


def rename_file(path):
    s = open(path, encoding="utf-8").read()
    if path.endswith(".json"):
        t = json.dumps(rename_json_values(json.loads(s)), indent=1 if "/hound_pages/" in path else 2,
                       ensure_ascii=False) + "\n"
    elif path.endswith(".html"):
        # outside <script>: HTML (& → &amp;); inside: JS strings (raw &)
        parts = re.split(r"(<script\b[^>]*>.*?</script>)", s, flags=re.S)
        t = "".join(rename_protected(p, html=not p.startswith("<script")) for p in parts)
    else:
        t = rename_protected(s)
    if t != s:
        open(path, "w", encoding="utf-8").write(t)
        return True
    return False


if __name__ == "__main__":
    n = sum(1 for p in sys.argv[1:] if rename_file(p))
    print(f"changed {n} of {len(sys.argv) - 1} file(s)")
