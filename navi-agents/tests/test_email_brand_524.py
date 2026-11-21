"""Build 524 — the emails Notify & Report sends are branded navi Ensemble, not "The Hounds".

The 490 rename swept the pages; the email header still read "🐾 The Hounds", the Automation
Station mails still said "AI Contract", and a specialist hand-off was signed with a bare codename
("Laelaps"). Every message builder is rendered here (subject, HTML and text) and checked against
the same retired-term list as tests/test_brand_rename.py.
Run: python3 tests/test_email_brand_524.py"""
import os
import re
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="mail524_")
DB = os.path.join(TMP, "navi.db")
os.environ.update({"HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_DB_PATH": DB,
                   "NAVI_CACHE_DIR": os.path.join(TMP, "c"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db"),
                   "NAVI_CWD": TMP})
for k in ("NAVI_ALLOW_WRITES", "NAVI_EMAIL"):
    os.environ.pop(k, None)
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT);
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, state TEXT, xrefs TEXT);
INSERT INTO assets VALUES ('a1','web','10.0.0.1','9');
INSERT INTO tags VALUES ('a1','CISA KEV','Due');
INSERT INTO vulns VALUES ('a1','12345','Bad thing','critical','open','CISA-KNOWN-EXPLOITED:2024-01-01');
""")
c.commit()
c.close()
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import brand  # noqa: E402
from agents.email import api  # noqa: E402

RETIRED = [r"\bhounds?\b", r"Release the Hounds", r"\bthe pack\b", r"On the Scent", r"AI Contract", "🐾",
           r"\bGabriel\b", r"\bSphinx\b", r"\bAtlas\b", r"Alert Raven", r"\bCovenant\b"]


def retired_in(txt):
    return [p for p in RETIRED if re.search(p, txt or "", re.I)]


msgs = {}
msgs["wrap"] = {"subject": "s", "body_html": api._html_wrap("A subject", "<p>x</p>"), "body_text": api._SIGN}
msgs["kev"] = api._kev_message("example.com", "sec@example.com")
msgs["contract_plan"] = api._contract_message("contract_plan", "x@example.com", {"title": "t", "body": "b"})
msgs["contract_summary"] = api._contract_summary_message({"armed": True, "tags": []}, "x@example.com")
msgs["handoff"] = api._findings_message({"source_agent": "cisakev", "asset_uuids": ["a1"], "finding_ids": ["12345"]},
                                        "technical", "example.com", "x@example.com")
for name, m in msgs.items():
    blob = " ".join(str(m.get(k) or "") for k in ("subject", "body_html", "body_text", "owner"))
    check(not retired_in(blob), "%s email has no retired brand terms %s" % (name, retired_in(blob)))
check(brand.BRAND in msgs["wrap"]["body_html"] and "uppercase" not in msgs["wrap"]["body_html"].split(brand.BRAND)[0][-200:],
      "the email header reads '%s' as written" % brand.BRAND)
check(brand.ORCHESTRATOR in msgs["contract_plan"]["subject"] and brand.ORCHESTRATOR in msgs["contract_summary"]["subject"],
      "Automation Station mails are named %s" % brand.ORCHESTRATOR)
check(msgs["handoff"]["owner"] == brand.display("cisakev") and brand.display("cisakev") in msgs["handoff"]["body_text"],
      "a hand-off names the specialist as its page does (%s)" % msgs["handoff"]["owner"])
check(all(api._AGENT_HOUND[a] == brand.display(a) for a in brand.ROSTER), "every agent's email name comes from core.brand")
src = open(os.path.join(ROOT, "agents/email/api.py"), encoding="utf-8").read()
check("The Hounds" not in src and "\\U0001F43E" not in src, "no hard-coded old brand left in the email builder")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
