"""Build 513 — the page email is a purple ✉ tile that sends the At a glance widget and every chart
as a picture (plus the numbers / tables inline); the IoT pipeline is one compact line.
Run: python3 tests/test_email_513.py"""
import base64
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


P = lambda f: open(os.path.join(ROOT, f), encoding="utf-8").read()
js = P("web/assets/console.js")
check("function hDashVisuals()" in js and "function hDashPictures(title)" in js and "function _hmGlanceComponents()" in js,
      "console.js: the page's visuals (At a glance + charts) are found, pictured and stacked")
check("btn.className='hgear tile hmbtn hmdash'" in js and "/static/icons/email.png" in js and "Email this page via Notify & Report" in js,
      "the page email is a purple icon tile with a hover that says what is sent")
check("payload.pictures=pics" in js and "_HW_REG.push(" in js and "[data-email-visual]" in js,
      "the dashboard send carries the pictures; hWidget charts and marked visuals are included")
check("'\\ud83d\\udce7 Email dashboard'" in js, "(the old text label is only a fallback for non-tile callers)")
check("m.nextElementSibling!==d" in js, "the ✉ tile sits left of Dashboards · Explorer · Settings")
for page, mark in (("agents/certificate/page.html", 'data-email-visual="Expired and failing by month"'),
                   ("agents/eol/page.html", 'data-email-visual="When support ended"'),
                   ("agents/compliance/page.html", 'data-email-visual="Results by status"'),
                   ("agents/compliance/page.html", 'data-email-visual="Framework exposure"'),
                   ("agents/acr/page.html", 'data-email-visual="Where the exposure sits"'),
                   ("agents/insights/page.html", "setAttribute('data-email-visual','')")):
    check(mark in P(page), f"{page.split('/')[1]}: its div-drawn chart is in the email picture")
sla, was, ins = P("agents/sla/page.html"), P("agents/was/page.html"), P("agents/insights/page.html")
check("hMailAuto({noWidgets:true, payload:" in sla and 'id="dashMail"' not in sla and "agentApi('email')" not in sla,
      "SLA Tracker: header ✉ tile with its own numbers")
check("hMailAuto({payload:" in was and 'id="emailBtn"' not in was and "agentApi('email')" not in was,
      "WAS: header ✉ tile replaces the old 📧 Email form")
check("hMailAuto({noWidgets:true, payload:" in ins, "Ensemble Report: header ✉ tile")
check(js.index("mountAgentHeader") > 0 and sla.index("hMailAuto(") > sla.index("mountAgentHeader("),
      "SLA mounts the tile after its header is built")

iot = P("agents/iot_squad/page.html")
check('<div class="pipe" id="pipeline"' in iot and "class=\"pstep" in iot and '<div class="agent">' not in iot,
      "IoT Discovery: the pipeline is one compact line (step · status · count), not four cards")

# server: pictures ride as one attachment (PNG) or a zip
from agents.email import api  # noqa: E402
png = b"\x89PNG\r\n\x1a\n" + b"0" * 32
uri = "data:image/png;base64," + base64.b64encode(png).decode()
pics, err = api._dash_pictures([{"name": "SLA Tracker.png", "png": uri}], "SLA")
check(not err and pics == [("SLA-Tracker.png", png)], "one picture → one PNG attachment")
pics, err = api._dash_pictures([{"name": "a.png", "png": uri}, {"name": "a.png", "png": uri}], "x")
check(not err and len(pics) == 2 and pics[0][0] != pics[1][0], "several pictures keep distinct names (zipped)")
_p, err = api._dash_pictures([{"png": "data:image/png;base64," + base64.b64encode(b"GIF89a").decode()}], "x")
check(bool(err), "a non-PNG picture is refused")
_p, err = api._dash_pictures("nope", "x")
check(bool(err), "pictures must be a list")
from core import navi_cli  # noqa: E402
navi_cli.email_enabled = lambda: False        # whatever this machine's email setting is
body, st = api.dashboard({"to": "a@b.com", "confirm": True, "pictures": [{"png": uri}], "components": []})
check(st == 200 and body.get("blocked"), "the send stays double-gated (email off → blocked)")
calls = []
navi_cli.email_enabled = lambda: True
navi_cli.mail = lambda **k: (calls.append((k, open(k["file"], "rb").read() if k.get("file") else b"",
                                           open(k["html"], encoding="utf-8").read())) or {"ok": True})
body, st = api.dashboard({"to": "a@b.com", "confirm": True, "title": "SLA Tracker", "visuals": "the At a glance widget + 5 charts",
                          "pictures": [{"name": "sla-1.png", "png": uri}, {"name": "sla-2.png", "png": uri}],
                          "components": [{"title": "t", "viz": "kpi", "columns": ["a"], "rows": [{"a": 1}]}]})
k, blob, html = calls[-1]
check(body["ok"] and body["attached"].endswith(".zip") and body["pictures"] == 2, "two pictures → a .zip attachment")
import io  # noqa: E402
check(sorted(zipfile.ZipFile(io.BytesIO(blob)).namelist()) == ["sla-1.png", "sla-2.png"], "the zip holds every picture")
check("The At a glance widget + 5 charts" in html and "SLA Tracker" in html, "the body says what the picture shows")
body, st = api.dashboard({"to": "a@b.com", "confirm": True, "pictures": [{"png": uri}], "components": []})
check(body["ok"] and body["attached"].endswith(".png"), "pictures alone (no tables) still send — as the PNG")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
