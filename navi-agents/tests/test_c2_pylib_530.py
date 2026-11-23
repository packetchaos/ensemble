#!/usr/bin/env python3
"""Build 530 — Remote Remediation plans a PYTHON LIBRARY finding as a pip upgrade, never an OS package.

The real case (plugin 200807, CentOS 8): "urllib3 Python Library < 1.26.19, < 2.2.2" with plugin output
  Path : /usr/local/lib/python3.11/site-packages/urllib3-2.1.0-py3.11.egg/EGG-INFO/PKG-INFO
  Installed version : 2.1.0 · Fixed version : 2.2.2 · Potential Vulnerability : Component
was planned as `sudo dnf -y upgrade 'python3'` (the word "Python" matched the python3 hint) with an rpm precheck and
"Fixed version: not found". Now: the library, its interpreter (/usr/local/bin/python3.11), a version-compared pip plan
on the installed major line, a narrow pip allow-list, refusals for system / --user Pythons, and ⑧ Verify hands the
changed hosts + the plugin to Scan Confirmation for a remediation scan.
Run: python3 tests/test_c2_pylib_530.py"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="pylib530_")
os.environ.update({"HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_DB_PATH": os.path.join(TMP, "navi.db"),
                   "NAVI_CACHE_DIR": os.path.join(TMP, "c"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db"),
                   "NAVI_CWD": TMP})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import c2_remediate as R  # noqa: E402

OUT = """
  Path                     : /usr/local/lib/python3.11/site-packages/urllib3-2.1.0-py3.11.egg/EGG-INFO/PKG-INFO
  Installed version        : 2.1.0
  Fixed version            : 2.2.2
  Potential Vulnerability  : Component
"""
PLUG = {"plugin_id": "200807", "plugin_name": "urllib3 Python Library < 1.26.19, < 2.2.2 (CVE-2024-37891)",
        "solution": "Upgrade to urllib3 version 1.26.19, 2.2.2 or later."}


def src_of(out, plug=PLUG, fam="dnf", ip="192.168.128.68"):
    return {"plugins": [plug], "hosts": [{"ip": ip, "os": "CentOS Linux 8", "family": fam, "outputs": {plug["plugin_id"]: out}}],
            "families": [fam], "plugin_ids": [plug["plugin_id"]]}


SRC = src_of(OUT)
m = R.plan_meta(SRC, "dnf")
L = m["library"] or {}
check(L.get("name") == "urllib3" and L.get("interpreter") == "/usr/local/bin/python3.11" and L.get("managed") == "pip",
      "the finding is the pip library urllib3 owned by /usr/local/bin/python3.11 (%s)" % {k: L.get(k) for k in ("name", "interpreter", "managed")})
check(m["packages"] == [] and m["compare"] == "pep440", "…no OS package in scope; versions compare as PEP 440")
check(R.guess_package(SRC) == "", "the package guess is no longer python3")
check(any("egg" in w for w in m["warnings"]), "an egg install is called out (pip installs beside it)")

g = R.generate(SRC, "dnf", use_llm=False)
p = g["plan"]
st = p["steps"][0] if p["steps"] else {}
check(len(p["steps"]) == 1 and st["command"] == "sudo /usr/local/bin/python3.11 -m pip install --upgrade --no-input "
      "--disable-pip-version-check 'urllib3>=2.2.2,<3'", "the step: pip upgrade with THAT interpreter, ≥ fixed, same major (%s)"
      % st.get("command"))
check("dnf" not in st.get("command", "") and "python3'" not in st.get("command", ""), "no dnf, no python3 package")
check(p["precheck"]["command"] == "/usr/local/bin/python3.11 -m pip show urllib3" and p["precheck"]["compare"] == "pep440"
      and p["precheck"]["want"] == "older" and p["precheck"]["fixed_version"] == "2.2.2", "precheck: pip show, affected while < 2.2.2")
check(st["verify"]["want"] == "at_least" and p["post_verify"]["fixed_version"] == "2.2.2", "verify / post-verify: ≥ 2.2.2 (a real compare)")
check(st["rollback"].endswith("'urllib3==2.1.0'"), "rollback re-pins the installed 2.1.0")
v = R.validate(p, SRC)
check(v["deployable"] and not v["rejected"], "the plan validates and is deployable (%s)" % v["rejected"])
check(not any("MANUAL" in w for w in v["warnings"]), "verification is not 'manual' any more")

# reading pip show
ps_old, ps_new = "Name: urllib3\nVersion: 2.1.0\nSummary: HTTP library\n", "Name: urllib3\nVersion: 2.2.3\nLocation: /x\n"
check(R.read_version(ps_old, p["precheck"]) == "2.1.0", "the version is read from pip show's Version: line")
check(R.version_ok(ps_old, p["precheck"]) and not R.version_ok(ps_new, p["precheck"]), "precheck: 2.1.0 affected, 2.2.3 not")
check(R.version_ok(ps_new, p["post_verify"]) and not R.version_ok(ps_old, p["post_verify"]), "verify: 2.2.3 passes, 2.1.0 fails")
for a, b, want in (("2.10", "2.9", 1), ("2.0rc1", "2.0", -1), ("2.0", "2.0.post1", -1), ("2.2.2", "2.2.2.0", 0), ("1.0.dev1", "1.0a1", -1)):
    check(R.pep_cmp(a, b) == want, "PEP 440: %s vs %s = %d" % (a, b, want))
check(R.pick_fixed("2.1.0", "1.26.19, 2.2.2") == "2.2.2" and R.pick_fixed("1.26.5", "1.26.19, 2.2.2") == "1.26.19",
      "two fixed versions: the one on the installed major line")
two = src_of(OUT.replace("Fixed version            : 2.2.2", "Fixed version            : 1.26.19, 2.2.2"))
check((R.plan_meta(two, "dnf")["library"] or {}).get("fixed") == "2.2.2", "…also when the output lists both")

# the pip allow-list
aff = R.affected(SRC)
bad = {
    "sudo /usr/bin/python3 -m pip install --upgrade 'urllib3>=2.2.2,<3'": "another interpreter",
    "sudo /usr/local/bin/python3.11 -m pip install --upgrade 'requests>=2'": "another library",
    "sudo /usr/local/bin/python3.11 -m pip install --upgrade 'urllib3>=2.0'": "below the fixed version",
    "sudo /usr/local/bin/python3.11 -m pip install --upgrade urllib3": "unbounded",
    "sudo /usr/local/bin/python3.11 -m pip install --upgrade --index-url=x 'urllib3>=2.2.2'": "an index URL",
    "sudo /usr/local/bin/python3.11 -m pip install --upgrade -i https://evil 'urllib3>=2.2.2'": "a download URL",
    "sudo /usr/local/bin/python3.11 -m pip install --upgrade --break-system-packages 'urllib3>=2.2.2'": "--break-system-packages",
    "sudo /usr/local/bin/python3.11 -m pip install --upgrade --user 'urllib3>=2.2.2'": "--user",
    "sudo /usr/local/bin/python3.11 -m pip install --upgrade 'urllib3>=2.2.2' ./evil.whl": "a second requirement",
    "/usr/local/bin/python3.11 -m pip uninstall -y urllib3": "uninstall",
    "sudo dnf -y upgrade python3": "the python3 OS package",
}
for c, why in bad.items():
    check(R.check_command(c, "step", aff) != [], "refused: " + why)
check(R.check_command("sudo /usr/local/bin/python3.11 -m pip install 'urllib3==2.0.0'", "step", aff, rollback=True) != [],
      "refused: a rollback to another version")
check(R.check_command("/usr/local/bin/python3.11 -m pip download urllib3", "read", aff) != [], "refused: pip download as a check")
check(R.check_command("/usr/local/bin/python3.11 -m pip show urllib3", "read", aff) == [] and
      R.check_command("/usr/local/bin/python3.11 -m pip check", "read", aff) == [], "allowed checks: pip show <lib> / pip check")
check(R.check_command("/usr/local/bin/python3.11 -m pip show urllib3", "read", R.affected(src_of("Path : /etc/x\n"))) != [],
      "pip is refused for a finding that is not a Python library")
check(R.resolve_rollback(st["rollback"], aff) == (st["rollback"], ""), "per-host rollback re-pins this host's installed version")

# who owns the directory
venv = src_of(OUT.replace("/usr/local/lib/python3.11", "/opt/app/venv/lib/python3.11"))
vl = R.plan_meta(venv, "dnf")["library"]
check(vl["interpreter"] == "/opt/app/venv/bin/python3.11" and any("application user" in w for w in R.plan_meta(venv, "dnf")["warnings"]),
      "a virtualenv: its own interpreter, and a note to run as the app user")
for path, kind in (("/usr/lib/python3.6/site-packages/urllib3/__init__.py", "os"),
                   ("/usr/lib64/python3.6/site-packages/urllib3-1.24.2.dist-info/METADATA", "os"),
                   ("/usr/lib/python3/dist-packages/urllib3/__init__.py", "os"),
                   ("/home/alice/.local/lib/python3.11/site-packages/urllib3/__init__.py", "user")):
    s2 = src_of(OUT.replace("/usr/local/lib/python3.11/site-packages/urllib3-2.1.0-py3.11.egg/EGG-INFO/PKG-INFO", path))
    lib = R.plan_meta(s2, "dnf")["library"] or {}
    pl = R.generate(s2, "dnf", use_llm=False)
    check(lib.get("managed") == kind and pl["plan"]["steps"] == [] and pl.get("refused") == "not_pip_managed",
          "%s → %s-managed: no pip plan (%s)" % (path.split("/site-packages")[0].split("/dist-packages")[0], kind, lib.get("managed")))
nolib = src_of(OUT, plug=dict(PLUG, plugin_name="Some Component < 2.2.2", solution="Upgrade."))
check(R.plan_meta(nolib, "dnf")["library"] is None, "a library the plugin TEXT doesn't name is never planned from the output alone")
check(R.guess_package({"text": "urllib3 Python Library < 2.2.2"}) != "python3", "plugin text alone never maps 'Python Library' to python3")

# a model's plan gets the same version compare on its pip show checks
llm_plan = R.normalize({"steps": [{"command": "sudo /usr/local/bin/python3.11 -m pip install --upgrade --no-input "
                                              "--disable-pip-version-check 'urllib3>=2.2.2,<3'",
                                   "verify": {"command": "/usr/local/bin/python3.11 -m pip show urllib3"}}],
                        "precheck": {"command": "/usr/local/bin/python3.11 -m pip show urllib3"}, "generator": "llm"})
R.attach_library_checks(llm_plan, L)
check(llm_plan["precheck"].get("want") == "older" and llm_plan["steps"][0]["verify"].get("compare") == "pep440",
      "an AI plan's pip show checks are version-compared too")
check("site-packages" in R.SYSTEM and "never upgrade python3" in R.SYSTEM, "the AI is told: site-packages → pip, never python3")

# a run on a fake host: before 2.1.0 → after 2.2.3 = Fixed; still 2.1.0 (the egg still loads) = verify failed; absent = not installed
from core import navi_cli  # noqa: E402
from agents.c2 import api as C2  # noqa: E402
state = {}


def fake_push(target="", command="", **kw):
    if " -m pip show " in command:
        if state.get("absent"):
            return {"status": "failed", "exit_code": 1, "output": "C2_OUT\nWARNING: Package(s) not found: urllib3\n"}
        return {"status": "ok", "exit_code": 0, "output": "C2_OUT\nName: urllib3\nVersion: %s\nSummary: x\n" % state["ver"]}
    if " -m pip install " in command:
        state["ran"] = command
        if not state.get("egg_shadow"):
            state["ver"] = "2.2.3"
        return {"status": "ok", "exit_code": 0, "output": "C2_OUT\nSuccessfully installed urllib3-2.2.3\n"}
    return {"status": "failed", "exit_code": 127, "output": ""}


navi_cli.push = fake_push
meta = R.plan_meta(SRC, "dnf")
state.update(ver="2.1.0")
r = C2._remediate_host(p, "t1", "c2", "sha", meta=meta)("192.168.128.68")
check(r.get("verdict") == "fixed" and r.get("before") == "2.1.0" and r.get("after") == "2.2.3",
      "a run: 2.1.0 → 2.2.3 is Fixed by version compare (%s / %s → %s)" % (r.get("verdict"), r.get("before"), r.get("after")))
check("python3.11 -m pip install --upgrade" in state.get("ran", ""), "…and the command sent was the pip upgrade")
state.clear()
state.update(ver="2.1.0", egg_shadow=True)
r = C2._remediate_host(p, "t2", "c2", "sha", meta=meta)("192.168.128.68")
check(r.get("verdict") == "step_failed" and "verify did not pass" in r.get("message", ""),
      "still 2.1.0 after pip (the egg still loads) is not reported as fixed (%s)" % r.get("verdict"))
state.clear()
state.update(ver="2.2.3")
r = C2._remediate_host(p, "t3", "c2", "sha", meta=meta)("192.168.128.68")
check(r.get("verdict") == "already_fixed" and "ran" not in state, "already ≥ 2.2.2: nothing changed (%s)" % r.get("verdict"))
state.clear()
state.update(ver="2.1.0", absent=True)
r = C2._remediate_host(p, "t4", "c2", "sha", meta=meta)("192.168.128.68")
check(r.get("verdict") == "not_installed" and "ran" not in state, "pip show finds nothing: Not installed (%s)" % r.get("verdict"))

# ⑧ Verify — a remediation scan through Scan Confirmation
pg = open(os.path.join(ROOT, "agents", "c2", "page.html"), encoding="utf-8").read()
sc = open(os.path.join(ROOT, "agents", "scan_confirm", "page.html"), encoding="utf-8").read()
check('id="rescanBtn"' in pg and "/agents/scan_confirm/page.html?" in pg and "plugin_ids" in pg,
      "⑧ Verify offers a remediation scan with the finding's plugin(s) and the changed hosts")
check("location.search" not in pg and "URLSearchParams" not in pg, "…built as an outgoing link; the C2 page still never reads its URL")
check("q.get('ips')" in sc and "Request from" in sc and "Nothing runs until you do" in sc,
      "Scan Confirmation takes the hosts (UUIDs or IPs), says who asked, and runs nothing by itself")
check('id="libBox"' in pg and "not found in the plugin output" not in pg, "the plan view shows the library box; the misleading 'not found' line is gone")
print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
