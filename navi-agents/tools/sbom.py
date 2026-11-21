#!/usr/bin/env python3
"""Software Bill of Materials for navi Ensemble — CycloneDX 1.6 and SPDX 2.3 (JSON).

    python3 tools/sbom.py            # rewrite sbom/navi-ensemble.cdx.json + .spdx.json (declared ranges)
    python3 tools/sbom.py --check    # exit 1 if the committed SBOM is stale (what the test runs)
    python3 tools/sbom.py --installed --stdout   # this install: the versions actually present

Stdlib only. What goes in, and where it comes from (so it can't drift silently):
  * navi Ensemble itself — name, version (core/version.py), license (LICENSE), repo (below).
  * Python packages — requirements.txt / requirements-mcp.txt (declared ranges), plus the
    optional / test-only imports listed in PACKAGES. tests/test_sbom_519.py fails when the code
    imports a third-party module this table doesn't know, or a requirement isn't in the SBOM.
  * The navi CLI (navi-pro) — the one REQUIRED runtime dependency: the Ensemble shells out to it.
    Its own dependencies (navi's setup.py) are listed under it.
  * Web fonts loaded by the browser from Google Fonts (console.css).
  * External services the code calls (CycloneDX `services`), with what data crosses.
There are no vendored third-party JavaScript or CSS libraries: every file under web/ is first-party.

Licenses for third-party packages are the upstream DECLARED licenses, not a legal review.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT_DIR = os.path.join(ROOT, "sbom")
CDX_PATH = os.path.join(OUT_DIR, "navi-ensemble.cdx.json")
SPDX_PATH = os.path.join(OUT_DIR, "navi-ensemble.spdx.json")
REPO = "https://github.com/packetchaos/ensemble"
SUPPLIER = "Casey Reid (packetchaos)"
NS = uuid.UUID("6f1b6a52-3d7e-4f0e-9a3c-5e0b8c1d2a77")          # fixed namespace → reproducible ids

# ── Python packages: pypi name → facts. `scope`: required | optional | excluded (test / dev only).
#    `why` is shown in the SBOM; `imports` are the module names the code uses (for the test).
PACKAGES = {
    "fastapi": {"license": "MIT", "scope": "optional", "imports": ["fastapi"],
                "why": "web server option (app_fastapi.py) — run one of FastAPI, Flask or the stdlib server"},
    "uvicorn": {"license": "BSD-3-Clause", "scope": "optional", "imports": ["uvicorn"], "extras": "standard",
                "why": "ASGI server for the FastAPI option"},
    "starlette": {"license": "BSD-3-Clause", "scope": "optional", "imports": ["starlette"], "via": "fastapi",
                  "why": "FastAPI's foundation (imported directly by app_fastapi.py)"},
    "flask": {"license": "BSD-3-Clause", "scope": "optional", "imports": ["flask"],
              "why": "web server option (app_flask.py)"},
    "werkzeug": {"license": "BSD-3-Clause", "scope": "optional", "imports": ["werkzeug"], "via": "flask",
                 "why": "Flask's WSGI toolkit (imported directly by app_flask.py)"},
    "boto3": {"license": "Apache-2.0", "scope": "optional", "imports": ["boto3"], "range": ">=1.34",
              "why": "only when NAVI_LLM_PROVIDER=bedrock (AWS credentials + SigV4)"},
    "certifi": {"license": "MPL-2.0", "scope": "optional", "imports": ["certifi"],
                "why": "CA bundle for model-provider TLS when present; falls back to the system store"},
    "fastmcp": {"license": "Apache-2.0", "scope": "optional", "imports": ["fastmcp"],
                "why": "the optional MCP server (hounds_mcp.py)"},
    "mcp": {"license": "MIT", "scope": "optional", "imports": ["mcp"],
            "why": "alternative to fastmcp for hounds_mcp.py (the official SDK ships FastMCP)"},
    "anyio": {"license": "MIT", "scope": "excluded", "imports": ["anyio"],
              "why": "MCP self-test only (hounds_mcp_selftest.py)"},
    "playwright": {"license": "Apache-2.0", "scope": "excluded", "imports": ["playwright"],
                   "why": "browser tests only"},
}
# The navi CLI and ITS declared dependencies (navi setup.py). Required: the Ensemble runs `navi …`.
NAVI = {"name": "navi-pro", "range": ">=8.8", "repo": "https://github.com/packetchaos/Navi",
        # navi's setup.py declares GPLv3 (license="GNUv3" + the GPLv3 classifier) while its LICENSE file is MIT.
        "licenses": [("GPL-3.0-only", "declared in setup.py (license + classifier)"), ("MIT", "LICENSE file")],
        "deps": [("click", ">=7.0", "BSD-3-Clause"), ("restfly", "<=1.5.1", "MIT"), ("requests", ">=2.31", "Apache-2.0"),
                 ("flask", ">=2.3.2", "BSD-3-Clause"), ("IPy", ">=1.0", "BSD-3-Clause"),
                 ("pytenable", ">=1.4.3", "MIT"), ("arrow", ">=0.17.0", "Apache-2.0"), ("boto3", ">=1.17.48", "Apache-2.0"),
                 ("pexpect", ">=4.8.0", "ISC"), ("typing-extensions", ">=4.0.1", "PSF-2.0"),
                 ("pandas", ">=1.1.5", "BSD-3-Clause"), ("numpy", ">=1.19.5", "BSD-3-Clause"), ("xlrd", ">=2.0.1", "BSD-3-Clause")]}
FONTS = [("Inter", "https://fonts.google.com/specimen/Inter"),
         ("Space Grotesk", "https://fonts.google.com/specimen/Space+Grotesk"),
         ("JetBrains Mono", "https://fonts.google.com/specimen/JetBrains+Mono")]
# External services the CODE contacts — (name, endpoints, when, data that crosses, authenticated, used by)
SERVICES = [
    ("Tenable Vulnerability Management / Tenable One API", ["https://cloud.tenable.com"],
     "always — every Tenable read and write goes through the navi CLI with its own API keys",
     "asset, finding, tag, scan and ACR data both ways (writes only through the write gates)", True, "navi CLI"),
    ("Anthropic API", ["https://api.anthropic.com"], "optional — when an AI provider is configured (BYO_MODEL.md)",
     "prompts built from navi.db findings / asset facts go out; text comes back", True, "core/llm.py"),
    ("OpenAI-compatible endpoint", ["https://api.openai.com/v1"], "optional — NAVI_LLM_PROVIDER=openai or a custom base URL",
     "same as above", True, "core/llm.py"),
    ("AWS Bedrock", ["https://bedrock-runtime.us-east-1.amazonaws.com"], "optional — NAVI_LLM_PROVIDER=bedrock (endpoint follows the configured AWS region; us-east-1 shown)",
     "same as above", True, "core/llm.py"),
    ("Ollama (local model)", ["http://localhost:11434"], "optional — OLLAMA_HOST / NAVI_LLM_PROVIDER=ollama",
     "same as above, to a local or self-hosted model", False, "core/llm.py"),
    ("CISA Known Exploited Vulnerabilities feed", ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                                                   "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"],
     "CISA KEV refresh", "public catalog downloaded; nothing sent", False, "core/kev.py"),
    ("NVD CVE API 2.0", ["https://services.nvd.nist.gov/rest/json/cves/2.0"], "advisory lookups",
     "CVE ids go out; public advisory data comes back", False, "core/advisory.py"),
    ("OSV.dev", ["https://api.osv.dev/v1/vulns/"], "advisory lookups", "CVE / advisory ids go out", False, "core/advisory.py"),
    ("MITRE CVE Services", ["https://cveawg.mitre.org/api/cve/"], "advisory lookups", "CVE ids go out", False, "core/advisory.py"),
    ("endoflife.date", ["https://endoflife.date/api/all.json"], "Software / End of Life lifecycle data",
     "public lifecycle catalog downloaded; nothing sent", False, "core/software.py, core/software_eol.py"),
    ("CTID Mappings Explorer (ATT&CK)", ["https://raw.githubusercontent.com/center-for-threat-informed-defense/"],
     "MITRE ATT&CK mapping refresh", "public mapping data downloaded; nothing sent", False, "core/mitre.py"),
    ("Google Fonts", ["https://fonts.googleapis.com", "https://fonts.gstatic.com"], "every page load — by the BROWSER",
     "the viewer's IP / user agent reach Google; no app data", False, "web/assets/console.css"),
]


def _version():
    from core import version
    return version.version_string()


def _license_id(path):
    try:
        head = open(path, encoding="utf-8").read(200)
    except OSError:
        return None
    return "MIT" if head.startswith("MIT License") else None


def _requirements():
    """{pypi name lower: (range, file, extras)} from requirements*.txt."""
    out = {}
    for fn in ("requirements.txt", "requirements-mcp.txt"):
        try:
            lines = open(os.path.join(ROOT, fn), encoding="utf-8").read().splitlines()
        except OSError:
            continue
        for ln in lines:
            ln = ln.split("#", 1)[0].strip()
            m = re.match(r"^([A-Za-z0-9_.-]+)(\[[^\]]+\])?\s*(.*)$", ln)
            if m:
                out[m.group(1).lower()] = (m.group(3).strip() or "", fn, (m.group(2) or "").strip("[]"))
    return out


def _installed(name):
    try:
        from importlib import metadata
        return metadata.version(name)
    except Exception:
        return None


def _purl(name, version=None):
    return "pkg:pypi/%s%s" % (name.lower().replace("_", "-"), ("@" + version) if version else "")


def _ref(name):
    return "pypi:" + name.lower()


def components(installed=False):
    req = _requirements()
    comps, deps = [], {}
    # navi CLI + its dependencies
    nv = _installed(NAVI["name"]) if installed else None
    navi_c = {"type": "application", "bom-ref": _ref(NAVI["name"]), "name": NAVI["name"],
              "description": "navi — the Tenable CLI the Ensemble drives for every Tenable read and write (`navi …`)",
              "scope": "required", "purl": _purl(NAVI["name"], nv),
              "licenses": [{"license": {"id": lid, "acknowledgement": "declared"}} for lid, _src in NAVI["licenses"]],
              "externalReferences": [{"type": "vcs", "url": NAVI["repo"]}],
              "properties": [{"name": "ensemble:requires", "value": NAVI["range"]},
                             {"name": "ensemble:license-note",
                              "value": "navi's setup.py declares GPLv3 (license='GNUv3' and the GPLv3 classifier) "
                                       "but its LICENSE file is MIT — the two disagree"}]}
    if nv:
        navi_c["version"] = nv
    comps.append(navi_c)
    deps[_ref(NAVI["name"])] = []
    for name, rng, lic in NAVI["deps"]:
        ref = "navi-dep:" + name.lower()
        c = {"type": "library", "bom-ref": ref, "name": name, "scope": "required", "purl": _purl(name, _installed(name) if installed else None),
             "licenses": [{"license": {"id": lic, "acknowledgement": "declared"}}],
             "properties": [{"name": "ensemble:requires", "value": rng}, {"name": "ensemble:via", "value": NAVI["name"]}]}
        if installed and _installed(name):
            c["version"] = _installed(name)
        comps.append(c)
        deps[_ref(NAVI["name"])].append(ref)
    # the Ensemble's own Python packages
    for name, f in PACKAGES.items():
        r = req.get(name.lower())
        rng = (r[0] if r else "") or f.get("range") or ""
        v = _installed(name) if installed else None
        c = {"type": "library", "bom-ref": _ref(name), "name": name, "scope": f["scope"], "purl": _purl(name, v),
             "description": f["why"], "licenses": [{"license": {"id": f["license"], "acknowledgement": "declared"}}],
             "properties": [{"name": "ensemble:requires", "value": rng or "unpinned"},
                            {"name": "ensemble:declared-in", "value": r[1] if r else ("pulled in by " + f["via"] if f.get("via")
                                                                                      else "imported when present (not in requirements)")}]}
        if f.get("extras") or (r and r[2]):
            c["properties"].append({"name": "ensemble:extras", "value": f.get("extras") or r[2]})
        if v:
            c["version"] = v
        comps.append(c)
    # platform + fonts
    comps.append({"type": "platform", "bom-ref": "platform:cpython", "name": "CPython", "scope": "required",
                  "description": "Python 3.10+ — the core runs on the standard library only (sqlite3, subprocess, urllib, ssl)",
                  "licenses": [{"license": {"id": "PSF-2.0", "acknowledgement": "declared"}}],
                  "properties": [{"name": "ensemble:requires", "value": ">=3.10"}]
                  + ([{"name": "ensemble:installed", "value": sys.version.split()[0]}] if installed else [])})
    for name, url in FONTS:
        comps.append({"type": "data", "bom-ref": "font:" + name.lower().replace(" ", "-"), "name": name + " (web font)",
                      "scope": "required", "description": "loaded by the browser from Google Fonts (console.css); the UI falls back to system fonts",
                      "licenses": [{"license": {"id": "OFL-1.1", "acknowledgement": "declared"}}],
                      "externalReferences": [{"type": "website", "url": url}]})
    return comps, deps


def services():
    out = []
    for name, eps, when, data, auth, by in SERVICES:
        out.append({"bom-ref": "svc:" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-"), "name": name,
                    "endpoints": eps, "authenticated": auth, "x-trust-boundary": True,
                    "description": when, "data": [{"flow": "bi-directional", "classification": data}],
                    "properties": [{"name": "ensemble:used-by", "value": by}]})
    return out


def cyclonedx(installed=False, now=None):
    ver = _version()
    comps, navi_deps = components(installed)
    lic = _license_id(os.path.join(ROOT, "LICENSE")) or "MIT"
    main = {"type": "application", "bom-ref": "navi-ensemble", "name": "navi Ensemble", "version": ver,
            "description": "Local web console of exposure-management specialists over navi.db (Tenable VM / Tenable One)",
            "supplier": {"name": SUPPLIER}, "licenses": [{"license": {"id": lic}}],
            "purl": "pkg:github/packetchaos/ensemble@" + ver,
            "externalReferences": [{"type": "vcs", "url": REPO}]}
    dep_refs = [c["bom-ref"] for c in comps if c["bom-ref"].startswith(("pypi:", "platform:", "font:"))
                and c["bom-ref"] != _ref(NAVI["name"])]
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(NS, "cdx|%s|%s" % (ver, "installed" if installed else "declared"))),
        "version": 1,
        "metadata": {"timestamp": now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "tools": {"components": [{"type": "application", "name": "tools/sbom.py", "version": ver}]},
                     "component": main,
                     "properties": [{"name": "ensemble:sbom-kind",
                                     "value": "installed (versions present in this Python)" if installed
                                     else "declared (version ranges from requirements and navi's setup.py)"},
                                    {"name": "ensemble:vendored-js", "value": "none — all web assets are first-party"}]},
        "components": comps,
        "services": services(),
        "dependencies": [{"ref": "navi-ensemble", "dependsOn": [_ref(NAVI["name"])] + dep_refs},
                         {"ref": _ref(NAVI["name"]), "dependsOn": navi_deps[_ref(NAVI["name"])]},
                         {"ref": _ref("fastapi"), "dependsOn": [_ref("starlette")]},
                         {"ref": _ref("flask"), "dependsOn": [_ref("werkzeug")]}],
    }


def spdx(cdx):
    """SPDX 2.3 view of the same components (packages + relationships)."""
    m = cdx["metadata"]["component"]
    sid = lambda ref: "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]+", "-", ref)
    pk = [{"SPDXID": sid(m["bom-ref"]), "name": m["name"], "versionInfo": m["version"], "supplier": "Person: " + SUPPLIER,
           "downloadLocation": REPO, "filesAnalyzed": False, "licenseDeclared": m["licenses"][0]["license"]["id"],
           "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION", "primaryPackagePurpose": "APPLICATION",
           "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": m["purl"]}]}]
    rel = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": sid(m["bom-ref"])}]
    by_ref = {c["bom-ref"]: c for c in cdx["components"]}
    for c in cdx["components"]:
        ids = [x["license"]["id"] for x in c.get("licenses") or []]
        p = {"SPDXID": sid(c["bom-ref"]), "name": c["name"], "versionInfo": c.get("version") or next(
                (x["value"] for x in c.get("properties") or [] if x["name"] == "ensemble:requires"), "NOASSERTION"),
             "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
             "licenseDeclared": (" OR ".join(ids) if len(ids) > 1 else (ids[0] if ids else "NOASSERTION")),
             "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION",
             "primaryPackagePurpose": {"application": "APPLICATION", "library": "LIBRARY", "platform": "OPERATING-SYSTEM",
                                       "data": "OTHER"}.get(c["type"], "OTHER")}
        if c.get("description"):
            p["comment"] = c["description"] + (" (scope: %s)" % c.get("scope") if c.get("scope") else "")
        if c.get("purl"):
            p["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c["purl"]}]
        pk.append(p)
    for d in cdx["dependencies"]:
        for t in d["dependsOn"]:
            scope = (by_ref.get(t) or {}).get("scope")
            rt = {"optional": "OPTIONAL_DEPENDENCY_OF", "excluded": "TEST_DEPENDENCY_OF"}.get(scope, "DEPENDENCY_OF")
            rel.append({"spdxElementId": sid(t), "relationshipType": rt, "relatedSpdxElement": sid(d["ref"])})
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "navi Ensemble %s SBOM" % m["version"],
            "documentNamespace": "%s/sbom/%s/%s" % (REPO, m["version"], cdx["serialNumber"].split(":")[-1]),
            "creationInfo": {"created": cdx["metadata"]["timestamp"], "creators": ["Tool: tools/sbom.py-" + m["version"],
                                                                                   "Person: " + SUPPLIER]},
            "packages": pk, "relationships": rel,
            "comment": "External services the Ensemble contacts are listed in the CycloneDX file (services)."}


def _stable(doc):
    """The document minus its timestamp — what --check compares."""
    d = json.loads(json.dumps(doc))
    if "metadata" in d:
        d["metadata"].pop("timestamp", None)
    if "creationInfo" in d:
        d["creationInfo"].pop("created", None)
    return d


def dumps(doc):
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 when the committed SBOM is stale")
    ap.add_argument("--installed", action="store_true", help="record the versions installed in this Python")
    ap.add_argument("--stdout", action="store_true", help="print CycloneDX to stdout instead of writing files")
    a = ap.parse_args(argv)
    cdx = cyclonedx(installed=a.installed)
    sp = spdx(cdx)
    if a.stdout:
        sys.stdout.write(dumps(cdx))
        return 0
    if a.check:
        stale = []
        for path, doc in ((CDX_PATH, cdx), (SPDX_PATH, sp)):
            try:
                cur = json.load(open(path, encoding="utf-8"))
            except (OSError, ValueError):
                stale.append(path)
                continue
            if _stable(cur) != _stable(doc):
                stale.append(path)
        for p in stale:
            print("stale: %s — run python3 tools/sbom.py" % os.path.relpath(p, ROOT))
        return 1 if stale else 0
    os.makedirs(OUT_DIR, exist_ok=True)
    for path, doc in ((CDX_PATH, cdx), (SPDX_PATH, sp)):
        with open(path, "w", encoding="utf-8") as f:
            f.write(dumps(doc))
        print("wrote %s (%s)" % (os.path.relpath(path, ROOT), hashlib.sha256(dumps(doc).encode()).hexdigest()[:12]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
