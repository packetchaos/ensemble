# Software bill of materials

navi Ensemble ships an SBOM in two standard formats, regenerated on every build:

| File | Format |
|---|---|
| [`sbom/navi-ensemble.cdx.json`](sbom/navi-ensemble.cdx.json) | CycloneDX 1.6 (JSON) — components, dependency graph, **and the external services** the code talks to |
| [`sbom/navi-ensemble.spdx.json`](sbom/navi-ensemble.spdx.json) | SPDX 2.3 (JSON) — the same packages and relationships |

Both validate against the official schemas (`cyclonedx-python-lib` strict JSON validation, `pyspdxtools`).

## What's in it

- **navi Ensemble** — version from `core/version.py`, MIT.
- **The navi CLI (`navi-pro`)** — the one *required* runtime dependency: every Tenable read and write goes through `navi`. Its own dependencies (from navi's `setup.py`) are listed under it. Note: navi's `setup.py` declares GPLv3 while its LICENSE file is MIT; the SBOM records both.
- **Python** 3.10+. The core uses the standard library only (sqlite3, subprocess, urllib, ssl).
- **Optional packages**, scoped as `optional`: FastAPI + Uvicorn or Flask (pick one web server, or use the stdlib one), boto3 (only for AWS Bedrock), certifi (CA bundle when present), fastmcp / mcp (only for the MCP server).
- **Test-only packages**, scoped as `excluded`: Playwright, anyio.
- **Web fonts** (Inter, Space Grotesk, JetBrains Mono — OFL-1.1), loaded by the browser from Google Fonts.
- **No vendored third-party JavaScript or CSS** — every file under `web/` is first-party.
- **External services** (CycloneDX `services`): Tenable (via navi), optional model providers (Anthropic, OpenAI-compatible, Bedrock, Ollama), CISA KEV, NVD, OSV.dev, MITRE CVE Services, endoflife.date, the CTID ATT&CK mappings, and Google Fonts — each with when it's used and what data crosses.

Third-party licenses are the upstream *declared* licenses, not a legal review.

## Declared vs. this install

The committed files record **version ranges** (what the code needs). For an exact inventory of a running install — the versions actually present in its Python — use **Settings ▸ 📦 Software bill of materials ▸ This install**, or:

```
python3 tools/sbom.py --installed --stdout > navi-ensemble-installed.cdx.json
```

## Keeping it current

```
python3 tools/sbom.py           # rewrite both files
python3 tools/sbom.py --check   # exit 1 when they're stale
```

`tests/test_sbom_519.py` fails when the committed SBOM is stale, when a `requirements*.txt` entry is missing, when the code imports a third-party module the SBOM doesn't know (add it to `PACKAGES` in `tools/sbom.py`), or when a page starts loading a remote script or stylesheet.
