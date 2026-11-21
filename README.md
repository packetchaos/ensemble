# navi Ensemble

**Specialist AI agents for exposure management, grounded in your Tenable data.**

navi Ensemble is a team of specialists that run over [Tenable **navi**](https://github.com/packetchaos/navi)
(`navi.db` and the Tenable API) and bring their results together in a local console. Each specialist
looks for one kind of exposure, such as exploited vulnerabilities, end-of-life software, weak or expiring
crypto, unowned assets, scan blind spots, shadow AI or IoT and OT devices. It then tags what it finds,
calibrates its risk, or answers a question about it. Every finding comes from a real navi query, and
every write back to Tenable is gated and confirmed by a person.

navi Ensemble grew out of **The Hounds**, the proof-of-concept project. The new name reflects how far it
has matured: server-side caching, an architecture built for very large estates, and a consistent
interface across every specialist.

Version `2.44.521`. The scheme is `MAJOR.<specialists>.<build>`, where the middle number is the count of
specialists the server discovers (43 in this release; see `navi-agents/core/version.py`).

## Quick start

```bash
cd navi-agents
python3 run.py            # auto: FastAPI if installed, else Flask, else the built-in server
python3 run.py stdlib     # force the zero-dependency server (no pip required)
python3 run.py fastapi    # FastAPI (auto-installs if missing)
python3 run.py flask      # Flask  (auto-installs if missing)
```

Run it from `navi-agents/` (the folder that contains `run.py`, `core/` and `app_*.py`), then open the
URL it prints (`http://localhost:8000` by default). On first run it builds a bundled sample database
(`sample_navi.db`) so you can try it with no setup. For production, point `NAVI_DB_PATH` at navi's real
database:

```bash
export NAVI_DB_PATH=/path/to/navi.db
export NAVI_ALLOW_WRITES=0   # keep writes disabled until you're ready
python3 run.py
```

Full setup is in [navi-agents/INSTALL.md](navi-agents/INSTALL.md). The console, every specialist and the
configuration are described in [navi-agents/README.md](navi-agents/README.md).

## How it works

```
Tenable VM / Tenable One ──navi sync──▶ navi.db (local SQLite)
                                           │  read-only SQL and rules
                                           ▼
                        43 specialists ──▶ server-side caches ──▶ console (browser)
                                           │
                       previewed, confirmed writes (tags, ACR) ──▶ back to Tenable via navi
```

- **Deterministic findings.** Specialists detect exposure with SQL and rules over `navi.db`. The same
  database gives the same answer, and every number in the console opens the assets behind it.
- **Server-side caching.** Heavy results are built once in the background and kept on the server,
  keyed to the exact `navi.db` they came from. Every browser shares them, and each specialist can keep up
  to five tag views (one business unit, one application, or the whole estate) to switch between.
- **Built to scale.** Designed for estates of about 150,000 assets and a 600 GB `navi.db`. Aggregation
  happens in SQL per asset, long jobs run in the background, and the browser only receives what it can
  display.
- **Optional model.** A model (Anthropic, any OpenAI-compatible endpoint, Bedrock, or a fully local Ollama)
  adds plain-English features. It turns a request into a query, rule or plan that you review; it never
  produces the findings or scores. With no model configured, everything still runs.

## Highlights

- **Exposure Score** fuses 16 signals (exploitability, criticality, attack paths, identity, end of life,
  crypto, SLA, ownership and more) into one score per asset, with "act now", convergence on crown jewels,
  and the projected reduction of each fix.
- **Finds the gaps:** Scan Health, Ownership, Asset Classification, IoT Discovery, End of Life,
  Certificates, Post-Quantum, AI Inventory and Identity Inventory.
- **Prioritizes the fix:** CISA KEV due dates, Attack Paths choke points, SLA Tracker and Criticality
  Calibration.
- **Acts safely:** tags and ACR go back to Tenable only after a preview and a confirmation. Automation
  Station keeps everything current on a schedule once you arm it.
- **Run the Ensemble** runs every specialist in the background (reads only), so each page is ready when you
  open it. The **Ensemble Report** summarises them all.

## Layout

```
navi-agents/
  run.py            one-command launcher (stdlib / FastAPI / Flask)
  app_stdlib.py     zero-dependency HTTP server
  hounds_mcp.py     optional read-only MCP server (see HOUNDS-MCP.md)
  core/             engine: db, caches, discovery, security, gates, llm, brand, release pipeline, …
  agents/           one folder per specialist (manifest.json · api.py · page.html · agent.py)
  web/              the console, shared dashboards, icons, and each specialist's one-pager (web/hounds/)
  tests/            regression tests — plain scripts: python3 tests/test_<name>.py
```

## The specialists

Grouped by mission. Nine "heroes" carry a codename; everyone else goes by their job.

| Mission | Specialists |
|---|---|
| Exploited Now | Laelaps · CISA KEV, Fenrir · Attack Paths, MITRE ATT&CK Map, Exposure Score |
| Asset Truth | Linnaeus · Asset Classification, Charon · End of Life, Identity Inventory, Software Inventory, Custom App Discovery, Asset Dossier |
| Coverage | Scan Health, Agent Group Sync |
| Ownership & SLA | Ownership, Exposure Routes, SLA Tracker, Criticality Calibration, Notify & Report |
| Crypto & Certificates | Certania · Certificates, Heimdall · Post-Quantum |
| OT, IoT & Unmanaged | Argos · IoT Discovery |
| AI Exposure | Pythia · AI Inventory |
| Web Apps | Arachne · Web App Report, Web App Dossier |
| Compliance | Compliance Overview, Compliance Drill-down, Audit Authoring |
| Platform | Ensemble Report, Automation Station, Remote Remediation, Tag Removal, Alerts, Dashboard Builder, MCP Routing Reference |
| Explorer | Assets, Vulnerabilities, Plugins, Routes, Paths, Software (with a zero-day lookup), Tags, Fixed, Compliance, Web Apps, and Advanced search |

## Prerequisites

- Python 3.10 or newer (a stock install works — the built-in server needs no third-party packages).
- [Tenable **navi**](https://github.com/packetchaos/navi) with a synced `navi.db` for production use (a
  sample database is generated automatically for evaluation).
- A Tenable Vulnerability Management / Tenable One account with API keys configured in navi.
- Optional: a model (Anthropic, OpenAI-compatible, Ollama or Bedrock) for the plain-English features —
  see [navi-agents/BYO_MODEL.md](navi-agents/BYO_MODEL.md).

## Outputs

- A local web console listing detected exposures per specialist, with the evidence behind each one.
- Proposed navi tag / ACR writes, shown for confirmation. Nothing is applied unless writes are enabled and
  you confirm — or you arm Automation Station, which then applies its previewed plan on a schedule behind
  the same gate.

## Known limitations

- Detection is signal-based inference; confirm findings before tagging.
- Writes are disabled by default (`NAVI_ALLOW_WRITES=0`) and every write is gated behind explicit
  confirmation; email and remote execution each need a further opt-in.
- Results are only as current as the `navi.db` you point it at.

## Coming from The Hounds?

Only the names you see changed. Agent ids, API routes, environment variables (`HOUNDS_*`), the config file
(`hounds.config.json`), the MCP server (`hounds_mcp.py`), one-pager links (`/web/hounds/<id>.html`) and
Tenable tag categories are unchanged, so existing installs, scripts and dashboards keep working. The full
list of renames is in [navi-agents/RENAME_REPORT.md](navi-agents/RENAME_REPORT.md).

## License

MIT — see [LICENSE](LICENSE).
