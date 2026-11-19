# Rename report — The Hounds → **navi Ensemble** (build 2.43.490)

A display-layer rename plus a navigation restructure. **No behaviour, API, id, tag, write gate or
security check changed.** Version: **2.43.490** (`core/version.py` MAJOR = 2; the middle number is
still the 43 discovered specialists).

## Brand (single source of truth)

| | |
|---|---|
| Brand | **navi Ensemble** (short: Ensemble) |
| Tagline | Specialist AI agents for exposure management, grounded in your Tenable data |
| Home action | **Run the Ensemble** (was Release the Hounds) |
| Orchestrator | **Standing Orders**, run by the Lead (was Covenant · AI Contract) |
| Home overview | **Briefing** (was Sphinx · On the Scent) |
| Members | "specialists"; together "the Ensemble" |
| Logo | `web/assets/brand-mark.png` (the iris mark: header, sidebar, home) · `web/assets/brand-logo.png` (full logo with wordmark) |

`core/brand.py` holds the brand, missions and the roster; `tools/brand_js.py` writes
`web/assets/brand.js` from it (loaded before `console.js` on every page). Page titles, the header,
the sidebar labels and icons, the guided-flow labels, the home grid and the one-pagers read from it.
To change a name later, edit `core/brand.py` and run `python3 tools/brand_js.py` and
`python3 tools/hound_pages.py` (+ `--intro`).

**Display rule:** a hero shows `Codename · Plain job` (e.g. *Charon · End of Life*); everyone else
the plain name only — no codename, no lore, no crest. **Crests are retired:** every specialist shows
its own icon — the one already in the sidebar — everywhere (sidebar, header, home grid, one-pager).

## The roster (old → new)

| id | Old | New | Hero codename | Mission |
|---|---|---|---|---|
| cisakev | Laelaps Hound · CISA KEV Tagging | CISA KEV | **Laelaps** | Exploited Now |
| attackpath | Fenrir Hound · Attack Path Analysis | Attack Paths | **Fenrir** | Exploited Now |
| mitre | Orthrus Hound · MITRE ATT&CK Tagging | ATT&CK Mapping | — | Exploited Now |
| fused_score | Nemesis · Exposure Score | Exposure Score | — | Exploited Now |
| classify | Linnaeus · Asset Classification | Classification | **Linnaeus** | Asset Truth |
| eol | Charon · EOL / Unsupported Tagging | End of Life | **Charon** | Asset Truth |
| identity | Janus · Identity Inventory | Identity Inventory | — | Asset Truth |
| software | Mimir · Software Analyzer | Software Inventory | — | Asset Truth |
| customapp | Cavall Hound · Custom App Name Agent | Custom App Discovery | — | Asset Truth |
| argos | Argos Hound · Asset Deep-Dive | Asset Dossier | — | Asset Truth |
| scan_eval | Chronos · Scan Evaluations | Scan Health | — | Coverage |
| agentgroup | Sirius Hound · Agent Group Tagging | Agent Group Sync | — | Coverage |
| asset_ownership | Terminus · Asset Ownership | Ownership | — | Ownership & SLA |
| exproute | Atlas · Exposure Routes | Route Mapping | — | Ownership & SLA |
| sla | Sköll · SLA Adherence | SLA Tracker | — | Ownership & SLA |
| acr | Anubis · ACR Calibration Agent | Criticality Calibration | — | Ownership & SLA |
| email | Gabriel · Email & Reports | Notify & Reports | — | Ownership & SLA |
| certificate | Certania · Certificate Agent | Certificates | **Certania** | Crypto & Certificates |
| postquantum | Heimdall · Post-Quantum Cipher Analysis | Post-Quantum | **Heimdall** | Crypto & Certificates |
| iot_squad | Cerberus Hound · IoT Discovery Squad | Device Discovery | **Argos** | OT, IoT & Unmanaged |
| ai | Pythia · AI Inventory | AI Inventory | **Pythia** | AI Exposure |
| was | Arachne · WAS · Web Apps | Web App Scanning | **Arachne** | Web Apps |
| was_asset | Beagle · Web App Recon | Web App Dossier | — | Web Apps |
| compliance | Minos · Compliance | Compliance Overview | — | Compliance |
| compliance_asset | Tiresias · Compliance Deep-Dive | Compliance Drill-down | — | Compliance |
| custom_audit | Draco · Custom Audit | Audit Authoring | — | Compliance |
| contract | Covenant · AI Navi Contract | Standing Orders | — | Platform |
| insights | Sphinx · On the Scent | Briefing | — | Platform |
| c2 | Amarok Hound · Command & Control | Remote Remediation | — | Platform |
| tagremoval | Garmr Hound · Tag Removal | Tag Removal | — | Platform |
| alert | Alert Raven · Alerting | Alerts | — | Platform |
| dashboard | Daedalus · Dashboard Builder | Dashboard Builder | — | Platform |
| mcpcmp | MCP Compare | MCP Routing Reference | — | Platform |
| ex_assets … ex_apps | Bloodhound … Vizsla | Explorer › Assets / Vulnerabilities / Plugins / Routes / Paths / Software / Tags / Fixed / Compliance / Web Apps | — | Platform (Explorer) |
| (advanced search) | Deerhound | Explorer › Advanced | — | Platform (Explorer) |
| hub | The Pack · Release the Hounds | Run the Ensemble | — | Platform |

"Argos" now names **Device Discovery** (iot_squad); the old per-asset deep-dive is **Asset Dossier**
everywhere (links from Classification, Ownership, Briefing, Device Discovery …).
"Atlas" → Route Mapping; genuine **MITRE ATLAS** references (AI Inventory's AI attack matrix) are untouched.

## What changed, by area

- **Brand source:** `core/brand.py`, `tools/brand_js.py` → `web/assets/brand.js`, `web/assets/brand-mark.png`,
  `web/assets/brand-logo.png`; `brand.js` is loaded before `console.js` on all 63 pages.
- **Manifests** (`agents/*/manifest.json`): new `name`, `mission`, `hero`, `codename` (heroes only),
  sidebar `icon`; the ten Explorer tabs get `grid: false` (off the home grid, still routable and
  searchable — `hidden` would have dropped them from the registry and the version count).
  `core/discovery.py` passes `mission / hero / codename / grid` through; `web/agents.json` regenerated.
- **Shell** (`web/assets/console.js`, `console.css`): top nav (Briefing · Run the Ensemble · Standing
  Orders · Notify & Reports · Dashboards · Explorer · Tools); sidebar labels/icons from the roster
  (its guided-flow groups kept); `CODENAMES` = the nine heroes with new lore; the codename banner shows
  only when `manifest.hero` is true; every page keeps its "what it does / key capabilities" panel
  (non-heroes without codename or lore); icon replaces the crest; header and `<title>` from
  `brand.js`; guided-flow "Next agent" labels from the roster; Explorer tabs in the roster's order.
- **Home** (`web/index.html`): grid grouped under mission headings (heroes → specialists → the rest),
  mission filter chips, one **Explorer** card, "Filter specialists — name, codename, mission, or what
  it does…", Run the Ensemble dialog/status copy (behaviour and the reads-only notice unchanged),
  "Recommended specialists" with icons.
- **Pages** (`agents/*/page.html`, `web/*.html`): headings, intro copy, labels, empty states; titles
  `<Page> — navi Ensemble`; `web/c2-log.html` → Remote Remediation Log; `web/search.html` → Explorer;
  `web/meet.html` icons + hero-only codenames.
- **Server strings** (`agents/*/api.py`, `core/*.py`): user-facing messages and labels only (Python
  string literals; docstrings, SQL, keys and identifiers excluded). The AI router prompt now names the
  suite "navi Ensemble"; the audit-authoring prompt no longer has a persona name.
- **One-pagers** (`tools/hound_pages/*.json` → `web/hounds/*.html`, path kept): heroes lead with
  codename + new lore; others lead with the plain job (no codename, no lore); icon instead of crest;
  mission chip; navi Ensemble footer.
- **Crests** (`web/assets/crests/`): no longer shown; files kept (nothing deleted — they can move to
  `_retired/` with `git mv` later); `README.md` now documents the nine heroes and the retirement.
  `crestSrc()` is unchanged.

## Retired-term sweep — `tests/test_brand_rename.py`

Scans `web/`, `agents/*/page.html`, `agents/*/manifest.json`, `tools/hound_pages/*.json` (code comments
and embedded images excluded) for: hound(s), Release the Hounds, the pack, On the Scent, AI Contract,
🐾, Command & Control, every retired codename and every dog breed. **Passes.** Allowlist, with reasons:

| Allowed | Why |
|---|---|
| `HOUNDS_*` | environment variables (saved configs depend on them) |
| `X-Hounds-*` | request headers the server reads |
| `hounds…` camel-case | localStorage keys (`houndsRelOff`, `houndsCache…`) — users' saved state |
| `hounds:ran` / `hounds:wrote` | browser event names |
| `hounds-…` | element ids / downloaded file names |
| `/web/hounds/…` | one-pager URLs (old links keep working) |
| `hounds_mcp`, `test_hound…`, `hound_pages` | module / test / tool names |
| `hounds.config.json` | the config file name |
| `the-hounds-repo` | the repository name |
| `Hounds-<Category>` and "Default Hounds." | the Settings → Test run tag-prefix default — a Tenable **tag value** |
| `.hound`, `hound:`, `hounds[…]`, `source_hound` … | JS / Python code (data keys, variables) |
| `MITRE ATLAS`, `ATLAS` | MITRE ATLAS, not the old Atlas |
| `Argos` | allowed — it now names Device Discovery — except on the old deep-dive's files or next to a link to it |

It also checks: `brand.js` ⇄ `brand.py`, every manifest matches the roster, `CODENAMES` holds exactly
the nine heroes, the banner is hero-only, the brand mark, version `2.<n>.<build>`, and that the
`/web/hounds/` pages, `hounds_mcp.py` and the `/?release=1` deep link still exist.

## Test changes (string expectations only)

| Test | Change | Why |
|---|---|---|
| test_acr_protect | "The Hounds' ACR log" → "navi Ensemble's ACR log"; Garmr → Tag Removal | renamed copy |
| test_bg_484 | Release the Hounds / AI Contract strings → Run the Ensemble / Standing Orders | renamed copy |
| test_classify_473 | Device-type tag credited to "Cerberus" → "Argos" | Argos now = Device Discovery |
| test_ex_software_475 | Explorer tab entry format; no Harrier codename; manifest name "Explorer › Software" | Explorer tabs carry no codename |
| test_gear_468 | "Hounds indexes" → "Ensemble indexes" | renamed copy |
| test_hx_optimize | "optimized for the Hounds" → "… the Ensemble" | renamed copy |
| test_nemesis_scope_488 | column header "Nemesis" → "Exposure Score" | renamed copy |
| test_release | "no hound selected" → "no specialist selected" | renamed copy |
| test_c2_487, test_c2_phase2_486 | version string `1.43.<build>` → `<MAJOR>.43.<build>` | version 2.x |
| test_security_client | "LLM pick ids go through crestSrc()" → "LLM pick ids never reach an `<img src>`" | picks show an esc()'d roster icon — no `<img>` is built from the id at all, which is **stricter**; the `/static/crests/'+p.id` guard is unchanged |

New: `tests/test_brand_rename.py`.

## Screenshots (`docs/rename_490/`)

home · home_phone · cisakev (hero) · iot_squad (Argos) · acr (non-hero) · explorer · c2 · c2log ·
contract · insights · onepager_hero · onepager_nonhero · release_dialog — checked for overflow, empty
crest boxes, hero-only banners and page errors (none). Old deep links checked:
`/agents/ex_assets/page.html`, `/web/hounds/cisakev.html`, `/?release=1`.

## Deferred (not changed — candidates for later)

- Markdown docs outside the UI: README, INSTALL, CONTRIBUTING, specs, `HOUNDS-MCP.md`, agent READMEs
  (only the version numbers were updated)
- Repository name, Python package / module names, MCP tool names in `hounds_mcp.py`
- Environment variables (`HOUNDS_*`), `localStorage` keys (`hounds*` — a migration would be needed),
  the `hounds.config.json` file name, the `X-Hounds-*` headers
- The `/web/hounds/` path for the one-pagers
- The `Hounds-` default test-run tag prefix (a Tenable tag value)
- Skills (`the-hounds` skill etc.)
- Code comments and docstrings that still say hound (not user-facing)
- The one-pagers' "At a glance" images are screenshots of the old UI (some still show old wording such
  as "changed by the Hounds"); re-capture with `node tools/hound_pages_capture.js` against a populated
  console, then `python3 tools/hound_pages.py`
- The crest PNGs (now unused) → `web/assets/crests/_retired/` with `git mv`

## Open questions for Casey

1. **Sidebar grouping** — the sidebar kept its guided-flow groups (Fast signal · Deeper analysis ·
   Organize · Operationalize · Views); the home grid uses the nine missions. Switch the sidebar to
   missions too?
2. **Remote Remediation's icon** is still 🐺 (from the sidebar) — keep it, or something less on-theme
   for the old brand (🛠️)?
3. **Duplicate icons** carried over from the sidebar: 🎯 (ATT&CK Mapping, Exposure Score), ⚖️
   (Criticality Calibration, Compliance Overview), 🕸️ (Attack Paths, Web App Scanning), 📜 (Audit
   Authoring, Standing Orders) — give some a new icon?
4. **Server log / email prefixes** now read `[navi Ensemble]` — fine for alert-email filters people set up?

## Build 491 follow-up

Three more display names changed (ids, routes and URLs unchanged):

| Was (490) | Now (491) | id |
|---|---|---|
| Standing Orders | **Automation** | `contract` |
| Briefing | **Ensemble Report** | `insights` |
| Route Mapping | **Exposure Routes** | `exproute` |

`core/brand.py` (ORCHESTRATOR, OVERVIEW, roster), manifests, pages, one-pagers, email subjects and
server strings were updated; `tests/test_brand_rename.py` now treats "Standing Orders", "Briefing" and
"Route Mapping" as retired words. Settings help for the route/paths sync no longer names the old codenames. The email template "Morning briefing" is a different thing and keeps its name.
The tables above describe build 490 as delivered.

## Build 492 — final names

| Was (491) | Now (492) | id |
|---|---|---|
| ATT&CK Mapping | **MITRE ATT&CK Map** | `mitre` |
| Device Discovery | **IoT Discovery** (hero: Argos · IoT Discovery) | `iot_squad` |
| Web App Scanning | **Web App Report** (hero: Arachne · Web App Report) | `was` |
| Classification | **Asset Classification** (hero: Linnaeus · Asset Classification) | `classify` |
| Notify & Reports | **Notify & Report** | `email` |
| Automation | **Automation Station** | `contract` |
| Tools (nav) | **Tools and Logs** | `/web/tools.html` |

Kept on purpose: MITRE technique T1120 "Peripheral Device Discovery", the generic "Web App Scanning program"
line in the Web Apps explorer's one-pager, and the Classification chart/facet labels on the Asset
Classification page (they name a category, not the specialist). Email subjects now read
"[navi Ensemble] Automation Station cycle — …".

## Build 493 — the navi Ensemble icon set

The sidebar emoji are replaced by the navi Ensemble icon tiles (32 specialists, from the two icon-system
sheets) wherever a specialist's icon appears: sidebar, home grid, page headers, intro panel, Meet and the
one-pagers. "Run the Ensemble" keeps the navi Ensemble mark; the Explorer tabs, Tools and Logs and MCP
Routing Reference keep their emoji until their tiles exist. See `web/assets/icons/README.md`.
