# IoT Discovery Squad — Specification

Four cooperating agents that discover IoT/OT devices in Tenable via navi, tag
them, and **learn new detections over time** under human review. Built on the
same shared core as the Certificate Agent (read-only `navi.db`, gated `navi`
CLI writes).

```
Discovery (A1) ──hand off iot_name + plugins──▶ Expansion (A2)
      │                                              │ expanded plugin list
      │ IoT:<name> tag actions (Gate 1)              ▼
      ▼                                       Cross-Reference (A3)
  human approves tags                     ┌── other matching assets (candidates)
                                          └── propose new detections (Gate 2) ──▶ human
                         Orchestrator / QA (A4) chains all three + quality checks
```

## Agent 1 — IoT Discovery
- Loads the detection registry (`data/iot_detections.json`).
- For each detection, finds assets whose vulns match by `plugin_id`,
  `plugin_name LIKE`, or `output LIKE` (conservative; ultra-short output terms skipped).
- **Action 1:** emits `IoT:<name>` tag actions (ephemeral `remove=True`, so
  membership always reflects current detections; UUID preserved).
- **Action 2 (hand-off):** sends `{iot_name, trigger_plugins, asset_uuids}` to A2.

## Agent 2 — Plugin Expansion
- For each `iot_name`, searches **every** plugin name and output for that name.
- Guardrails (false-positive control):
  - drop plugins on the generic/enumeration **denylist** (10863, 11936, 54615, 35716, …);
  - drop plugins firing on **> 50%** of assets (too prevalent);
  - skip `iot_name`s shorter than 5 chars or on the stoplist (cast, camera, server, …).
- Kept plugins not yet in the registry's explicit `plugins` list (and not previously
  rejected) become **proposals**. Hands the expanded list to A3.

## Agent 3 — Cross-Reference
- Uses the kept expanded plugins to find **other assets** (not already discovered)
  that share those signatures → cross-reference candidates (with evidence count).
- Sends the proposed new detections to the **human (Gate 2)**: "add these plugins
  to the default detection for `<iot_name>`?"
  - **Approve** → persisted into `iot_detections.json` with provenance; reused next run.
  - **Reject** → remembered in `rejected[]`, never re-proposed.

## Agent 4 — Orchestrator / QA
- Runs A1 → A2 → A3 as one pipeline, pausing at the two human gates.
- Quality checks: ambiguous plugins (proposed for >1 device), generic-denylist leaks,
  weak (single-plugin) candidate evidence. Returns flags for review.

## Human-in-the-loop gates
1. **Tag approval** (A1): approve `IoT:<name>` → gated `navi enrich tag … -remove`
   (needs `NAVI_ALLOW_WRITES=1` + `navi` on PATH). Handles the navi 8.6.2
   cosmetic `job_uuid` crash as applied-with-warning.
2. **Detection approval** (A3): approve/reject proposals → writes the local registry.

## 📟 Device inventory (builds 504–505)
`core/iot_inventory.py`. ▶ Run publishes **one row per device asset** to the result store
(core/payload.py), so the page pages, searches, exports and tags it on the server. Asset UUIDs never
reach the browser, and a 200-camera list and a 149K-asset list behave the same.

| Status | Means |
|---|---|
| **Confirmed** | a registry detection matched (Agent 1) |
| **Identified** | fingerprinted by a certificate (signal fusion) |
| **Predicted** | inferred, not confirmed: Device Type / OUI / mDNS signals only, named `<Device Type> · <vendor>` (e.g. *Camera · Hikvision*), or a carrier plugin that mentions a device term the registry doesn't match on that asset yet (Agent 3 `new` / `cross`, from the **full** asset set, not the 200 the payload keeps) |

An asset found more than once keeps its strongest status; the other names go to `also`.
Every row carries filter flags `st:` · `dev:` · `type:` · `vendor:` · `src:` · `crit` · `high` · `kev` · `aes_high`.

**At a glance** (build 505) keeps four small cards: Device inventory (confirmed / identified / predicted),
Gate 1, Exposure, Learning loop. The rollups have their own full-width sections:

- **🧭 Devices & vendors** — tabs *Devices* / *Vendors (OUI)*, top 200 by asset count, filterable, paged:
  assets, **riskiest asset → Asset Dossier** (AES · ACR · KEV), exposure (KEV / crit / high / AES ≥ 650),
  max AES · avg ACR, how found (confirmed / identified / predicted mix), the vendors of a device (or the
  devices of a vendor), Device Type, **List ↓**.
- **🔮 Predicted — not confirmed** — predicted assets only, grouped by predicted device (top 200 groups;
  *List all* shows every predicted asset): confidence mix (High / Medium / Low), the evidence on the riskiest
  asset, its Dossier link, exposure, vendors, **List & tag ↓** — and a jump to Gate 2 to make a plugin-term
  prediction a registry detection.

Any **List ↓** narrows the **📟 Device inventory** table (and clears an old search), where each host opens Asset Dossier (Argos), **⬇ Export CSV** writes every row of the list,
and **🏷️ Tag these N assets** writes either `Asset Inventory : Device Type: <value>` (pre-filled with the
Classifier's label, e.g. `camera` → `Camera`) or `IoT : <device name>` — both schemes the Classifier reads.
Gated + confirm; add-only; `navi_cli.tag_set` pages it at 1,999 assets per navi job.

Build 504 also widened `core/signals._DEVTYPE` to every Nessus Device Type the Classifier maps
(camera, wireless-access-point, scada, voip, storage, mobile, …), anchored on `Remote device type :` —
those devices read `unknown` before.

## REST API
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/agents/iot_squad/run` | Run the whole pipeline; returns discovery/expansion/xref/qa + the two gates. |
| POST | `/api/agents/iot_squad/tags/apply` | Apply approved `IoT:<name>` tags (`{values, confirm}`). |
| POST | `/api/iot_squad/drill` | Device inventory page: `{run, section:"devices", filter:[flags], q, sort, next, limit}`. |
| POST | `/api/iot_squad/inventory_export` | Every row of the list as CSV: `{run, filter, q}`. |
| POST | `/api/iot_squad/inventory_tag` | Gated: tag the list — `{run, filter, q, scheme: device_type\|iot, value, confirm}`. |
| GET | `/api/iot/registry` | Current default detections + rejected list. |
| POST | `/api/iot/detections/decide` | Persist approve/reject decisions (`{decisions, confirm}`). |

## Detection registry (`data/iot_detections.json`)
Seeded from the navi device-fingerprinting playbook (plugin 10863 cert appliances,
66717 mDNS, 35716 MAC OUI): Chromecast, pfSense, Ubiquiti, TeraStation,
Samsung SmartTV. Grows via Gate 2. Path override: `IOT_REGISTRY_PATH`.

## Validated (sample dataset)
- A1 discovers all 5 seed device types and emits 5 tag actions.
- A2 keeps device-specific plugins; drops the generic 10863 via the denylist.
- A3 surfaces a cross-reference candidate (`edge-fw-02` via the pfSense HTTP plugin)
  and 4 detection proposals.
- Approving a proposal persists it (and stops it being re-proposed); rejecting is remembered.
- A4 QA returns no false flags on clean data.
- Identical results via FastAPI and Flask; tag + detection writes both gated.

## Things to keep tuning
- **Generic terms / prevalence cap** are the main false-positive levers (`core/iot_common.py`).
- **Stale navi.db** still applies — run `navi config update full` so discovery sees live assets.
- **Loop bounds:** the pipeline runs one expansion pass per execution; re-run after
  approving detections to pick up the newly-promoted plugins (the UI does this automatically).
