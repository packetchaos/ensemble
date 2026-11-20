# ACR Calibration Agent — Specification

Adjusts the **Asset Criticality Rating (ACR, 1–10)** for all assets carrying a
tag, so Tenable One's Asset Exposure Score (AES) reflects business reality.

## Tag source — the live command (not the tags table)
The agent lists tags via **`navi explore info tags`** (parsed Category / Value /
Value UUID), per requirement — *not* a `SELECT` on the local `tags` table. In the
standalone app this runs through `navi_cli.list_tags()` (subprocess); in the live
artifact it runs through `navi_explore_info(subcommand="tags")`.

## What the operator can do
- **Set** — absolute ACR 1–10 for every asset on the tag (`mod="set"`).
- **Increase by N** — `mod="inc"`: each asset's ACR goes up by N (capped at 10).
- **Decrease by N** — `mod="dec"`: each asset's ACR goes down by N (floored at 1).
  So an asset at **9** with −1 becomes **8**; an asset at **3** with −1 becomes **2**.
- **Business justification** — a free-text note (required for inc/dec) carried into
  the change for audit.
- **Change Reason** — at least one of business / compliance / mitigation /
  development (Tenable One mandates a reason on every ACR change).

## Apply (gated)
`navi_enrich_acr(category, value, score, mod, note, <reason>=True, confirm=True)`
— needs `confirm=true` (the UI's Apply) **and** `NAVI_ALLOW_WRITES=1` with `navi`
on PATH. Validates score 1–10 and ≥1 reason before calling. Handles navi 8.6.2's
cosmetic `job_uuid` crash as applied-with-warning. Allow ~30 min for AES recompute.

## Bulk ACR — free-form natural language (LLM)
A prompt box lets you calibrate many tags from one plain-English instruction,
e.g.:

> *Drop all IoT and lab gear by 5, set anything internet-facing to 9, bump
> production databases to 10, and leave the vuln-route tags alone.*

**Interpret with AI** sends the instruction + the live tag list to a model,
which returns proposed ACR changes. The model only *proposes* — output is then
**validated** against the current tags (tag must exist, `mod ∈ set/inc/dec`,
score 1–10; anything else is rejected and shown) and rendered as a per-tag
preview. Nothing is written until you click **Apply all**, which runs one gated
`navi_enrich_acr` per change (the instruction + the model's "why" become the
audit note).

- **Artifact**: uses on-device inference (`window.cowork.askClaude`).
- **Standalone**: uses the Anthropic API via `ANTHROPIC_API_KEY` (model from
  `ANTHROPIC_MODEL`, default `claude-haiku-4-5-20251001`) at `/api/acr/interpret`.
- **Fallback**: with no key / no inference available, the box is parsed by the
  deterministic rule grammar instead (`Parse as rules`):
  `if <keyword> reduce|increase|set by|to N` (first match wins). Always available,
  fully offline, auditable.

## 📊 At a glance — estate metrics (build 502)
`core/acr_estate.py`, returned as `estate` by `POST /api/acr/metrics` (loaded by ▶ Load, never on open).
Read-only; one grouped pass over `assets` (never `vulns`), two top-N reads, cached per navi.db
file signature + ACR-log high-water mark. Bands are Tenable's: **ACR** Critical 9–10 · High 7–8 ·
Medium 4–6 · Low 1–3; **AES** High 650–1000 · Medium 350–649 · Low 0–349.

| Card | Question it answers |
|---|---|
| ACR spread | How much of my estate is at each ACR band (count + % of all assets), average ACR, assets with no ACR (navi skips them). |
| ACR values 10 → 1 | The per-value distribution, zeros included. |
| AES | Average AES, **top** and **bottom** AES asset (click → Argos), AES 0 vs unscored, AES band bar. |
| Highest / Lowest AES | Top-5 and bottom-5 assets with their ACR — the fix-first list. |
| Default vs changed | Rated assets with no recorded change vs changed by the Ensemble vs protected (`NO : UPDATE`); **drift**; most-common ACR value. |
| Where the exposure sits | Share of total AES per ACR band + avg AES per band; **ACR 9–10 × AES High** (fix first); **ACR 1–3 × AES High** (rated right?). |
| Who changed ACR | Applied changes by Change Reason and by Hound. |

**Design input — VM manager + Tenable expert review.** The spread/AES/default-vs-changed asks were
extended with what a vulnerability-management lead acts on: (1) the ACR × AES crossover — a critical
asset with high exposure is the first fix, a low-rated asset with high exposure is a calibration
question; (2) where the total AES sits by band (are crown jewels better or worse maintained?);
(3) drift — an ACR the Ensemble set that has since moved means it needs `NO : UPDATE`;
(4) a single dominant ACR value (≥ 60 %) as the "still on defaults" signal; (5) reason / Hound mix
for audit. Tenable-expert constraints: Tenable does not calculate AES for unlicensed assets, so a
missing AES is *unscored*, never 0; navi.db stores ACR as text (`"8.0"`) and blanks as `''`/`'None'`;
navi.db only covers assets in the sync window (default 90 days), same as Tenable's own CES.

**Limit — "changed by the user".** navi.db carries only the current ACR — no ACR drivers and no
override flag — so an ACR changed directly in the Tenable UI (or by plain navi CLI) is invisible here
and is reported under *no recorded change*. "Changed" = an applied row in the Ensemble ACR log, or an
asset tagged exactly `NO : UPDATE`. Closing this gap needs navi to store the export's ACR source /
drivers. Drift is judged only for changes older than navi.db's last write.

## REST API
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/agents/acr/run` | List tags from `navi explore info tags`. |
| POST | `/api/acr/apply` | Apply one ACR change. Body: `{category, value, score, mod, note, reasons[], confirm}`. |
| POST | `/api/acr/metrics` | At a glance: `estate` (ACR spread, AES, default vs changed) + Protection. Body: `{show, limit, fresh}`. |
| POST | `/api/acr/bulk_apply` | Apply a batch. Body: `{changes:[{category,value,score,mod,note,reasons[]}], confirm}`. |

## Suggested tier mapping (set)
Prod+PII 10 · Internet-facing 9 · Production 8 · Staging 6 · Dev/Test 3 · Isolated 2.

## Validated
Tag-listing parser handles values containing colons (e.g. Mitre "Primary Impact: T1574").
Gates verified: confirm required, score 1–10, ≥1 reason, justification required for
inc/dec, and writes blocked without `NAVI_ALLOW_WRITES`. Identical on FastAPI and Flask;
also live in the artifact tab.
