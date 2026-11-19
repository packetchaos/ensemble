# Crests — retired in build 490 (navi Ensemble)

The UI no longer shows crests. Every specialist is shown with its **own icon** — the one in the
sidebar — from `core/brand.py` (`ROSTER[id][3]`, mirrored in `web/assets/brand.js`). The console's
brand mark (top-left, and "Run the Ensemble") is the iris mark, `web/assets/brand-mark.png`; the full
logo with the wordmark is `web/assets/brand-logo.png`. Both were cut from the navi Ensemble logo.

The PNGs here are kept (no file was deleted) so old links keep working; they can move to
`_retired/` with `git mv` when convenient. `crestSrc()` in console.js is unchanged (a security
test checks it).

## The nine heroes (codename · plain job)

| id | Hero | Plain job | Mission |
|---|---|---|---|
| cisakev | Laelaps | CISA KEV | Exploited Now |
| attackpath | Fenrir | Attack Paths | Exploited Now |
| classify | Linnaeus | Classification | Asset Truth |
| eol | Charon | End of Life | Asset Truth |
| certificate | Certania | Certificates | Crypto & Certificates |
| postquantum | Heimdall | Post-Quantum | Crypto & Certificates |
| iot_squad | Argos | Device Discovery | OT, IoT & Unmanaged |
| ai | Pythia | AI Inventory | AI Exposure |
| was | Arachne | Web App Scanning | Web Apps |

Everyone else shows its plain name only — no codename, no lore, no crest.
