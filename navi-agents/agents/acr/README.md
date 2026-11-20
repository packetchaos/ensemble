# ACR Calibration Agent
Lists tags from the live `navi explore info tags` command (not the tags table)
and adjusts Asset Criticality Rating per tag — **set** absolute, or **+N / −N**
relative — with a required business justification and Change Reason. Bulk mode
takes **free-form natural language** ("drop all IoT and lab gear by 5 …") via an
LLM, validated and previewed before any gated write.

- **UI:** `page.html` · **API:** `/api/acr/run`, `apply`, `bulk_apply`, `interpret`
- **Config:** a configured model (any provider in [BYO_MODEL.md](../../BYO_MODEL.md)) enables NL
  bulk; without one, per-tag set / +N / −N still works.
- **Writes:** gated `navi enrich acr` (`NAVI_ALLOW_WRITES=1` + `confirm: true`); assets tagged
  exactly `NO : UPDATE` are skipped, and every change lands in the ACR log.
- **At a glance:** ACR spread by Tenable band, average / top / bottom AES, default vs changed
  (ACR log ∪ `NO : UPDATE`), drift and the ACR × AES crossover — `core/acr_estate.py`, see [ACR_SPEC.md](../../ACR_SPEC.md).
- **Ensemble (build 506):** pre-run by Run the Ensemble; Done so far panel; last ▶ Load restored from the server
  page cache; sections ACR values · Where the exposure sits · Ensemble changes & protection · Who changed ACR.
