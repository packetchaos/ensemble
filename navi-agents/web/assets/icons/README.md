# navi Ensemble icon tiles (build 493)

One 96×96 PNG per specialist id, cut from the navi Ensemble icon-system sheets (dark rounded tile,
purple line glyph). `core/brand.ICON_IMG` lists which ids have a tile; `brand.js` carries the path as
`BRAND.roster[id].img`, and `brandIconHtml(id)` in `console.js` renders it (sidebar, home grid, intro
panel, Meet). Page headers reference `/static/icons/<id>.png` directly, and the one-pagers embed it.

Specialists without a tile (the Explorer tabs, Tools and Logs, MCP Routing Reference) keep their emoji.
"Run the Ensemble" keeps the navi Ensemble mark (`/static/brand-mark.png`).

To add one: drop `<id>.png` here, add the id to `ICON_IMG`, run `python3 tools/brand_js.py` and
`python3 tools/hound_pages.py`, and replace the emoji in that page's `<h2>`.
