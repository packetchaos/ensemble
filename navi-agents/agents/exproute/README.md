# Exposure Routes — owner mapping (Atlas)

Map exposure **routes** (`vuln_route`) and filesystem **paths** (`vuln_paths`) to
the people who own them, in plain English.

- **Owners** come from navi (`navi explore info users | user_groups | agent_groups`,
  live Tenable API). The Tenable MCP is a backup/validator in the desktop console.
- **Routes & paths** come from navi.db.
- A natural-language instruction (e.g. *"give all payment routes to VM Team, put
  /opt and nginx paths under Networking Systems"*) is mapped per item to an owner.
- Applying a mapping tags every asset on the matched route/path with
  `Owner:<group-or-user>` via the gated navi tag path (route → `--route_id`,
  path → `--query`). Writes need `NAVI_ALLOW_WRITES=1` and `navi` on PATH.

The natural-language step needs a configured model on the server (any provider in
[BYO_MODEL.md](../../BYO_MODEL.md)); without it the NL box is hidden (the rest of the page still loads owners, routes, and paths).

## One run, cached

**▶ Run** calls `snapshot`: owners, routes, paths, coverage and the ownership map from **one
server-side pass**, cached on disk (`data/cache/exproute_<db>.json.gz`, gzipped) and in memory,
keyed by navi.db's signature (size + mtime of the db and its `-wal`).

- navi.db unchanged → the cached snapshot renders at once (a Run or reopening the page).
- navi.db changed (e.g. after `navi config update assets`) → the build runs on the **job queue**. You
  can leave the page; it keeps running (Runs log), and reopening the page re-attaches to it.
- Opening the page only *peeks*: it shows a cached snapshot or follows a running build, and
  never starts a computation.
- **↻ Rebuild** (Sankey) / "rebuild" forces a fresh build. **↻ Refresh owners** re-pulls the
  owner directory, which is otherwise cached for 6 h (`NAVI_OWNERS_TTL_S`) — it's a live
  Tenable API call through navi. A failed pull keeps the last good list.

The one result feeds the **Sankey**, the embedded **Ownership Map** (`/web/ownermap.html?embed=1`,
handed the result with `omLoad()`; its own header, sidebar and refresh are hidden) and the
metrics. `map` and `coverage` are still available and are served from the snapshot.

Speed: membership (route → assets, route ↔ path) is built from linear scans in Python instead
of the old `LIKE '%…%'` cross-joins. 100K findings / 300 routes went from ~3 minutes to 0.4 s;
600K findings / 1,500 routes builds in ~5 s.

## Build 498

- **Runs are reported like every other specialist's.** ▶ Run / ↻ rebuild / ↻ refresh owners send
  a run id; the run lands in *Done so far* when the snapshot is ready (its real build time, or a
  cached run). Run the Ensemble records its own runs. (SLA Tracker got the same fix.)
- **⛶ full screen** on the Ownership Map section and on its ownership graph (threads / Sankey),
  standalone and embedded.
- **Path → Remote Remediation.** Clicking a path (Sankey node, *Close the gap* path, or the map's
  route → path list) opens its detail — open findings only, % owned, its own owners and the
  route owners covering it — with **📧 Email this path** *or* **🛠 Remediate → Remote
  Remediation** (pick the plugin) / **🔎 Validate path**. The hand-off pre-fills the C2 page's
  hosts; nothing runs until the operator chooses and confirms there.
- **The Ownership specialist** (asset_ownership) uses the same rule: each asset's *claimed %* is
  the share of its open findings owned (or dispositioned) through their route or a path, and the
  Asset Owner cascade tags the asset's routes plus only the paths of findings with no route.

## Plugin coverage — the route / path / plugin index (build 496)

navi assigns every non-info plugin to **one route** (`vuln_route`) and parses **paths** out of
non-info findings (`vuln_paths`). A route has many plugins; a plugin can sit at many paths and a
path can carry many plugins, so route ↔ path is 1:1 or many-to-many. Exposure Routes zips the two
together **per finding**:

- Every **open** (open / reopened), **non-info** finding — one per plugin × asset — is matched to
  its plugin's route and the paths that plugin was found at on that asset. Fixed and info
  findings no longer count anywhere on this page.
- A finding is **owned** when its asset carries a real Owner tag for that route **or** one of
  those paths; **decided** when it carries Ignored / Accepted / Mitigated instead; **unowned**
  otherwise; **unreachable** when its plugin has no route and no path (the route table is older
  than the plugin — rebuild routes).
- A plugin is owned / decided / partial / unowned / unrouted from its findings; an asset is
  **closed** when every open finding on it is owned.
- **Close the gap** lists the routes and the paths whose Owner tag would close the most unowned
  findings, each with a 🏷 Tag owner button; the plugin list shows the 200 plugins with the most
  open findings that aren't fully owned.

The index lives in navi.db as `hx_rpp` (finding → route, path count) and `hx_rpp_path` (its
paths), built by ⚡ Optimize (core/hx_rpp.py). It goes stale when vulns/assets change **or** when
routes or paths are rebuilt; a console route/paths update re-runs Optimize when the index was
built before. Until then the page computes the same rows from navi.db directly (slower on large
estates) and says so. Measured on 150K assets / 3.8M findings / 1,500 routes: the index adds 9 s
to Optimize and the page's pass takes 12 s with it (37 s without).

## Ownership rules

- An asset is **owned** for a route/path only by a real owner tag `<name>: <user>` — not
  `Ignored` / `Accepted` / `Mitigated`, not a bare `<name>`. Names compare case- and
  whitespace-insensitively with no wildcards. An owner containing `': '` splits at the known
  route/path name.
- **Routes and paths are methods of assigning plugins** (build 497). A route or path is
  **owned** (covered) when every open finding on it is owned — by its own Owner tag or by the
  route / path tag that covers the same finding; **partial** when some are. Own the CentOS route
  and every CentOS path is 100% owned; hand one of those paths to someone else and it stays 100%
  owned (now by them). A route can likewise be owned entirely through its paths' tags.
- **Assigned directly** = the route/path carries an Owner tag of its own — counted separately
  (`routes_assigned`, `paths_assigned`). Workload counts only direct assignments; owners shown on
  an item = its own plus those of the routes/paths that cover it (`via_routes` / `via_paths`).
- **Ownerless Risk** = assets where not one open finding is owned or decided through its route or
  a path.
- Owner workload counts only the assets tagged to that owner.
- Routes that share an app name are one route; tagging it tags every `route_id` with the name.
- Re-tagging an unmatched Owner name (`retag`) moves only the assets carrying the old tag,
  per owner, onto the exact route/path name.
Ticking gaps in the embedded map and sending them to Atlas opens the quick-assign card on this
page. The standalone `/web/ownermap.html` works as before.

## Metrics

- **Attack surface:** routes (with / without paths), distinct paths (under a route / orphan),
  assets in scope and routes per asset, and the route-findings → routes reduction.
- **Ownership:** routes fully owned (owned · partial · none), paths owned (incl. via their
  route), **Ownerless Risk** assets, assets closed (every route owned).
- **Risk without an owner:** unowned or partially owned routes/paths with VPR ≥ 7 and the
  unowned assets behind them, critical (VPR ≥ 9) ones and the worst, dispositions
  (mitigated · accepted · ignored), Owner tags whose app name misses every route.
- **People:** owners with work vs users & groups available, the busiest owner's share of
  owner-assigned assets, routes + paths per owner.
- **At a glance:** routes and paths by ownership, Ownerless Risk by VPR band, owner workload.

The jump panel links the Ask box, coverage, the Sankey, the Ownership Map and Owners.

Actions: `snapshot` (`peek` / `force` / `refresh_owners`), `load` (owners + routes + paths),
`coverage`, `map` (routes/paths ↔ owners, gaps, workload, reduction funnel), `interpret`
(NL → mappings), `apply` (gated Owner tag), `retag` (gated), `refresh` (background
`navi config update assets`), `path_detail`.
