"""The widget library (build 509) — every widget a board can hold, as a DEFINITION (never a saved
copy of rows), so the same widget shows the same number on every board.

Three sources, one shape:
  · presets      — the starter metrics below (the Builder's starters, rewritten on the shared
                   definitions in core/dashmetrics so KEV / crown jewel / open mean one thing)
  · specialists  — each specialist declares its widgets in its manifest.json under "widgets"
                   (id, title, viz, sql, optional drill / note / w / h / lineage)
  · my SQL       — SQL widgets a person saved (core/boards keeps them); imported ones need a
                   review before they run

A definition:
  {ref, title, note, group, viz, sql, drill?, label_col?, value_col?, w, h,
   source: {kind, agent?, name?, page?}, lineage?: [{t, src}]}

`sql` / `drill` are read-only SELECTs over navi.db with the $__macros of core/dashmetrics.
Running one: core/boards.run_widget (cached per definition + scope + navi.db state).
"""
import json
import os
import re

from core import dashmetrics

VIZ = ["kpi", "bar", "column", "stacked", "grouped", "pie", "donut", "line", "area", "combo", "scatter",
       "bubble", "heatmap", "treemap", "funnel", "waterfall", "radar", "gauge", "progress", "histogram",
       "table", "text"]
ROW_CAP = 500                 # rows a widget returns (like run_sql) — charts never need more
PAGE_MAX = 200                # rows per drill page
EXPORT_MAX = 5000             # rows a CSV export may pull (the UI's UUID ceiling)

_SEV = ("CASE lower(v.severity) WHEN 'critical' THEN 'Critical' WHEN 'high' THEN 'High' "
        "WHEN 'medium' THEN 'Medium' WHEN 'low' THEN 'Low' END")
_EOL = ("(lower(v.plugin_name) LIKE '%unsupported%' OR lower(v.plugin_name) LIKE '%end of life%' "
        "OR lower(v.plugin_name) LIKE '%end-of-life%' OR lower(v.plugin_name) LIKE '%seol%')")
_SCANNED = ",".join(dashmetrics.lit(p) for p in dashmetrics.SCANNED_PLUGINS)
_FIND_DRILL = ("SELECT COALESCE(NULLIF(v.asset_hostname,''), v.asset_ip) AS host, v.asset_ip AS ip, "
               "v.plugin_id, v.plugin_name, v.severity, v.state, v.first_found, v.last_found, v.asset_uuid "
               "FROM vulns v WHERE {w} ORDER BY host, v.plugin_id")
_ASSET_DRILL = ("SELECT COALESCE(NULLIF(a.hostname,''), a.ip_address) AS host, a.ip_address AS ip, "
                "a.operating_system, a.acr, a.last_found, a.uuid AS asset_uuid FROM assets a WHERE {w} "
                "ORDER BY host")
_CERT_DRILL = ("SELECT COALESCE(NULLIF(a.hostname,''), a.ip_address) AS host, c.common_name, c.issuer_name, "
               "$__certdate(c.not_valid_after) AS expires, c.signature_algorithm, c.key_length, c.asset_uuid "
               "FROM certs c LEFT JOIN assets a ON a.uuid=c.asset_uuid WHERE {w} ORDER BY expires")


def _p(group, slug, title, note, viz, sql, drill=None, w=3, h=2, **kw):
    d = {"ref": "preset." + slug, "title": title, "note": note, "group": group, "viz": viz, "sql": sql,
         "w": w, "h": h, "source": {"kind": "preset", "name": "Starter metrics"}}
    if drill:
        d["drill"] = drill
    d.update(kw)
    return d


PRESETS = [
    # ── Program / leadership ────────────────────────────────────────────────────────────────
    _p("Program", "assets_in_scope", "Assets in scope",
       "Every asset the scope covers — the denominator for the rest of the board.", "kpi",
       "SELECT COUNT(*) AS \"Assets\" FROM assets a WHERE $__scope(a.uuid)",
       _ASSET_DRILL.format(w="$__scope(a.uuid)"), w=2),
    _p("Program", "kev_assets", "KEV-exposed assets",
       "Assets with an open finding for a CISA Known Exploited Vulnerability — the same set the CISA KEV page counts.",
       "kpi",
       "SELECT COUNT(DISTINCT v.asset_uuid) AS \"KEV-exposed assets\" FROM vulns v "
       "WHERE $__open(v) AND $__kev(v) AND $__scope(v.asset_uuid)",
       _FIND_DRILL.format(w="$__open(v) AND $__kev(v) AND $__scope(v.asset_uuid)")),
    _p("Program", "crown_jewels", "Crown jewels ({CROWN})",
       "Assets rated 9 or 10 for business criticality.", "kpi",
       "SELECT COUNT(*) AS \"Crown jewels\" FROM assets a WHERE $__crown(a) AND $__scope(a.uuid)",
       _ASSET_DRILL.format(w="$__crown(a) AND $__scope(a.uuid)"), w=2),
    _p("Program", "crown_kev", "Crown jewels with KEV",
       "Crown jewels ({CROWN}) carrying an open KEV finding — fix these first.", "kpi",
       "SELECT COUNT(*) AS \"Crown jewels with KEV\" FROM assets a WHERE $__crown(a) AND $__scope(a.uuid) "
       "AND a.uuid IN (SELECT v.asset_uuid FROM vulns v WHERE $__open(v) AND $__kev(v))",
       _ASSET_DRILL.format(w="$__crown(a) AND $__scope(a.uuid) AND a.uuid IN "
                              "(SELECT v.asset_uuid FROM vulns v WHERE $__open(v) AND $__kev(v))")),
    _p("Program", "unpatchable_pct", "Unpatchable share (EOL)",
       "Share of the assets in scope running end-of-life / unsupported software — risk a patch can never fix.",
       "kpi",
       "SELECT ROUND(100.0*(SELECT COUNT(DISTINCT v.asset_uuid) FROM vulns v WHERE $__open(v) AND " + _EOL +
       " AND $__scope(v.asset_uuid)) / NULLIF((SELECT COUNT(*) FROM assets a WHERE $__scope(a.uuid)),0),1) "
       "AS \"Unpatchable %\"",
       _FIND_DRILL.format(w="$__open(v) AND " + _EOL + " AND $__scope(v.asset_uuid)")),
    _p("Program", "ownerless", "Ownerless assets",
       "Assets with no Owner tag — nobody is accountable for their risk.", "kpi",
       "SELECT COUNT(*) AS \"Ownerless assets\" FROM assets a WHERE $__scope(a.uuid) AND a.uuid NOT IN "
       "(SELECT asset_uuid FROM tags WHERE tag_key='Owner' AND asset_uuid IS NOT NULL)",
       _ASSET_DRILL.format(w="$__scope(a.uuid) AND a.uuid NOT IN (SELECT asset_uuid FROM tags "
                              "WHERE tag_key='Owner' AND asset_uuid IS NOT NULL)"), w=2),
    _p("Program", "cred_coverage", "Credentialed coverage",
       "Of the scanned assets, the share the scanner logged in to (credentialed_asset).", "gauge",
       "SELECT 'Credentialed %' AS metric, COALESCE(ROUND(100.0*COUNT(DISTINCT CASE WHEN $__cred(v) THEN "
       "v.asset_uuid END)/NULLIF(COUNT(DISTINCT v.asset_uuid),0),1),0) AS pct FROM vulns v "
       f"WHERE v.plugin_id IN ({_SCANNED}) AND $__scope(v.asset_uuid)", w=3, label_col="metric",
       value_col="pct"),
    _p("Program", "blind_hosts", "Blind hosts (no credentials)",
       "Scanned but never logged in to — the scan could not see inside these.", "kpi",
       "SELECT COUNT(*) AS \"Blind hosts\" FROM (SELECT v.asset_uuid FROM vulns v WHERE v.plugin_id IN "
       f"({_SCANNED}) AND $__scope(v.asset_uuid) GROUP BY v.asset_uuid "
       "HAVING MAX(CASE WHEN $__cred(v) THEN 1 ELSE 0 END)=0)",
       _ASSET_DRILL.format(w="a.uuid IN (SELECT v.asset_uuid FROM vulns v WHERE v.plugin_id IN "
                              f"({_SCANNED}) AND $__scope(v.asset_uuid) GROUP BY v.asset_uuid "
                              "HAVING MAX(CASE WHEN $__cred(v) THEN 1 ELSE 0 END)=0)"), w=2),
    _p("Program", "sev_mix", "Open findings by severity", "Open, non-info findings split by severity.", "donut",
       f"SELECT {_SEV} AS severity, COUNT(*) AS findings FROM vulns v WHERE $__open(v) AND "
       "lower(v.severity) IN ('critical','high','medium','low') AND $__scope(v.asset_uuid) "
       "GROUP BY lower(v.severity) ORDER BY CASE lower(v.severity) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
       "WHEN 'medium' THEN 3 ELSE 4 END", w=4, h=3, label_col="severity", value_col="findings"),
    _p("Program", "ownership_split", "Ownership coverage", "Owned vs ownerless assets in scope.", "pie",
       "SELECT CASE WHEN a.uuid IN (SELECT asset_uuid FROM tags WHERE tag_key='Owner') THEN 'Owned' "
       "ELSE 'Ownerless' END AS coverage, COUNT(*) AS assets FROM assets a WHERE $__scope(a.uuid) "
       "GROUP BY coverage", w=4, h=3, label_col="coverage", value_col="assets"),
    # ── Exposure ────────────────────────────────────────────────────────────────────────────
    _p("Exposure", "vpr_bands", "Open findings by VPR band", "Priority mix by Vulnerability Priority Rating.",
       "bar",
       "SELECT CASE WHEN v.score>=9 THEN '9.0-10 Critical' WHEN v.score>=7 THEN '7.0-8.9 High' WHEN v.score>=4 "
       "THEN '4.0-6.9 Medium' WHEN v.score>0 THEN '0.1-3.9 Low' ELSE 'Unscored' END AS vpr_band, "
       "COUNT(*) AS findings FROM vulns v WHERE $__open(v) AND $__scope(v.asset_uuid) GROUP BY vpr_band "
       "ORDER BY CASE WHEN vpr_band='Unscored' THEN 1 ELSE 0 END, vpr_band DESC", w=4, h=3, label_col="vpr_band", value_col="findings"),
    _p("Exposure", "top_assets", "Top 15 assets by open findings", "Where the open findings concentrate.", "bar",
       "SELECT COALESCE(NULLIF(v.asset_hostname,''), v.asset_ip) AS host, COUNT(*) AS findings FROM vulns v "
       "WHERE $__open(v) AND $__scope(v.asset_uuid) GROUP BY v.asset_uuid ORDER BY findings DESC LIMIT 15",
       w=6, h=4, label_col="host", value_col="findings"),
    _p("Exposure", "fix_leverage", "Fix leverage — top plugins",
       "Critical / high plugins by the assets each one clears — root-cause remediation order.", "bar",
       "SELECT v.plugin_name, COUNT(DISTINCT v.asset_uuid) AS assets FROM vulns v WHERE $__open(v) AND "
       "lower(v.severity) IN ('critical','high') AND $__scope(v.asset_uuid) GROUP BY v.plugin_id "
       "ORDER BY assets DESC LIMIT 15", w=6, h=4, label_col="plugin_name", value_col="assets"),
    _p("Exposure", "exploitable", "Exploitable open findings", "Open findings with a public exploit.", "kpi",
       "SELECT COUNT(*) AS \"Exploitable findings\" FROM vulns v WHERE $__open(v) AND lower(v.exploit)='true' "
       "AND $__scope(v.asset_uuid)",
       _FIND_DRILL.format(w="$__open(v) AND lower(v.exploit)='true' AND $__scope(v.asset_uuid)"), w=2),
    _p("Exposure", "vpr_peak", "Average / peak VPR", "How dangerous the open backlog is.", "kpi",
       "SELECT ROUND(AVG(v.score),1) AS \"Avg VPR\", MAX(v.score) AS \"Max VPR\" FROM vulns v WHERE $__open(v) "
       "AND v.score>0 AND $__scope(v.asset_uuid)"),
    _p("Exposure", "kev_plugins", "KEV plugins by assets", "The KEV findings to fix, by the assets they touch.",
       "bar",
       "SELECT v.plugin_name, COUNT(DISTINCT v.asset_uuid) AS assets FROM vulns v WHERE $__open(v) AND $__kev(v) "
       "AND $__scope(v.asset_uuid) GROUP BY v.plugin_id ORDER BY assets DESC LIMIT 15", w=6, h=4,
       label_col="plugin_name", value_col="assets"),
    # ── Ownership ───────────────────────────────────────────────────────────────────────────
    _p("Ownership", "assets_per_owner", "Assets per owner", "Owner workload — spot the bottleneck.", "bar",
       "SELECT t.tag_value AS owner, COUNT(DISTINCT t.asset_uuid) AS assets FROM tags t WHERE t.tag_key='Owner' "
       "AND $__scope(t.asset_uuid) GROUP BY t.tag_value ORDER BY assets DESC LIMIT 15", w=6, h=4,
       label_col="owner", value_col="assets"),
    _p("Ownership", "owner_open_crit", "Open critical / high by owner",
       "Who carries the urgent backlog (ownerless assets shown as “No owner”).", "bar",
       "SELECT COALESCE((SELECT t.tag_value FROM tags t WHERE t.tag_key='Owner' AND t.asset_uuid=v.asset_uuid "
       "LIMIT 1),'No owner') AS owner, COUNT(*) AS findings FROM vulns v WHERE $__open(v) AND "
       "lower(v.severity) IN ('critical','high') AND $__scope(v.asset_uuid) GROUP BY owner "
       "ORDER BY findings DESC LIMIT 15", w=6, h=4, label_col="owner", value_col="findings"),
    # ── Hygiene & lifecycle ─────────────────────────────────────────────────────────────────
    _p("Hygiene", "os_family", "Assets by OS family", "Windows / Linux / macOS / Other.", "bar",
       "SELECT CASE WHEN a.operating_system LIKE '%Windows%' THEN 'Windows' WHEN a.operating_system LIKE '%Linux%' "
       "OR a.operating_system LIKE '%CentOS%' OR a.operating_system LIKE '%Ubuntu%' OR a.operating_system LIKE "
       "'%Red Hat%' OR a.operating_system LIKE '%Debian%' THEN 'Linux' WHEN a.operating_system LIKE '%Mac%' THEN "
       "'macOS' ELSE 'Other' END AS os_family, COUNT(*) AS assets FROM assets a WHERE $__scope(a.uuid) "
       "GROUP BY os_family ORDER BY assets DESC", w=4, h=3, label_col="os_family", value_col="assets"),
    _p("Hygiene", "eol_products", "Unsupported / EOL products", "End-of-life software by plugin.", "bar",
       "SELECT v.plugin_name, COUNT(DISTINCT v.asset_uuid) AS assets FROM vulns v WHERE $__open(v) AND " + _EOL +
       " AND $__scope(v.asset_uuid) GROUP BY v.plugin_id ORDER BY assets DESC LIMIT 15", w=6, h=4,
       label_col="plugin_name", value_col="assets"),
    _p("Hygiene", "stale_assets", "Stale assets (> 30 days)", "Assets not seen in the last 30 days.", "kpi",
       "SELECT COUNT(*) AS \"Stale assets\" FROM assets a WHERE substr(a.last_found,1,10) < date('now','-30 day') "
       "AND $__scope(a.uuid)",
       _ASSET_DRILL.format(w="substr(a.last_found,1,10) < date('now','-30 day') AND $__scope(a.uuid)"), w=2),
    _p("Hygiene", "cert_expiry", "Certificates expiring", "Expired and expiring in 30 / 60 / 90 days.", "column",
       "SELECT bucket, certs FROM (SELECT CASE WHEN d < date('now') THEN 'Expired' WHEN d < date('now','+30 day') "
       "THEN '≤ 30 days' WHEN d < date('now','+60 day') THEN '≤ 60 days' WHEN d < date('now','+90 day') THEN "
       "'≤ 90 days' END AS bucket, COUNT(*) AS certs, MIN(d) AS o FROM (SELECT $__certdate(c.not_valid_after) AS d "
       "FROM certs c WHERE $__scope(c.asset_uuid)) WHERE d IS NOT NULL AND d < date('now','+90 day') "
       "GROUP BY bucket) ORDER BY o", w=4, h=3, label_col="bucket", value_col="certs",
       drill=_CERT_DRILL.format(w="$__certdate(c.not_valid_after) < date('now','+90 day') AND "
                                  "$__scope(c.asset_uuid)")),
    _p("Hygiene", "weak_keys", "Weak-key certificates", "Certificates with an RSA key under 2048 bits.", "kpi",
       "SELECT COUNT(*) AS \"Weak-key certs\" FROM certs c WHERE c.key_length IS NOT NULL AND "
       "CAST(c.key_length AS INTEGER) BETWEEN 1 AND 2047 AND $__scope(c.asset_uuid)",
       _CERT_DRILL.format(w="c.key_length IS NOT NULL AND CAST(c.key_length AS INTEGER) BETWEEN 1 AND 2047 AND "
                            "$__scope(c.asset_uuid)"), w=2),
    _p("Hygiene", "cert_sig", "Certificate signature algorithms", "SHA-1 vs SHA-256 etc. across your certs.",
       "bar",
       "SELECT COALESCE(NULLIF(c.signature_algorithm,''),'(unknown)') AS algorithm, COUNT(*) AS certs FROM certs c "
       "WHERE $__scope(c.asset_uuid) GROUP BY algorithm ORDER BY certs DESC", w=4, h=3, label_col="algorithm",
       value_col="certs"),
]

# ── Ownership analytics: the hard joins (routes × tags × device type) on the
# semantic tables $__route_assets() / $__path_assets() / $__asset_facts() — also the worked
# examples the ✨ Ask AI prompt learns from (core/dashai) ───────────────────────────────────
_RD = ("WITH rd AS (SELECT af.device_type AS dt, ra.route, MIN(ra.owned) AS all_owned FROM $__route_assets() ra "
       "JOIN $__asset_facts() af ON af.asset_uuid=ra.asset_uuid WHERE $__scope(ra.asset_uuid) GROUP BY dt, ra.route) ")
ANALYTICS = [
    _p("Ownership analytics", "routes_by_device_type", "Routes by device type — owned vs unowned",
       "For each device type: the routes found on it, how many are owned on every asset of that type, and "
       "how many still are not.", "grouped",
       _RD + "SELECT dt AS device_type, COUNT(*) AS \"Total routes\", SUM(all_owned) AS \"Owned routes\", "
       "COUNT(*)-SUM(all_owned) AS \"Unowned routes\" FROM rd GROUP BY dt ORDER BY \"Unowned routes\" DESC, dt",
       "SELECT af.device_type, ra.route, af.host, ra.owned, ra.decided, ra.owner, ra.asset_uuid FROM $__route_assets() ra "
       "JOIN $__asset_facts() af ON af.asset_uuid=ra.asset_uuid WHERE ra.owned=0 AND $__scope(ra.asset_uuid) "
       "ORDER BY af.device_type, ra.route, af.host", w=8, h=4, label_col="device_type"),
    _p("Ownership analytics", "route_coverage", "Route coverage",
       "Share of route × asset pairs whose route is owned on that asset (Exposure Routes' Owner-tag rule).", "gauge",
       "SELECT 'Owned %' AS metric, COALESCE(ROUND(100.0*SUM(ra.owned)/NULLIF(COUNT(*),0),1),0) AS pct "
       "FROM $__route_assets() ra WHERE $__scope(ra.asset_uuid)", w=4, h=4, label_col="metric", value_col="pct"),
    _p("Ownership analytics", "routes_most_unowned", "Routes with the most unowned assets",
       "Per route: assets owned, decided (Ignored / Accepted / Mitigated) and still unowned.", "stacked",
       "SELECT ra.route, SUM(ra.owned) AS \"Owned\", SUM(CASE WHEN ra.owned=0 AND ra.decided=1 THEN 1 ELSE 0 END) "
       "AS \"Decided\", SUM(CASE WHEN ra.owned=0 AND ra.decided=0 THEN 1 ELSE 0 END) AS \"Unowned\" "
       "FROM $__route_assets() ra WHERE $__scope(ra.asset_uuid) GROUP BY ra.route ORDER BY \"Unowned\" DESC LIMIT 15",
       w=6, h=4, label_col="route"),
    _p("Ownership analytics", "owner_workload", "Owner workload across routes",
       "Assets each owner is accountable for through their route tags.", "bar",
       "SELECT ra.owner, COUNT(DISTINCT ra.asset_uuid) AS assets FROM "
       "$__route_assets() ra WHERE ra.owned=1 AND $__scope(ra.asset_uuid) GROUP BY ra.owner ORDER BY assets DESC LIMIT 15",
       w=6, h=4, label_col="owner", value_col="assets"),
    _p("Ownership analytics", "routes_by_tier", "Route ownership by Business Tier",
       "Owned vs unowned route × asset pairs for each Business Tier tag value.", "grouped",
       "SELECT COALESCE($__tag(ra.asset_uuid, 'Business Tier'),'(no tier)') AS tier, SUM(ra.owned) AS \"Owned\", "
       "SUM(1-ra.owned) AS \"Unowned\" FROM $__route_assets() ra WHERE $__scope(ra.asset_uuid) GROUP BY tier "
       "ORDER BY \"Unowned\" DESC", w=6, h=4, label_col="tier"),
    _p("Ownership analytics", "paths_by_os", "Path ownership by OS family",
       "Vulnerable paths × assets, owned vs unowned, by operating-system family.", "grouped",
       "SELECT af.os_family, SUM(pa.owned) AS \"Owned\", SUM(1-pa.owned) AS \"Unowned\" FROM $__path_assets() pa "
       "JOIN $__asset_facts() af ON af.asset_uuid=pa.asset_uuid WHERE $__scope(pa.asset_uuid) GROUP BY af.os_family "
       "ORDER BY \"Unowned\" DESC", w=6, h=4, label_col="os_family"),
    _p("Ownership analytics", "crown_unowned_route", "Crown jewels on an unowned route",
       "Crown jewels ({CROWN}) where at least one route is neither owned nor decided.", "kpi",
       "SELECT COUNT(DISTINCT ra.asset_uuid) AS \"Crown jewels\" FROM $__route_assets() ra JOIN $__asset_facts() af "
       "ON af.asset_uuid=ra.asset_uuid WHERE af.crown=1 AND ra.owned=0 AND ra.decided=0 AND $__scope(ra.asset_uuid)",
       "SELECT af.host, af.ip, af.acr, ra.route, ra.route_type, ra.asset_uuid FROM $__route_assets() ra JOIN "
       "$__asset_facts() af ON af.asset_uuid=ra.asset_uuid WHERE af.crown=1 AND ra.owned=0 AND ra.decided=0 AND "
       "$__scope(ra.asset_uuid) ORDER BY af.acr DESC, af.host", w=3, h=2),
    _p("Ownership analytics", "unowned_heatmap", "Unowned assets: device type × route type",
       "Where unowned route exposure concentrates — device type against route type (OS / application…).", "heatmap",
       "SELECT af.device_type, COALESCE(ra.route_type,'(none)') AS route_type, COUNT(DISTINCT ra.asset_uuid) AS assets "
       "FROM $__route_assets() ra JOIN $__asset_facts() af ON af.asset_uuid=ra.asset_uuid WHERE ra.owned=0 AND "
       "ra.decided=0 AND $__scope(ra.asset_uuid) GROUP BY af.device_type, route_type ORDER BY af.device_type",
       w=6, h=4, label_col="device_type", value_col="assets"),
    _p("Ownership analytics", "kev_unowned_routes", "Unowned route assets with a KEV",
       "Per route: unowned assets that also carry an open CISA KEV finding — no owner and known-exploited.", "bar",
       "SELECT ra.route, COUNT(DISTINCT ra.asset_uuid) AS assets FROM $__route_assets() ra WHERE ra.owned=0 AND "
       "ra.decided=0 AND $__scope(ra.asset_uuid) AND ra.asset_uuid IN (SELECT v.asset_uuid FROM vulns v WHERE "
       "$__open(v) AND $__kev(v)) GROUP BY ra.route ORDER BY assets DESC LIMIT 15", w=6, h=4,
       label_col="route", value_col="assets"),
]
PRESETS += ANALYTICS

TEXT = {"ref": "text.heading", "title": "Section heading", "note": "A full-width heading that splits a board "
        "into sections (Triage · Ops · Board · Audit…).", "group": "Layout", "viz": "text", "sql": "",
        "w": 12, "h": 1, "source": {"kind": "layout", "name": "Layout"}}


def _manifest_widgets():
    """Specialist widgets declared in agents/<id>/manifest.json → "widgets"."""
    from core import discovery
    out = []
    d0 = discovery.AGENTS_DIR
    for name in sorted(os.listdir(d0)) if os.path.isdir(d0) else []:
        mf = os.path.join(d0, name, "manifest.json")
        try:
            with open(mf, encoding="utf-8") as f:
                m = json.load(f)
        except Exception:
            continue
        ws = m.get("widgets")
        if not isinstance(ws, list):
            continue
        aid = m.get("id", name)
        for w in ws:
            if not isinstance(w, dict) or not w.get("id") or not (w.get("sql") or isinstance(w.get("snapshot"), dict)):
                continue
            d = {"ref": f"{aid}.{w['id']}", "title": w.get("title") or w["id"], "note": w.get("note", ""),
                 "group": m.get("name", aid), "viz": w.get("viz") if w.get("viz") in VIZ else "table",
                 "sql": w.get("sql") or "", "w": int(w.get("w") or 3), "h": int(w.get("h") or 2),
                 "source": {"kind": "specialist", "agent": aid, "name": m.get("name", aid),
                            "page": f"/agents/{aid}/page.html"}}
            if isinstance(w.get("snapshot"), dict):
                # a number read from the specialist's own last run (its page cache) —
                # the specialist's logic, not a re-implementation in SQL
                d["snapshot"] = {"call": str(w["snapshot"].get("call") or "run"),
                                 "path": w["snapshot"].get("path"), "paths": w["snapshot"].get("paths"),
                                 "label": w["snapshot"].get("label") or d["title"]}
            for k in ("drill", "label_col", "value_col", "lineage"):
                if w.get(k):
                    d[k] = w[k]
            out.append(d)
    return out


_SPEC = {"t": None, "v": []}


def specialists():
    """Manifest widgets, re-read when any manifest changes (mtime sum)."""
    from core import discovery
    try:
        sig = sum(os.path.getmtime(os.path.join(discovery.AGENTS_DIR, n, "manifest.json"))
                  for n in os.listdir(discovery.AGENTS_DIR)
                  if os.path.exists(os.path.join(discovery.AGENTS_DIR, n, "manifest.json")))
    except Exception:
        sig = None
    if _SPEC["t"] != sig or sig is None:
        _SPEC["v"], _SPEC["t"] = _manifest_widgets(), sig
    return _SPEC["v"]


def builtin():
    """{ref: definition} for presets + specialists + layout widgets."""
    out = {d["ref"]: d for d in PRESETS}
    for d in specialists():
        out[d["ref"]] = d
    out[TEXT["ref"]] = TEXT
    from core import crown                      # titles / notes carry the live crown-jewel line
    return crown.fill(out)


def summary(d):
    """What the library tray lists for a definition (no SQL — the SQL panel fetches it)."""
    out = {k: d.get(k) for k in ("ref", "title", "note", "group", "viz", "w", "h", "source", "review")
           if d.get(k) is not None}
    out["scoped"] = dashmetrics.uses_scope(d.get("sql")) or d.get("viz") == "text" or bool(d.get("snapshot"))
    if d.get("snapshot"):
        out["snapshot"] = True
    return out


# ── SQL validation (same rules as Explore's run_sql — the engine guard is the real backstop) ──
def check_sql(sql):
    """(clean_sql, None) or (None, error). Single read-only SELECT/WITH; macros allowed."""
    try:
        from agents.explore import api as xapi
    except Exception:                                  # pragma: no cover
        return None, "SQL checks unavailable"
    s = (sql or "").strip().rstrip(";").strip()
    if not s:
        return None, "the widget has no SQL"
    if len(s) > 20000:
        return None, "SQL is too long (20,000 characters max)"
    if not re.match(r"^(select|with)\b", s, re.I):
        return None, "only SELECT / WITH queries are allowed"
    bare = xapi._bare(s)
    if ";" in bare:
        return None, "only a single statement is allowed"
    if xapi._SQL_BANNED.search(bare):
        return None, "read-only queries only (no writes / DDL / file access)"
    if "?" in bare:
        return None, "use literals, not ? parameters"
    return s, None
