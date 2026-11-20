"""✨ Ask AI for a dashboard widget (build 511).

Plain English in ("unowned routes by device type"), a widget definition out: title, chart type,
label/value columns and ONE read-only SELECT over navi.db written on the shared building blocks
of core/dashmetrics — $__scope, $__open, $__kev, $__crown, $__tag and the semantic tables
$__route_assets() / $__path_assets() / $__asset_facts() that hold the hard joins (route ownership
from Owner tags, device type from three sources…). The model never writes those joins itself; it
composes them, so a question that needs "tags and crazy joins" becomes a short GROUP BY.

The model only PROPOSES. The SQL is checked (single read-only SELECT, known macros), expanded
and test-run read-only here; a failing query goes back to the model once with the error. The
person still reads it in the editor and saves it — nothing is added to a board on its own.
"""
import json
import time

from core import dashmetrics, db, widgets

PREVIEW_ROWS = 200

SYSTEM = """You write ONE read-only SQLite query for a dashboard widget over navi.db (a local cache of
Tenable Vulnerability Management). Return ONLY a JSON object:
{"title": "<short widget title>", "viz": "<chart>", "label_col": "<category column or null>",
 "value_col": "<main numeric column or null>", "note": "<one sentence: what the widget shows and how it counts>",
 "sql": "<the query>"}

Chart types (viz): kpi (one row of numbers), bar (one category + one number), grouped (one category
+ 2-4 numbers side by side, e.g. total / owned / unowned), stacked (one category + parts of a whole),
column, pie / donut (few categories, one number), line / area (a date category), heatmap (long format:
row category, column category, number), gauge (one percentage 0-100 with a label column), table.

Rules:
- ONE SELECT (a WITH … SELECT is fine). No writes, no PRAGMA, no ATTACH, no ? parameters.
- ALWAYS filter by the board's tag scope with $__scope(<asset uuid column>) so the widget follows the
  board's tag filter (e.g. WHERE $__scope(v.asset_uuid), $__scope(a.uuid), $__scope(ra.asset_uuid)).
- Prefer these building blocks over hand-written joins — they encode the project's definitions:
    $__open(v)          vulns alias v is an OPEN (open/reopened), non-info finding. Use it for any "finding" count.
    $__kev(v)           the finding is a CISA Known Exploited Vulnerability.
    $__cred(v)          the row proves a credentialed scan (scan-coverage questions).
    $__crown(a)         assets alias a is a crown jewel (ACR >= 9).
    $__tag(col, 'Cat')  an asset's value for tag category 'Cat' (NULL when untagged) — any tag dimension:
                        Business Tier, Environment, Owner, a customer category… GROUP BY it for "by <tag>".
    $__certdate(c.not_valid_after)  a certificate date as YYYY-MM-DD.
    $__route_assets() ra   TABLE: route_id, route (exposure route name), route_type (Operating System /
                        Application…), asset_uuid, owned (1 when that asset carries the route's Owner tag),
                        decided (1 when Ignored/Accepted/Mitigated), owner (the owner's name or NULL).
                        One row per route × affected asset. "Unowned" = owned=0 (and decided=0 when the
                        question means "still needs an owner").
    $__path_assets() pa    TABLE: path, asset_uuid, owned, decided, owner — the same for vulnerable paths.
    $__asset_facts() af    TABLE: asset_uuid, host, ip, os_family (Windows/Linux/macOS/Other/Unknown),
                        device_type (Device Type tag → Asset Inventory → Nessus 54615 → 'Unclassified'),
                        acr, crown (1/0), has_owner_tag (1/0). JOIN it for device type / OS / crown questions.
- A "route counts as owned for a group" only when every one of its assets in that group is owned:
  aggregate MIN(ra.owned) per (group, route) in a CTE, then count.
- Name output columns for people ("Owned routes", "Unowned routes"); quote names with spaces in "double quotes".
- Order the rows usefully and LIMIT long category lists (15-25).
- Use only tables/columns in the schema below or the building blocks above.

"""


def _examples():
    pick = [d for d in widgets.ANALYTICS] + [widgets.builtin()[r] for r in (
        "preset.kev_assets", "preset.owner_open_crit", "preset.sev_mix", "preset.cred_coverage")]
    out = []
    for d in pick:
        out.append(json.dumps({"request": d["title"], "answer": {
            "title": d["title"], "viz": d["viz"], "label_col": d.get("label_col"), "value_col": d.get("value_col"),
            "note": d.get("note", ""), "sql": d["sql"]}}, ensure_ascii=False))
    return "Worked examples (request → answer):\n" + "\n".join(out) + "\n\n"


def _schema(path=None):
    try:
        from core import dashboard
        return dashboard.schema_text(path)
    except Exception as e:                    # pragma: no cover
        return f"(schema unavailable: {e})"


def _ask_model(prompt, extra=""):
    from core import llm
    text = llm._messages(SYSTEM + _examples() + _schema(),
                         "Request: " + prompt + (("\n\n" + extra) if extra else "")
                         + "\n\nReturn ONLY the JSON object.", max_tokens=1800, timeout=90)
    return llm._extract_json(text)


def _norm(spec):
    viz = spec.get("viz") if spec.get("viz") in widgets.VIZ and spec.get("viz") != "text" else "table"
    return {"title": str(spec.get("title") or "AI widget")[:120], "viz": viz,
            "label_col": (spec.get("label_col") or None), "value_col": (spec.get("value_col") or None),
            "note": str(spec.get("note") or "")[:400], "sql": str(spec.get("sql") or "").strip()}


def preview(sql, scope=None, rows=PREVIEW_ROWS):
    """Check + expand + run read-only (first `rows` rows). Raises ValueError / sqlite errors."""
    clean, err = widgets.check_sql(sql)
    if err:
        raise ValueError(err)
    full, disp, info = dashmetrics.expand(clean, scope)
    t0 = time.time()
    out, more = [], False
    it = db.user_iter(full)
    try:
        for r in it:
            if len(out) >= rows:
                more = True
                break
            out.append(r)
    finally:
        it.close()
    return {"sql": clean, "sql_expanded": disp, "rows": out, "columns": list(out[0].keys()) if out else [],
            "truncated": more, "ms": round((time.time() - t0) * 1000), "defs": info["defs"],
            "scoped": info["scoped"], "notes": info["notes"]}


def ask(prompt, scope=None):
    """{ok, spec, preview} | {ok:False, error, needs_key?, spec?}."""
    prompt = (prompt or "").strip()
    if not prompt:
        return {"ok": False, "error": "describe the widget you want"}
    if len(prompt) > 2000:
        return {"ok": False, "error": "keep the request under 2,000 characters"}
    from core import llm
    if not llm.available():
        return {"ok": False, "needs_key": True,
                "error": "✨ Ask AI needs a model — set one up in Settings → AI model. " + (llm.why_unavailable() or "")}
    spec, last_err = None, ""
    for attempt in range(2):
        extra = ""
        if attempt and spec:
            extra = ("Your previous answer failed. SQL:\n" + spec.get("sql", "") + "\nError: " + last_err +
                     "\nFix it (keep the same intent). Use only the schema and building blocks given.")
        try:
            spec = _norm(_ask_model(prompt, extra))
        except Exception as e:
            return {"ok": False, "error": f"the model call failed ({e})"}
        try:
            pv = preview(spec["sql"], scope)
        except Exception as e:
            last_err = str(e)
            continue
        if not pv["scoped"]:
            pv["notes"] = list(pv["notes"]) + ["This query has no $__scope(…) — it will ignore the board's tag filter."]
        cols = pv["columns"]
        if spec["label_col"] not in cols:
            spec["label_col"] = None
        if spec["value_col"] not in cols:
            spec["value_col"] = None
        return {"ok": True, "spec": spec, "preview": pv, "attempts": attempt + 1}
    return {"ok": False, "error": "the model's query did not run: " + last_err, "spec": spec}


def explain_macros():
    return dashmetrics.catalog()

