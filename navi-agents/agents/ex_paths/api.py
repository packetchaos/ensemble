"""Path Explorer — read-only navi.db search (paginated) + tag-by-path."""
from core import search, navi_cli, db
from core.gates import confirmed


def run(p):
    try:
        res = search.paths((p.get("q") or "").strip(), int(p.get("offset") or 0), p.get("limit"))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200


def tag(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    path = (p.get("path") or "").strip()
    value = (p.get("value") or "").strip()
    if not path or not value:
        return {"ok": False, "error": "path and value required"}, 400
    # tag every asset that carries this exact path (navi tag-by-query)
    q = "SELECT asset_uuid FROM vuln_paths WHERE path='" + path.replace("'", "''") + "'"
    r = navi_cli.tag(p.get("category", "Path"), value, query=q, remove=False)
    return {"ok": True, "result": r, "writes_enabled": navi_cli.writes_enabled()}, 200


def count(p):
    """Read-only: how many assets a tag-by-path would hit — shown in the page's confirm()."""
    path = (p.get("path") or "").strip()
    if not path:
        return {"ok": False, "error": "path required"}, 400
    try:
        n = db.scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vuln_paths WHERE path=?", (path,))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "assets": int(n or 0)}, 200


def export(p):
    """Build 525: EVERY row of this search as CSV (the table's ⤓ CSV ▾ → every row) — at once up to
    5,000, past that a background job running `navi export query` over the explorer's own SQL."""
    from core import exports
    sql, args = search.export_sql(search.paths, (p.get("q") or "").strip(), 0, None)
    if not sql:
        return {"ok": False, "error": "nothing to export"}, 200
    try:
        return exports.start_sql("paths-explorer", sql, args, agent="ex_paths", trusted=True), 200
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200


ACTIONS = {"export": export, "search": run, "tag": tag, "count": count}
