"""Plugin Explorer — read-only navi.db search (paginated)."""
from core import search

def run(p):
    try:
        res = search.plugins((p.get("q") or "").strip(), int(p.get("offset") or 0), p.get("limit"))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200

def export(p):
    """Build 525: EVERY row of this search as CSV (the table's ⤓ CSV ▾ → every row) — at once up to
    5,000, past that a background job running `navi export query` over the explorer's own SQL."""
    from core import exports
    sql, args = search.export_sql(search.plugins, (p.get("q") or "").strip(), 0, None)
    if not sql:
        return {"ok": False, "error": "nothing to export"}, 200
    try:
        return exports.start_sql("plugins-explorer", sql, args, agent="ex_plugins", trusted=True), 200
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200


ACTIONS = {"export": export, "search": run}
