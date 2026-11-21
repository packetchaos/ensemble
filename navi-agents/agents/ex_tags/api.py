"""Tag Explorer — read-only navi.db search over the tags table (paginated).

`search` → one row per tag (tag_key : tag_value) with a DISTINCT asset count.
`assets` → drill-down: the assets carrying one tag, joined to the assets table
           (hostname, IP, OS, ACR/AES, platform url) so you can see exactly
           which assets are in each tag.
"""
from core import search


def run(p):
    try:
        res = search.tags((p.get("q") or "").strip(), int(p.get("offset") or 0), p.get("limit"))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200


def assets(p):
    key = (p.get("key") or "").strip()
    value = (p.get("value") or "").strip()
    if not key:
        return {"ok": False, "error": "key (tag category) required"}, 400
    try:
        res = search.tag_assets(key, value, (p.get("q") or "").strip(),
                                int(p.get("offset") or 0), p.get("limit"))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200


def export(p):
    """Build 525: every row as CSV — the tag list ({q}), or one tag's assets ({key, value, q}).
    ≤ 5,000 at once; more → a background job (`navi export query` over the explorer's own SQL)."""
    from core import exports
    q = (p.get("q") or "").strip()
    key = (p.get("key") or "").strip()
    if key:
        sql, args = search.export_sql(search.tag_assets, key, (p.get("value") or "").strip(), q, 0, None)
        name = "tag-assets-" + key + "-" + (p.get("value") or "")
    else:
        sql, args = search.export_sql(search.tags, q, 0, None)
        name = "tags-explorer"
    if not sql:
        return {"ok": False, "error": "nothing to export"}, 200
    try:
        return exports.start_sql(name, sql, args, agent="ex_tags", trusted=True), 200
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200


ACTIONS = {"search": run, "assets": assets, "export": export}
