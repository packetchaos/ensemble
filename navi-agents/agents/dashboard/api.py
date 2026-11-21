"""Dashboard Builder — self-contained HTTP actions.

`build` — take a plain-English `prompt`, ask the model for ONE read-only SQL
          SELECT over navi.db (core.dashboard validates + runs it read-only), and
          return rows + the chosen visualization for the UI to render.

Read-only end to end: navi.db is opened in SQLite read-only mode and the SQL is
guarded to a single SELECT. This agent never writes anything.
"""
from core import dashboard

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import DashboardAgent
        AGENT = DashboardAgent()
    return AGENT


def build(p):
    prompt = (p.get("prompt") or "").strip()
    if not prompt:
        return {"ok": False, "error": "describe the dashboard you want to see"}, 200
    try:
        res = dashboard.build(prompt)
    except Exception as e:
        return {"ok": False, "error": f"dashboard build failed: {e}"}, 200
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error", "could not build"),
                "needs_key": res.get("needs_key", False), "sql": res.get("sql")}, 200
    return {"ok": True, "agent": _agent().meta(), "result": res}, 200


ACTIONS = {"build": build}


# ── build 509: the Dashboards app (web/dashboards.html) — server-side boards ─────────────────
# Boards, the widget library and the per-widget cache live in core/boards (app state, never
# navi.db). Nothing here runs widget SQL except widget_run / widget_data, which the page sends
# only on an explicit ▶ Run / ↗ Open the data.
from core import boards as _boards, dashmetrics as _dm, tagscope as _ts


def _err(e, code=400):
    return {"ok": False, "error": str(e)}, code


def _board(p):
    b = _boards.get(p.get("board") or p.get("id"))
    if not b:
        raise LookupError("no such board")
    return b


def _defs(b):
    """The definitions a board's widgets point at (title, viz, columns, source) — no SQL."""
    out = {}
    for w in (b or {}).get("widgets") or []:
        if w["ref"] in out:
            continue
        d = _boards.definition(w["ref"])
        if d:
            s = _boards.widgets.summary(d)
            s.update({k: d.get(k) for k in ("label_col", "value_col") if d.get(k)})
            s["drill"] = bool(d.get("drill"))
            out[w["ref"]] = s
        else:
            out[w["ref"]] = {"ref": w["ref"], "title": "Missing widget", "missing": True, "viz": "text"}
    return out


def boards_list(p):
    _boards.ensure_daily()
    return {"ok": True, "boards": _boards.list_boards(), "templates": [
        {"id": k, "name": v["name"]} for k, v in _boards.templates().items()]}, 200


def board_get(p):
    b = _boards.get(p.get("id"))
    if not b:
        return _err("no such board", 404)
    return {"ok": True, "board": b, "defs": _defs(b), "scope_assets": _dm.scope_count(b.get("scope"))}, 200


def board_save(p):
    try:
        b, err = _boards.save(p.get("board") or {})
    except ValueError as e:
        return _err(e)
    if err == "conflict":
        return {"ok": False, "conflict": True, "error": "this board changed in another tab — reload it",
                "board": _boards.get((p.get("board") or {}).get("id"))}, 409
    if err:
        return _err(err, 404)
    return {"ok": True, "board": b, "defs": _defs(b), "scope_assets": _dm.scope_count(b.get("scope"))}, 200


def board_new(p):
    try:
        b = _boards.create(name=(p.get("name") or None), template=p.get("template") or "blank",
                           copy_of=p.get("copy_of") or None)
    except ValueError as e:
        return _err(e)
    return {"ok": True, "board": b}, 200


def board_delete(p):
    return ({"ok": True}, 200) if _boards.delete(p.get("id")) else _err("no such board", 404)


def board_default(p):
    return ({"ok": True}, 200) if _boards.set_default(p.get("id")) else _err("no such board", 404)


def board_export(p):
    doc = _boards.export(p.get("id"))
    return ({"ok": True, "doc": doc}, 200) if doc else _err("no such board", 404)


def board_import(p):
    origin = "browser" if p.get("origin") == "browser" else "file"
    try:
        b = _boards.import_doc(p.get("doc"), origin=origin)
    except ValueError as e:
        return _err(e)
    return {"ok": True, "board": b}, 200


def library(p):
    return {"ok": True, "groups": _boards.library(), "catalog": _dm.catalog()}, 200


def widget_cached(p):
    try:
        b = _board(p)
    except LookupError as e:
        return _err(e, 404)
    return {"ok": True, "results": _boards.cached(b), "db_fp": _dm.fingerprint()}, 200


def widget_run(p):
    try:
        b = _board(p)
        res = _boards.run_widget(b, str(p.get("iid") or ""), refresh=bool(p.get("refresh")))
    except PermissionError as e:
        return {"ok": False, "review": True, "error": str(e)}, 200
    except (LookupError, ValueError) as e:
        return _err(e)
    except Exception as e:                       # SQL errors, budget, cancelled → the widget shows it
        from core import db
        if isinstance(e, db.QueryTimeout):
            body = db.budget_payload(e)
            body["ok"] = False
            return body, 200
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200


def widget_sql(p):
    try:
        return {"ok": True, **_boards.sql_info(_board(p), str(p.get("iid") or ""))}, 200
    except (LookupError, ValueError) as e:
        return _err(e)


def widget_export(p):
    """Build 525: every row of a widget's data as CSV (≤ 5,000 at once, more as a background job)."""
    try:
        return _boards.export_widget(_board(p), str(p.get("iid") or "")), 200
    except PermissionError as e:
        return {"ok": False, "review": True, "error": str(e)}, 200
    except (LookupError, ValueError, TypeError) as e:
        return _err(e)


def widget_data(p):
    try:
        out = _boards.data(_board(p), str(p.get("iid") or ""), page=p.get("page") or 0, size=p.get("size") or 50)
    except PermissionError as e:
        return {"ok": False, "review": True, "error": str(e)}, 200
    except (LookupError, ValueError, TypeError) as e:
        return _err(e)
    except Exception as e:
        from core import db
        if isinstance(e, db.QueryTimeout):
            body = db.budget_payload(e)
            body["ok"] = False
            return body, 200
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, **out}, 200


def sql_save(p):
    try:
        ref = _boards.save_sql_widget(p.get("widget") or {}, origin="user")
    except ValueError as e:
        return _err(e)
    return {"ok": True, "ref": ref, "definition": _boards.definition(ref)}, 200


def sql_approve(p):
    ref = str(p.get("ref") or "")
    return ({"ok": True}, 200) if _boards.approve_sql(ref) else _err("no such SQL widget", 404)


def sql_delete(p):
    ref = str(p.get("ref") or "")
    return ({"ok": True}, 200) if _boards.delete_sql_widget(ref) else _err("no such SQL widget", 404)


def sql_get(p):
    d = _boards.definition(str(p.get("ref") or ""))
    if not d or not str(d.get("ref", "")).startswith("sql."):
        return _err("no such SQL widget", 404)
    return {"ok": True, "definition": d}, 200


def preset_sql(p):
    """The whole-estate SQL of a starter metric (the Builder's starters run the library's SQL)."""
    ref = str(p.get("ref") or "")
    d = _boards.definition(ref) if ref.startswith("preset.") else None
    if not d:
        return _err("no such starter metric", 404)
    try:
        full, _disp, _info = _boards.prepare(d, None)
    except ValueError as e:
        return _err(e)
    return {"ok": True, "sql": full, "title": d["title"], "note": d.get("note", "")}, 200


def _scope_of(p):
    """The board's scope (or an explicit one) for a preview."""
    if p.get("scope") is not None:
        return _dm.norm_scope(p.get("scope"))
    if p.get("board"):
        b = _boards.get(p.get("board"))
        return (b or {}).get("scope")
    return None


def ai_sql(p):
    """✨ Ask AI: plain English → a widget definition + a read-only test run (core/dashai)."""
    from core import dashai
    try:
        sc = _scope_of(p)
    except ValueError as e:
        return _err(e)
    out = dashai.ask(str(p.get("prompt") or ""), sc)
    try:
        con = _boards._con()
        _boards._audit(con, "ai_sql", str(p.get("board") or ""),
                       f"{'ok' if out.get('ok') else 'fail'}: {str(p.get('prompt') or '')[:200]}")
        con.commit(); con.close()
    except Exception:
        pass
    return out, 200


def sql_preview(p):
    """Run a SQL widget's query read-only (first 200 rows) under the board's scope — the editor's ▶ Preview."""
    from core import dashai
    try:
        return {"ok": True, **dashai.preview(str(p.get("sql") or ""), _scope_of(p))}, 200
    except ValueError as e:
        return _err(e)
    except Exception as e:
        from core import db
        if isinstance(e, db.QueryTimeout):
            body = db.budget_payload(e); body["ok"] = False
            return body, 200
        return {"ok": False, "error": str(e)}, 200


def scope_keys(p):
    return {"ok": True, "keys": _ts.keys()}, 200


def scope_values(p):
    return {"ok": True, "values": _ts.values(str(p.get("key") or ""))}, 200


def scope_count(p):
    try:
        sc = _dm.norm_scope(p.get("scope"))
    except ValueError as e:
        return _err(e)
    return {"ok": True, "assets": _dm.scope_count(sc), "label": _dm.scope_label(sc)}, 200


ACTIONS.update({
    "boards": boards_list, "board_get": board_get, "board_save": board_save, "board_new": board_new,
    "board_delete": board_delete, "board_default": board_default, "board_export": board_export,
    "board_import": board_import, "library": library, "widget_cached": widget_cached,
    "widget_run": widget_run, "widget_sql": widget_sql, "widget_data": widget_data, "widget_export": widget_export,
    "sql_save": sql_save, "sql_approve": sql_approve, "sql_delete": sql_delete, "sql_get": sql_get,
    "scope_keys": scope_keys, "preset_sql": preset_sql, "ai_sql": ai_sql, "sql_preview": sql_preview, "scope_values": scope_values, "scope_count": scope_count,
})
