"""Tiresias — Compliance Asset deep-dive HTTP actions.

run    — readiness stub (the hub's generic Execute).
detail — payload {asset_uuid, f} (falls back to the worst-failing asset; `f` narrows the
         asset list to a cohort from a Minos widget) → its audit checks
         (pass/fail/warn + actual/expected/frameworks), its vulns, and the inferred
         audit↔vuln correlations; plus the compliance asset list for the page selector.
tag    — GATED: tag this asset with an 'Audit-Vuln Link' for a correlated topic, via navi.

Build 525 — at scale (a 44,000-asset "failing a check" group) the page never finished: `detail`
aggregated every asset and shipped the whole list. Now:
cohort — {f} → the group's assets, worst first, streamed ONCE into the result store; returns the
         first 500 rows + a drill handle (the page shows 20 at a time and asks for the next 500 only
         when you page past them). Long builds detach as a background run (the console's run-bg).
drill  — {run, section:"assets", next, limit ≤ 500, q} — the next chunk / a search.
export — {f, run?, q?} → every asset of the group as CSV: ≤ 5,000 rows at once, more as a
         background export job (`navi export query` over the same SQL — core/exports.py).
detail — with list:false it skips the asset list (the page has it) and answers in_cohort for the
         one asset instead.
"""
from core import payload
import re

from core.gates import confirmed
AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import TiresiasAgent
        AGENT = TiresiasAgent()
    return AGENT


def run(p):
    return {"ok": True, "agent": _agent().meta(), "result": _agent().run()}, 200


STORE_NS = "compliance_asset"
CHUNK = payload.CHUNK_MAX              # rows a page call returns; the page shows 20 at a time
SECTIONS = {"assets": {"sorts": {}, "flags": set(), "max_limit": CHUNK}}


def _row_keys(r, i):
    return (-(r.get("failed") or 0), -(r.get("warning") or 0), i)


def cohort(p):
    """The group's assets (every audited asset when f is empty) → the result store; the first
    CHUNK rows + the drill handle. summary: {f, kind, key, label, count}."""
    from core import compliance as _c
    f = str((p or {}).get("f") or "")
    meta = _c.cohort_meta(f)
    if meta is None:
        return {"ok": False, "error": "unknown group"}, 200
    if not _c.ready():
        return {"ok": True, "summary": dict(meta, count=0, available=False), "top": [], "total": payload.total(0),
                "page": {"next": None, "start": 0, "limit": CHUNK}, "drill": None}, 200
    W = payload.STORE.begin(STORE_NS)
    W.section("assets")
    n = 0
    try:
        for r in _c.cohort_rows(f):
            text = " ".join(str(x or "") for x in (r["hostname"], r["ip"], r["asset_uuid"]))
            W.add("assets", r, uid=r["asset_uuid"], keys=_row_keys(r, n), text=text)
            n += 1
        W.meta = {"f": f}
    except BaseException:
        W.close(ok=False)
        raise
    W.close()
    first, _c2 = payload.drill(STORE_NS, {"run": W.run, "section": "assets", "limit": CHUNK}, SECTIONS)
    summary = dict(meta, count=n, available=True)
    return payload.response(summary=summary, top=first.get("top") or [], total_=first.get("total"),
                            page=first.get("page"), drill={"action": "drill", "run": W.run, "section": "assets"},
                            tag={"key": "cohort", "count": n}, max_rows=CHUNK), 200


def drill(p):
    return payload.drill(STORE_NS, p, SECTIONS)


def export(p):
    """Every asset of the group as CSV (no cap). A search on the list (q) exports what it matched,
    from the stored run; otherwise the group's own SQL — run by `navi export query` when it is more
    than 5,000 rows (core/exports.py)."""
    from core import compliance as _c, exports
    p = p or {}
    f = str(p.get("f") or "")
    meta = _c.cohort_meta(f)
    if meta is None:
        return {"ok": False, "error": "unknown group"}, 200
    name = "compliance-" + (re.sub(r"[^A-Za-z0-9]+", "-", meta["label"]).strip("-").lower()[:60] or "assets")
    run = p.get("run")
    if (p.get("q") or "").strip() and run:
        return exports.store_export({"run": run, "section": "assets", "q": p.get("q")}, name=name), 200
    total = None
    if run and payload.STORE.run_info(run, STORE_NS):
        total = payload.STORE.section_total(run, "assets")
    cols = ["asset_uuid", "hostname", "ip", "failed", "warning", "passed", "total", "pass_pct"]
    if meta["kind"] == "fw":                     # an exact framework match needs Python: stream the rows
        return exports.start(name, rows=lambda: _c.cohort_rows(f), header=None, total=total,
                             agent=STORE_NS), 200
    sql, args = _c.cohort_sql(f)
    if total is not None and total <= exports.INLINE_MAX:
        return exports.start(name, rows=lambda: ([r.get(c) for c in cols] for r in _c.cohort_rows(f)),
                             header=cols, total=total, agent=STORE_NS), 200
    # the full list: navi exports the entire result of the group's own SQL (server-built → trusted)
    return exports.start(name, sql=sql, args=args, total=total, agent=STORE_NS, trusted=True, force_job=True), 200


def detail(p):
    """{asset_uuid, f}: `f` is a cohort from a Minos widget (st:failed, check:<id>, fw:<name>,
    audit:<file>, pct:lt50 …) — the asset list is narrowed to it, and with no asset given
    the worst asset IN the cohort opens. list:false (build 525) — the page already holds the
    list (cohort / drill): skip it and say whether this one asset is in the group."""
    from core import compliance as _c, navi_cli
    au = (p.get("asset_uuid") or p.get("asset") or "").strip()
    if p.get("list") is False:
        meta = _c.cohort_meta(p.get("f")) if p.get("f") else None
        det = (_c.asset_detail(asset_uuid=au, focus_check=meta["key"] if meta and meta["kind"] == "check" else None)
               if au else {"available": False, "empty_cohort": bool(meta),
                           "reason": "No asset in navi.db is in this group right now." if meta else "no compliance assets"})
        return {"ok": True, "result": {"detail": det, "cohort": meta,
                                       "in_cohort": bool(meta) and _c.in_cohort(meta["f"], au)},
                "writes": {"enabled": navi_cli.writes_enabled(), "navi": navi_cli.navi_available(),
                           "reason": navi_cli.write_gate_reason()}}, 200
    coh = _c.cohort(p.get("f")) if p.get("f") else None
    assets = _c.assets_list(only=coh["uuids"] if coh else None)
    if coh and not au and assets:
        au = assets[0]["asset_uuid"]
    cinfo = ({"f": coh["f"], "kind": coh["kind"], "key": coh["key"], "label": coh["label"],
              "count": len(assets)} if coh else None)
    if coh and not au:
        # an empty group: say so — never fall back to some unrelated "worst asset"
        det = {"available": False, "empty_cohort": True,
               "reason": "No asset in navi.db is in this group right now."}
    else:
        det = _c.asset_detail(asset_uuid=au, focus_check=coh["key"] if coh and coh["kind"] == "check" else None)
    return {"ok": True, "result": {"detail": det,
                                   "assets": assets, "cohort": cinfo},
            "writes": {"enabled": navi_cli.writes_enabled(), "navi": navi_cli.navi_available(),
                       "reason": navi_cli.write_gate_reason()}}, 200


def tag(p):
    from core import compliance as _c, navi_cli
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    topic = (p.get("topic") or p.get("value") or "").strip()
    if not topic:
        return {"ok": False, "error": "correlation topic required"}, 400
    tgt = _c.correlation_targets(asset_uuid=(p.get("asset_uuid") or ""))
    if not tgt or not tgt["uuids"]:
        return {"ok": False, "error": "asset_uuid required"}, 400
    cat = _c.TAG_LINK_CATEGORY
    jobs = navi_cli.tag_capped(cat, topic, uuids=tgt["uuids"], col="asset_uuid",
                               table="compliance", agent="compliance_asset")
    job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    first = jobs[0] if jobs else {}
    ok = all(j.get("ok") or j.get("queued") for j in jobs) if jobs else False
    return {"ok": ok, "queued": any(j.get("queued") for j in jobs), "category": cat, "value": topic,
            "asset_count": len(tgt["uuids"]), "job_id": job_ids[0] if job_ids else first.get("job_id"),
            "job_ids": job_ids, "message": first.get("message"),
            "writes_enabled": navi_cli.writes_enabled(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


def audit_files(p):
    """The AUDIT-FILE lens (aggregate): the audit-file leaderboard + the estate-wide
    audit↔vuln correlation, side by side."""
    from core import compliance as _c
    return {"ok": True, "result": _c.audit_overview()}, 200


def audit_file(p):
    """One audit file, all its assets: adherence, checks rollup, assets rollup, and the
    file-scoped audit↔vuln correlation."""
    from core import compliance as _c
    return {"ok": True, "result": _c.audit_detail(p.get("audit_file") or p.get("file") or "")}, 200


ACTIONS = {"run": run, "detail": detail, "tag": tag, "cohort": cohort, "drill": drill, "export": export,
           "audit_files": audit_files, "audit_file": audit_file}
