"""WAS Apps Explorer — Vizsla. Read-only navi.db search over the `apps` table.

Filters: free text (name / target / tech), severity presence (has critical / has high /
clean), and scan recency (stale / fresh). Reuses core.was for the owasp/tech parsing so
each row carries its parsed tech list + top OWASP category. KPIs span the whole filtered
set. Risk-sorted (criticals first).
"""
from core import db, was

_PAGE = 200
_STALE = 30


def _exists():
    try:
        return bool(db.scalar("SELECT 1 FROM sqlite_master WHERE type='table' AND name='apps'",
                              budget=0))
    except Exception:
        return False


def _where(p):
    cl, args = [], []
    q = (p.get("q") or "").strip()
    if q:
        cl.append("(name LIKE ? OR target LIKE ? OR tech_list LIKE ?)")
        args += ["%" + q + "%"] * 3
    sev = (p.get("sev") or "").strip().lower()
    if sev == "crit":
        cl.append("CAST(critical_count AS INT)>0")
    elif sev == "high":
        cl.append("CAST(high_count AS INT)>0")
    elif sev == "clean":
        cl.append("CAST(critical_count AS INT)+CAST(high_count AS INT)+"
                  "CAST(medium_count AS INT)+CAST(low_count AS INT)=0")
    rec = (p.get("recency") or "").strip().lower()
    if rec == "stale":
        cl.append("%s>%d" % (was._SCAN_AGE, _STALE))
    elif rec == "fresh":
        cl.append("%s<=%d" % (was._SCAN_AGE, _STALE))
    return ((" WHERE " + " AND ".join(cl)) if cl else ""), tuple(args)


def search(p):
    if not _exists():
        return {"ok": True, "result": {"missing": True, "rows": [], "kpi": {}}}, 200
    where, args = _where(p)
    off = max(0, int(p.get("offset") or 0))
    try:
        _n = max(1, min(_PAGE, int(p.get("limit") or _PAGE)))   # UI asks 10–50
    except (TypeError, ValueError):
        _n = _PAGE
    kpi = db.query(
        "SELECT COUNT(*) AS total,"
        " SUM(CASE WHEN CAST(critical_count AS INT)>0 THEN 1 ELSE 0 END) AS with_crit,"
        " SUM(CASE WHEN CAST(high_count AS INT)>0 THEN 1 ELSE 0 END) AS with_high,"
        " SUM(CAST(critical_count AS INT)+CAST(high_count AS INT)+CAST(medium_count AS INT)"
        "   +CAST(low_count AS INT)+CAST(info_count AS INT)) AS findings,"
        " SUM(CASE WHEN %s>%d THEN 1 ELSE 0 END) AS stale"
        " FROM apps%s" % (was._SCAN_AGE, _STALE, where), args)
    k = dict(kpi[0]) if kpi else {}

    raw = db.query(
        "SELECT %s FROM apps%s ORDER BY CAST(critical_count AS INT) DESC,"
        " CAST(high_count AS INT) DESC LIMIT ? OFFSET ?" % (was._APP_COLS, where),
        args + (_n + 1, off))
    rows = [was._row_view(r) for r in raw]
    has_next = len(rows) > _n
    for a in rows[:_n]:
        ow = a.get("owasp") or {}
        top = max(ow.items(), key=lambda kv: kv[1]) if ow else None
        a["top_owasp"] = (top[0] + " " + was.OWASP_LABELS.get(top[0], top[0])) if (top and top[1] > 0) else ""
        a["tech_count"] = len(a.get("tech") or [])
        a["tech_str"] = ", ".join((a.get("tech") or [])[:6])
    return {"ok": True, "result": {"rows": rows[:_n], "kpi": k, "offset": off,
            "page": off // _n + 1, "has_next": has_next, "count": min(len(rows), _n)}}, 200


def export(p):
    """Build 525: EVERY app of the search as CSV (the page used to export only the rows on screen);
    ≤ 5,000 at once, more as a background export job (core/exports.py)."""
    from core import exports
    if not _exists():
        return {"ok": False, "error": "no apps table in navi.db"}, 200
    where, args = _where(p or {})
    total = int(db.scalar("SELECT COUNT(*) FROM apps" + where, args) or 0)
    cols = ["name", "target", "critical", "high", "medium", "low", "info", "findings_total", "tech_str",
            "top_owasp", "scan_completed_time"]

    def rows():
        for r in db.iter("SELECT %s FROM apps%s ORDER BY CAST(critical_count AS INT) DESC,"
                         " CAST(high_count AS INT) DESC" % (was._APP_COLS, where), args):
            a = was._row_view(r)
            ow = a.get("owasp") or {}
            top = max(ow.items(), key=lambda kv: kv[1]) if ow else None
            a["top_owasp"] = (top[0] + " " + was.OWASP_LABELS.get(top[0], top[0])) if (top and top[1] > 0) else ""
            a["tech_str"] = ", ".join(a.get("tech") or [])
            yield [a.get(c) for c in cols]
    return exports.start("was-apps", rows=rows, header=cols, total=total, agent="ex_apps"), 200


ACTIONS = {"search": search, "export": export}
