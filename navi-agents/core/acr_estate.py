"""ACR estate metrics — the "how is my estate rated and exposed?" half of the ACR page's
📊 At a glance (the other half, core/acr_protect.metrics, is about what the Ensemble changed).

Reads only. Bounded for a 600 GB navi.db:
  • ONE grouped pass over `assets` (never vulns) → ≤ 11 × 4 rows (ACR value × AES band), from
    which every spread / average / share below is computed in Python.
  • Two ORDER BY … LIMIT 5 reads for the top / bottom AES assets (a top-N heap, no full sort).
  • The "changed" side reuses the ACR log + the NO : UPDATE set (core/acrlog, core/acr_protect)
    and looks those UUIDs up in chunked IN lists — never pulls the estate into Python.
  • Cached per (navi.db file signature, ACR-log high-water mark): a ▶ Load or a Protection
    filter click after the first one is free until navi syncs or a Hound changes an ACR.

Bands are Tenable's own (docs.tenable.com, Tenable One / Lumin metrics):
  ACR  Critical 9–10 · High 7–8 · Medium 4–6 · Low 1–3
  AES  High 650–1000 · Medium 350–649 · Low 0–349
Tenable does not calculate AES for unlicensed assets, so a missing AES is "unscored" — not 0.

navi.db quirks handled: ACR is TEXT and often "8.0"; empty fields are '' / ' ' / 'None'
(see navi notes) — all of those count as "no ACR" / "unscored".

What navi.db can NOT say: whether an ACR was set by a person in the Tenable UI. navi.db holds
the current value only (no ACR drivers, no override flag). "Changed" therefore means a change
the Ensemble recorded (ACR log) or an asset someone protected with NO : UPDATE; everything else
is reported as "no recorded change" — Tenable-calculated as far as navi can tell.
"""
import os
import threading

from . import db

ACR_BANDS = (("critical", "Critical", 9, 10), ("high", "High", 7, 8),
             ("medium", "Medium", 4, 6), ("low", "Low", 1, 3))
AES_BANDS = (("high", "High", 650, 1000), ("medium", "Medium", 350, 649), ("low", "Low", 0, 349))
TOP_N = 5

_LOCK = threading.Lock()
_CACHE = {}

# One pass. r = whole ACR 1–10 (NULL = no ACR); e = AES (NULL = unscored).
_SQL = """
WITH a AS (
  SELECT CASE WHEN CAST(TRIM(acr) AS REAL) BETWEEN 1 AND 10
              THEN CAST(ROUND(CAST(TRIM(acr) AS REAL)) AS INTEGER) END AS r,
         CASE WHEN aes IS NULL OR TRIM(CAST(aes AS TEXT)) IN ('', 'None') THEN NULL
              ELSE CAST(aes AS INTEGER) END AS e
    FROM assets)
SELECT r,
       CASE WHEN e IS NULL THEN 'u' WHEN e >= 650 THEN 'high' WHEN e >= 350 THEN 'medium' ELSE 'low' END AS b,
       COUNT(*) AS n, SUM(e) AS s, MIN(e) AS lo, MAX(e) AS hi, SUM(e = 0) AS z
  FROM a GROUP BY r, b
"""
_AES_OK = "aes IS NOT NULL AND TRIM(CAST(aes AS TEXT)) NOT IN ('', 'None')"


def _cols(path=None):
    try:
        return {r["name"] for r in db.query('PRAGMA table_info("assets")', path=path)}
    except Exception:
        return set()


def acr_band(v):
    try:
        v = int(round(float(v)))
    except (TypeError, ValueError):
        return None
    for key, _l, lo, hi in ACR_BANDS:
        if lo <= v <= hi:
            return key
    return None


def _pct(n, d):
    return round(100.0 * n / d, 1) if d else 0.0


def _num(v):
    try:
        f = float(str(v).strip())
    except (TypeError, ValueError):
        return None
    return f if f == f else None


def _edge(order, path, has_host, has_ip):
    host = "hostname" if has_host else "''"
    ip = "ip_address" if has_ip else "''"
    sql = ("SELECT uuid, %s AS hostname, %s AS ip, acr, CAST(aes AS INTEGER) AS aes FROM assets "
           "WHERE %s ORDER BY CAST(aes AS INTEGER) %s LIMIT %d" % (host, ip, _AES_OK, order, TOP_N))
    out = []
    for r in db.query(sql, path=path, budget="run"):
        a = _num(r.get("acr"))
        out.append({"uuid": r["uuid"], "hostname": (r.get("hostname") or "").strip(),
                    "ip": (r.get("ip") or "").strip(), "aes": r.get("aes"),
                    "acr": int(round(a)) if a and 1 <= a <= 10 else None})
    return out


def _changed(path=None):
    """Default vs changed: the Ensemble's applied changes (ACR log) ∪ NO : UPDATE, looked up in navi.db."""
    from . import acr_protect, acrlog
    try:
        changed = acrlog.applied_assets()
    except Exception:
        changed = {}
    try:
        prot = acr_protect.protected_uuids(path)
    except Exception:
        prot = set()
    rows = acr_protect._asset_rows(set(changed), path) if changed else {}   # chunked IN lists
    in_db = set(rows)
    try:
        synced_at = os.stat(path or db.db_path()).st_mtime
    except Exception:
        synced_at = None
    drift, drift_eligible = 0, 0
    for u in in_db:
        c = changed[u]
        if synced_at is None or (c.get("last_ts") or 0) >= synced_at:
            continue                                   # navi.db not synced since the change — can't judge
        want, have = _num(c.get("acr_after")), _num(rows[u].get("acr"))
        if want is None:
            continue
        drift_eligible += 1
        if have is None or int(round(have)) != int(round(want)):
            drift += 1
    by_agent = {}
    for u in in_db:
        a = changed[u].get("agent") or "?"
        by_agent[a] = by_agent.get(a, 0) + 1
    reasons = {}
    try:
        for r in acrlog._q("SELECT reasons, COUNT(DISTINCT asset_uuid) n FROM acr_log "
                           "WHERE result='applied' AND asset_uuid<>'' GROUP BY reasons"):
            import json
            try:
                rs = json.loads(r["reasons"] or "[]") or ["(none)"]
            except Exception:
                rs = ["(none)"]
            for x in rs:
                reasons[x] = reasons.get(x, 0) + r["n"]
    except Exception:
        pass
    return {"ensemble": len(in_db), "ensemble_not_in_db": len(set(changed) - in_db),
            "protected": len(prot), "protected_only": len(prot - in_db),
            "either": len(in_db | prot), "drift": drift, "drift_checked": drift_eligible,
            "by_agent": sorted(({"agent": k, "assets": v} for k, v in by_agent.items()), key=lambda x: -x["assets"]),
            "by_reason": sorted(({"reason": k, "assets": v} for k, v in reasons.items()), key=lambda x: -x["assets"])}


def _key(path):
    from . import acrlog
    try:
        sig = db._sig(path or db.db_path())
    except Exception:
        sig = None
    try:
        hw = tuple(acrlog._q("SELECT (SELECT MAX(id) FROM acr_log) a, (SELECT MAX(id) FROM acr_protect) b")[0].values())
    except Exception:
        hw = None
    return (path or "", sig, hw)


def estate(path=None, fresh=False) -> dict:
    """The estate at a glance (see module doc). Cached until navi.db or the ACR log changes."""
    k = _key(path)
    if not fresh:
        with _LOCK:
            hit = _CACHE.get(k[0])
            if hit and hit[0] == k:
                return dict(hit[1], cached=True)
    out = _compute(path)
    with _LOCK:
        _CACHE[k[0]] = (k, out)
    return dict(out, cached=False)


def _compute(path=None) -> dict:
    cols = _cols(path)
    if not cols:
        return {"ok": False, "error": "navi.db has no assets table — run a navi asset sync"}
    if "acr" not in cols or "aes" not in cols:
        return {"ok": False, "error": "navi.db assets has no acr/aes columns — update navi and re-sync assets"}
    rows = db.query(_SQL, path=path, budget="run")

    total = sum(r["n"] for r in rows)
    by_val = {v: 0 for v in range(1, 11)}
    acr_b = {k: {"assets": 0, "aes_sum": 0, "scored": 0, "aes": {"high": 0, "medium": 0, "low": 0, "u": 0}}
             for k, *_ in ACR_BANDS}
    acr_b["none"] = {"assets": 0, "aes_sum": 0, "scored": 0, "aes": {"high": 0, "medium": 0, "low": 0, "u": 0}}
    aes_b = {"high": 0, "medium": 0, "low": 0, "u": 0}
    scored = aes_sum = zero = 0
    lo = hi = None
    acr_sum = acr_n = 0
    for r in rows:
        v, b, n, s = r["r"], r["b"], r["n"] or 0, r["s"] or 0
        band = acr_band(v) if v is not None else "none"
        if v is not None:
            by_val[int(v)] += n
            acr_sum += int(v) * n
            acr_n += n
        ab = acr_b[band]
        ab["assets"] += n
        ab["aes"][b] += n
        aes_b[b] += n
        if b != "u":
            ab["aes_sum"] += s
            ab["scored"] += n
            scored += n
            aes_sum += s
            zero += r["z"] or 0
            lo = r["lo"] if lo is None else min(lo, r["lo"])
            hi = r["hi"] if hi is None else max(hi, r["hi"])

    has_host, has_ip = "hostname" in cols, "ip_address" in cols
    top = _edge("DESC", path, has_host, has_ip) if scored else []
    bottom = _edge("ASC", path, has_host, has_ip) if scored else []

    bands = []
    for key, label, b_lo, b_hi in ACR_BANDS:
        b = acr_b[key]
        bands.append({"band": key, "label": label, "range": "%d–%d" % (b_lo, b_hi), "assets": b["assets"],
                      "pct": _pct(b["assets"], total), "avg_aes": round(b["aes_sum"] / b["scored"]) if b["scored"] else None,
                      "aes_share_pct": _pct(b["aes_sum"], aes_sum), "aes_high": b["aes"]["high"],
                      "aes_medium": b["aes"]["medium"], "aes_low": b["aes"]["low"], "unscored": b["aes"]["u"]})
    mode_v = max(by_val, key=lambda x: by_val[x]) if acr_n else None
    ch = _changed(path)
    with_acr = acr_n
    return {
        "ok": True, "total": total, "with_acr": with_acr, "no_acr": acr_b["none"]["assets"],
        "avg_acr": round(acr_sum / acr_n, 1) if acr_n else None,
        "acr_values": [{"acr": v, "assets": by_val[v], "pct": _pct(by_val[v], total)} for v in range(10, 0, -1)],
        "acr_bands": bands,
        "mode_acr": mode_v, "mode_pct": _pct(by_val[mode_v], with_acr) if mode_v else 0.0,
        "aes": {"scored": scored, "unscored": aes_b["u"], "avg": round(aes_sum / scored) if scored else None,
                "min": lo, "max": hi, "zero": zero, "sum": aes_sum,
                "bands": [{"band": k, "label": l, "range": "%d–%d" % (a, b), "assets": aes_b[k],
                           "pct": _pct(aes_b[k], total)} for k, l, a, b in AES_BANDS],
                "top": top, "bottom": bottom},
        # the two calibration questions a VM lead asks first
        "crown_exposed": acr_b["critical"]["aes"]["high"],            # ACR 9–10 AND AES High → fix first
        "low_but_exposed": acr_b["low"]["aes"]["high"],               # ACR 1–3 AND AES High → rated right?
        "changed": dict(ch, default=max(0, with_acr - ch["either"]),
                        changed_pct=_pct(ch["either"], with_acr), default_pct=_pct(max(0, with_acr - ch["either"]), with_acr)),
        "bands_ref": {"acr": "Critical 9–10 · High 7–8 · Medium 4–6 · Low 1–3",
                      "aes": "High 650–1000 · Medium 350–649 · Low 0–349 (Tenable)"},
    }
