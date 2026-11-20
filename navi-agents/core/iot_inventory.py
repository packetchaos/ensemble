"""IoT device inventory — the "what's on my network that I didn't know about" view of a squad run
(build 503). One row per device ASSET, published to the result store (core/payload.py) so the page
pages / searches / exports / tags it on the server: no asset UUIDs ever reach the browser and a
200-camera list or a 149K-asset list are handled the same way.

How each asset got there (its STATUS — the strongest wins when an asset is found more than once):
  confirmed   a registry detection matched (plugin / name / identity output) — Agent 1
  identified  fingerprinted by a certificate (Chromecast, TeraStation, Ubiquiti …) — signal fusion
  predicted   inferred, not yet confirmed: Device Type / OUI / mDNS signals only (signal fusion), or a
              carrier plugin that mentions a device term the registry does not match on this asset
              yet (Agent 3 cross-term proposal, kind new / cross). Reviewing these is the point.

Filter flags on every row (the glance, the table chips and the tag/export all use them):
  st:<status> · dev:<device name> · type:<Tenable Device Type> · vendor:<OUI vendor> ·
  src:registry | src:signals | src:xterm · crit · high · kev · aes_high
"""
from . import iot_common as ic
from . import payload

HOUND = "iot_squad"
SECTION = "devices"
STATUS_RANK = {"confirmed": 0, "identified": 1, "predicted": 2}
FIXED_FLAGS = {"crit", "high", "kev", "aes_high", "src:registry", "src:signals", "src:xterm",
               "st:confirmed", "st:identified", "st:predicted"}
PREFIXES = ("dev:", "type:", "vendor:")
TOP_GROUPS = 200                  # ranked lists shipped to the page (the table has the rest)
CSV_COLS = ["hostname", "ip", "device", "status", "confidence", "device_type", "vendor", "why",
            "also", "critical", "high", "kev", "acr", "aes", "uuid"]


def flag_ok(f) -> bool:
    return isinstance(f, str) and (f in FIXED_FLAGS or (f.startswith(PREFIXES) and len(f) > 4))


SECTIONS = {SECTION: {"sorts": {"aes": ("s1",), "acr": ("s2",), "status": ("s3",)}, "flags": flag_ok}}


def _clean(s, n=120):
    s = " ".join(str(s or "").split())
    return "".join(ch for ch in s if ch >= " ")[:n]


def _vendor(v):
    v = _clean(v)
    return "" if v in ("", "—", "-", "None") else v


_CORP = {"co", "co.", "corp", "corp.", "corporation", "inc", "inc.", "ltd", "ltd.", "llc", "gmbh", "ag", "sa", "plc",
         "limited", "company", "technology", "technologies", "digital", "electronics", "systems", "networks",
         "international", "group", "holdings", "hangzhou", "shenzhen", "zhejiang", "beijing", "shanghai", "&"}


def vendor_short(v) -> str:
    """'Hangzhou Hikvision Digital Technology Co.,Ltd.' → 'Hikvision' · 'Ubiquiti Inc' → 'Ubiquiti'."""
    words = [w for w in str(v or "").split(",")[0].replace(".,", " ").split() if w.lower().strip(".,") not in _CORP
             and w.lower() not in _CORP]
    return " ".join(words[:2]) or _clean(v, 40)


def predicted_name(a) -> str:
    """A signal-only device is named by what it most likely IS: '<Device Type> · <vendor>'
    (Camera · Hikvision) — the predicted device TYPE — falling back to the squad's own name."""
    t = a.get("dev_type") or a.get("type")
    if t and t not in ("unknown", "general-purpose"):
        v = vendor_short(_vendor(a.get("vendor")))
        return type_label(t) + (" · " + v if v else "")
    return _clean(a.get("iot_name")) or "Embedded device"


def build_rows(res, xterm_full=None, db_path=None) -> list:
    """One dict per device asset from an orchestrator result (+ Agent 3's full proposal sets)."""
    by = {}

    def put(u, row):
        if not u:
            return
        cur = by.get(u)
        if cur is None:
            by[u] = row
            return
        if STATUS_RANK[row["status"]] < STATUS_RANK[cur["status"]]:      # stronger finding wins
            row["also"] = sorted((set(cur.get("also", [])) | {cur["device"]} | set(row.get("also", []))) - {row["device"]})
            row["sources"] = sorted(set(cur["sources"]) | set(row["sources"]))
            by[u] = row
        else:
            if row["device"] != cur["device"]:
                cur["also"] = sorted(set(cur.get("also", [])) | {row["device"]})
            cur["sources"] = sorted(set(cur["sources"]) | set(row["sources"]))
            for k in ("device_type", "vendor"):
                cur[k] = cur[k] or row[k]

    for a in ((res.get("discovery") or {}).get("detected") or []):
        fused = bool(a.get("fused"))
        klass = a.get("klass") or ""
        if not fused:
            st, why, conf = "confirmed", "registry detection", "Confirmed"
        elif klass and klass != "Embedded / candidate":
            st, why, conf = "identified", "certificate fingerprint · " + " · ".join(a.get("signals") or []), "High"
        else:
            st, why, conf = "predicted", "signals: " + " · ".join(a.get("signals") or ["candidate"]), a.get("conf") or "Medium"
        put(a.get("asset_uuid"), {
            "uuid": a.get("asset_uuid"), "hostname": _clean((a.get("hostname") or "").replace("(none)", "")),
            "ip": _clean(a.get("ip")),
            "device": predicted_name(a) if st == "predicted" else (_clean(a.get("iot_name")) or "Embedded device"),
            "status": st, "confidence": conf, "why": _clean(why, 200),
            "device_type": _clean(a.get("dev_type") or a.get("type")) if (a.get("dev_type") or a.get("type")) not in (None, "unknown", "general-purpose") else "",
            "vendor": _vendor(a.get("vendor")), "sources": ["signals" if fused else "registry"], "also": []})

    xterm_full = xterm_full or {}
    for p in res.get("proposals") or []:
        if p.get("kind") not in ("new", "cross"):
            continue
        uu = xterm_full.get(p.get("key")) or p.get("asset_uuids") or []
        why = "plugin %s%s mentions “%s” — not in the registry for this asset yet" % (
            p.get("plugin_id"), (" (" + _clean(p.get("plugin_name"), 60) + ")") if p.get("plugin_name") else "", p.get("term"))
        conf = "Low" if p.get("warnings") else "Medium"
        for u in uu:
            put(u, {"uuid": u, "hostname": "", "ip": "", "device": _clean(p.get("iot_name")), "status": "predicted",
                    "confidence": conf, "why": _clean(why, 200), "device_type": "", "vendor": _vendor(p.get("vendor")),
                    "sources": ["xterm"], "also": []})
    return list(by.values())


def _fill(rows, exposure, db_path=None):
    """Exposure + ACR / AES (reuses the run's exposure; looks up only what it lacks) + host / ip."""
    ex = {e["asset_uuid"]: e for e in (exposure or {}).get("assets") or []}
    miss = [r["uuid"] for r in rows if r["uuid"] not in ex]
    if miss:
        for e in ic.device_exposure(miss, db_path).get("assets", []):
            ex[e["asset_uuid"]] = e
    need = [r["uuid"] for r in rows if not (r["hostname"] or r["ip"])]
    names = {}
    if need:
        from . import db
        for i in range(0, len(need), 900):
            part = need[i:i + 900]
            for a in db.query("SELECT uuid, hostname, ip_address FROM assets WHERE uuid IN (%s)" % ",".join("?" * len(part)),
                              tuple(part), path=db_path):
                names[a["uuid"]] = a
    for r in rows:
        e = ex.get(r["uuid"]) or {}
        for k in ("critical", "high", "kev", "acr", "aes"):
            r[k] = e.get(k) if k in ("acr", "aes") else int(e.get(k) or 0)
        if r["uuid"] in names:
            a = names[r["uuid"]]
            r["hostname"] = _clean(a.get("hostname")) or r["hostname"]
            r["ip"] = _clean(a.get("ip_address")) or r["ip"]
    return rows


def _flags(r):
    f = ["st:" + r["status"], "dev:" + r["device"]] + ["src:" + s for s in r["sources"]]
    if r["device_type"]:
        f.append("type:" + r["device_type"])
    if r["vendor"]:
        f.append("vendor:" + r["vendor"])
    if r["critical"]:
        f.append("crit")
    if r["high"]:
        f.append("high")
    if r["kev"]:
        f.append("kev")
    if (r["aes"] or 0) >= 650:
        f.append("aes_high")
    return f


def type_label(t):
    """Tenable Device Type (plugin 54615, e.g. 'camera') → the Classifier's Device Type label ('Camera')."""
    if not t:
        return ""
    try:
        from .classify import _NESSUS_DEVTYPE
    except Exception:          # noqa: BLE001
        _NESSUS_DEVTYPE = {}
    return _NESSUS_DEVTYPE.get(str(t).lower(), str(t)[:1].upper() + str(t)[1:])


def _top(d, n=3):
    return [k for k, _ in sorted(d.items(), key=lambda kv: (-kv[1], kv[0].lower()))[:n]]


def _rank(rows, key, cap=TOP_GROUPS):
    """Group rows by `key` (device / device_type / vendor). Rows arrive riskiest first, so each
    group's FIRST row is its riskiest asset — the page's Dossier link. Per group: counts by status,
    confidence and exposure, max AES / avg ACR, the related names (vendors of a device, devices of a
    vendor), the Device Type, and the evidence ('why') of the riskiest asset."""
    other = {"device": "vendor", "vendor": "device", "device_type": "device"}.get(key, "vendor")
    g = {}
    for r in rows:
        k = r[key]
        if not k:
            continue
        x = g.get(k)
        if x is None:
            x = g[k] = {"name": k, "assets": 0, "confirmed": 0, "identified": 0, "predicted": 0,
                        "kev": 0, "crit": 0, "high": 0, "aes_high": 0, "max_aes": None, "_acr": [0.0, 0],
                        "conf": {}, "_types": {}, "_other": {}, "why": r.get("why") or "",
                        "top": {"uuid": r["uuid"], "hostname": r["hostname"], "ip": r["ip"],
                                "aes": r["aes"], "acr": r["acr"], "critical": r["critical"], "kev": r["kev"]}}
        x["assets"] += 1
        x[r["status"]] += 1
        x["conf"][r.get("confidence") or "—"] = x["conf"].get(r.get("confidence") or "—", 0) + 1
        if r["device_type"]:
            x["_types"][r["device_type"]] = x["_types"].get(r["device_type"], 0) + 1
        if r.get(other):
            x["_other"][r[other]] = x["_other"].get(r[other], 0) + 1
        x["kev"] += 1 if r["kev"] else 0
        x["crit"] += 1 if r["critical"] else 0
        x["high"] += 1 if r["high"] else 0
        x["aes_high"] += 1 if (r["aes"] or 0) >= 650 else 0
        if r["aes"] is not None and (x["max_aes"] is None or r["aes"] > x["max_aes"]):
            x["max_aes"] = r["aes"]
        a = _desc(r["acr"])
        if a <= 0:
            x["_acr"][0] += -a
            x["_acr"][1] += 1
    out = sorted(g.values(), key=lambda x: (-x["assets"], x["name"].lower()))
    for x in out:
        x["status"] = "confirmed" if x["confirmed"] else ("identified" if x["identified"] else "predicted")
        ts, oth, ac = x.pop("_types"), x.pop("_other"), x.pop("_acr")
        x["avg_acr"] = round(ac[0] / ac[1], 1) if ac[1] else None
        x["types"] = [type_label(t) for t in _top(ts)]
        x["related"] = _top(oth)                       # vendors of a device / devices of a vendor
        x["related_total"] = len(oth)
        # the Device Type value the page pre-fills when tagging this group (its most common type)
        x["type_label"] = type_label(x["name"] if key == "device_type" else (max(ts, key=ts.get) if ts else ""))
    return out[:cap], len(out)


def publish(res, xterm_full=None, db_path=None, store=None) -> dict:
    """Build + store the inventory for this run; return the page's glance data + the first page."""
    store = store or payload.STORE
    rows = _fill(build_rows(res, xterm_full, db_path), res.get("exposure"), db_path)
    rows.sort(key=lambda r: (-(r["kev"] or 0), -(r["critical"] or 0), -(r["high"] or 0), -(r["aes"] or 0),
                             STATUS_RANK[r["status"]], r["device"].lower(), r["hostname"].lower()))
    W = store.begin(HOUND)
    W.section(SECTION)
    try:
        for r in rows:
            W.add(SECTION, r, uid=r["uuid"], rk=r["uuid"], flags=_flags(r),
                  text=" ".join(str(r.get(k) or "") for k in ("hostname", "ip", "device", "device_type", "vendor",
                                                             "why", "uuid")) + " " + " ".join(r["also"]),
                  keys=(_desc(r["aes"]), _desc(r["acr"]), STATUS_RANK[r["status"]]))
    except BaseException:
        W.close(ok=False)
        raise
    W.close()
    devs, n_dev = _rank(rows, "device")
    pred, n_pred = _rank([r for r in rows if r["status"] == "predicted"], "device")
    types, n_type = _rank(rows, "device_type")
    vendors, n_vendor = _rank(rows, "vendor")
    st = {s: sum(1 for r in rows if r["status"] == s) for s in STATUS_RANK}
    first, _c = payload.drill(HOUND, {"run": W.run, "section": SECTION, "limit": 50}, SECTIONS, store=store)
    return {"run": W.run, "total": len(rows), "status": st,
            "devices": devs, "devices_total": n_dev,
            # predicted rows ONLY, grouped by device — the 🔮 Predicted section (counts are predicted assets)
            "predicted": pred, "predicted_total": n_pred,
            "predicted_conf": {k: sum(1 for r in rows if r["status"] == "predicted" and r["confidence"] == k)
                               for k in ("High", "Medium", "Low")},
            "types": types, "types_total": n_type, "vendors": vendors, "vendors_total": n_vendor,
            "exposed": {"kev": sum(1 for r in rows if r["kev"]), "crit": sum(1 for r in rows if r["critical"]),
                        "high": sum(1 for r in rows if r["high"]),
                        "aes_high": sum(1 for r in rows if (r["aes"] or 0) >= 650)},
            "first": first}


def _desc(v):
    """A descending sort key (the store sorts ascending); a missing value sorts last."""
    try:
        return -float(v)
    except (TypeError, ValueError):
        return 1.0


def selection(p, store=None):
    """(run, flags, q) from a request, validated — or an error dict. The tag / export key."""
    store = store or payload.STORE
    p = p or {}
    run = p.get("run")
    if not isinstance(run, str) or not store.run_info(run, HOUND):
        return None, {"ok": False, "expired": True,
                      "error": "this run's device list is no longer on the server — press ▶ Run again"}
    flt = p.get("filter") or []
    if isinstance(flt, str):
        flt = [flt]
    if not isinstance(flt, list) or len(flt) > 6 or not all(flag_ok(f) and len(f) <= 160 for f in flt):
        return None, {"ok": False, "error": "bad filter"}
    q = p.get("q") or ""
    if not isinstance(q, str) or len(q) > 200:
        return None, {"ok": False, "error": "bad search"}
    return (run, flt, q.strip()), None
