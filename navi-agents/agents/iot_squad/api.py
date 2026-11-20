"""IoT Discovery Squad — self-contained HTTP actions.

Device inventory (build 503, core/iot_inventory.py): ▶ Run publishes one row per device asset
(confirmed / identified / predicted) to the result store. `drill` pages / searches it,
`inventory_export` streams it as CSV and `inventory_tag` (gated) tags it — all by the run +
filter KEY, so the browser never holds asset UUIDs and any size works (tag_set pages ≤ 1,999)."""
import csv
import io
import re

from core import navi_cli, iot_registry, iot_common, iot_inventory, payload
from .agent import IoTSquadOrchestrator
from core.gates import confirmed

AGENT = IoTSquadOrchestrator()


def run(p):
    p = p or {}
    use_pack = bool(p.get("use_pack"))
    try:
        res = AGENT.run(use_pack=use_pack)
    except FileNotFoundError as e:          # no navi.db at all — say so, don't 500
        return {"ok": False, "error": str(e)}, 200
    if isinstance(res, dict):
        try:                                # additive: every older result key is unchanged
            res["inventory"] = iot_inventory.publish(res, getattr(AGENT.a3, "full_uuids", None))
        except Exception as e:              # noqa: BLE001 — the inventory never breaks the run
            res["inventory"] = {"ok": False, "error": "device inventory unavailable: %s" % e}
    return {"ok": True, "agent": AGENT.meta(), "result": res,
            "options": {"use_pack": use_pack,
                        "pack_size": len(iot_common.term_pack()),
                        "byo_pack": bool(__import__("os").environ.get("IOT_TERM_PACK_PATH")),
                        "supplied_carriers": len(iot_common.byo_carrier_plugins())}}, 200


def _tag_selector(cat, val, s):
    """Apply ONE navi built-in selector (--plugin/--output/--name), or --query only
    for signal-fusion groups that have no plugin signature. Add-only."""
    if s.get("plugin"):
        return navi_cli.tag(cat, val, plugin=str(s["plugin"]), output=s.get("output", ""),
                            remove=False, agent="iot_squad")
    if s.get("name"):
        return navi_cli.tag(cat, val, plugin_name=s["name"], remove=False, agent="iot_squad")
    return navi_cli.tag(cat, val, query=s.get("query", ""), remove=False, agent="iot_squad")


def _ensure_result(use_pack=False):
    """The page can show a run replayed from the page cache after a server restart, when
    this process has no result yet — re-derive it (a read) instead of failing the write."""
    if AGENT.result is None:
        AGENT.run(use_pack=bool(use_pack))
    return AGENT.result


def tags_apply(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to apply tags"}, 400
    if _ensure_result(p.get("use_pack")) is None:
        return {"ok": False, "error": "run the agent first"}, 400
    actions = {a["value"]: a for a in AGENT.result.get("tag_actions", [])}
    # Unified inventory scheme: category 'Asset Inventory', value '<Facet>: <name>'. The UI
    # may override the facet per device (facets map) or set one default for all (facet).
    facets = p.get("facets") or {}
    default_facet = (p.get("facet") or "").strip()
    results = []
    for v in p.get("values", []):
        a = actions.get(v)
        if not a:
            results.append({"value": v, "ok": False, "message": "no matching tag action"})
            continue
        facet = (facets.get(v) or default_facet or a.get("facet") or "Device Type").strip()
        tag_value = f"{facet}: {v}"
        # Each device is tagged via its navi built-in selectors — one navi command
        # per plugin/output/name — so no giant UUID --query (dodges the 1999 cap).
        sels = a.get("selectors") or ([{"query": a.get("query", "")}] if a.get("query") else [])
        jobs = [_tag_selector("Asset Inventory", tag_value, s) for s in sels]
        job_ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
        results.append({"value": v, "facet": facet, "tag_value": "Asset Inventory : " + tag_value,
                        "ok": True, "queued": True,
                        "job_ids": job_ids, "job_id": (job_ids[0] if job_ids else None),
                        "commands": len(sels)})
    return {"ok": True, "results": results, "writes_enabled": navi_cli.writes_enabled(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


def tag_candidate(p):
    """Tag a single cross-reference candidate asset IoT:<name> (gated).

    Used after a human inspects the candidate's plugin output and decides it is a
    true match, not a false positive."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to apply tag"}, 400
    name = (p.get("iot_name") or "").strip()
    uuid = (p.get("asset_uuid") or "").strip()
    value = (p.get("value") or name).strip()   # human can rename the tag value
    if not name or not uuid:
        return {"ok": False, "error": "iot_name and asset_uuid required"}, 400
    q = f"SELECT asset_uuid FROM vulns WHERE asset_uuid = '{uuid.replace(chr(39), chr(39)*2)}';"
    res = navi_cli.tag("IoT", value, q, remove=False, agent="iot_squad")
    return {"ok": True, "iot_name": name, "value": value, "asset_uuid": uuid,
            "result": res, "writes_enabled": navi_cli.writes_enabled()}, 200


def detections_decide(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to update detections"}, 400
    decisions = p.get("decisions", [])
    if not decisions:
        return {"ok": False, "error": "no decisions supplied"}, 400
    return {"ok": True, **iot_registry.apply_decisions(decisions)}, 200


def detections_export(p):
    """Base-building: write the confirmed proposals from a rich-db hunt to a
    reviewable learned base file (default) — or merge=True to fold in the seeds
    too. Does NOT touch the live registry; the operator swaps the file in."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to export a base"}, 400
    proposals = p.get("proposals")
    if proposals is None:                       # default: everything Agent 3 confirmed
        proposals = (_ensure_result(p.get("use_pack")) or {}).get("proposals", [])
    if not proposals:
        return {"ok": False, "error": "no proposals to export (run a hunt first)"}, 400
    return {"ok": True, **iot_registry.export_base(proposals, merge=bool(p.get("merge")))}, 200


def registry(p):
    data = iot_registry.load()
    return {"path": iot_registry.registry_path(),
            "detections": data["detections"], "rejected": data.get("rejected", [])}, 200


def drill(p):
    """Read: one page of the device inventory (filters / search / sort on the server)."""
    return payload.drill(iot_inventory.HOUND, p, iot_inventory.SECTIONS)


def inventory_export(p):
    """Read: EVERY row of the device inventory for this filter + search, as CSV."""
    sel, err = iot_inventory.selection(p)
    if err:
        return err, 200 if err.get("expired") else 400
    run, flt, q = sel
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(iot_inventory.CSV_COLS)
    n = 0
    for r in payload.STORE.iter_rows(run, iot_inventory.SECTION, flt, q):
        r = dict(r, also="; ".join(r.get("also") or []))
        vals = [r.get(c) if r.get(c) is not None else "" for c in iot_inventory.CSV_COLS]
        w.writerow([("'" + v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v for v in vals])
        n += 1
    return {"ok": True, "rows": n, "csv": buf.getvalue()}, 200


# the two schemes the Classifier reads (core/classify.py): a Device Type it maps to a class
# (Camera → IoT, Switch → Network …), or the IoT squad's own per-device tag.
TAG_SCHEMES = {"device_type": ("Asset Inventory", "Device Type: {v}"), "iot": ("IoT", "{v}")}
_BAD_VALUE = re.compile(r"[\x00-\x1f'\"]")


def inventory_tag(p):
    """Gated: tag every asset in the inventory list (run + filter + search) with
    scheme device_type → Asset Inventory : 'Device Type: <value>'  (Gate 1 / Classifier scheme), or
    scheme iot         → IoT : '<value>'                          (the per-device IoT tag).
    Add-only; paged by navi_cli.tag_set (≤ 1,999 per navi job, a background series above)."""
    p = p or {}
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to tag"}, 400
    sel, err = iot_inventory.selection(p)
    if err:
        return err, 200 if err.get("expired") else 400
    scheme = p.get("scheme") or "device_type"
    if scheme not in TAG_SCHEMES:
        return {"ok": False, "error": "scheme must be one of: " + ", ".join(TAG_SCHEMES)}, 400
    value = " ".join(str(p.get("value") or "").split())
    if not value or len(value) > 120 or _BAD_VALUE.search(value):
        return {"ok": False, "error": "a tag value (≤ 120 characters, no quotes) is required"}, 400
    run, flt, q = sel
    uuids = payload.STORE.uids(run, iot_inventory.SECTION, flt, q)
    if not uuids:
        return {"ok": False, "error": "no assets in this list"}, 400
    cat, fmt = TAG_SCHEMES[scheme]
    tag_value = fmt.format(v=value)
    jobs = navi_cli.tag_set(cat, tag_value, uuids=uuids, agent="iot_squad")
    s = navi_cli.jobs_summary(jobs)
    return {"ok": bool(jobs) and all(j.get("ok") or j.get("queued") for j in jobs),
            "queued": any(j.get("queued") for j in jobs), "job_ids": s["job_ids"], "jobs": s["jobs"],
            "value": "%s : %s" % (cat, tag_value), "asset_count": len(uuids),
            "message": ("queued %d batch(es) for %d assets" % (len(jobs), len(uuids)) if len(jobs) > 1
                        else (jobs[0].get("message") if jobs else s.get("error"))),
            "writes_enabled": navi_cli.writes_enabled(),
            "write_gate_reason": navi_cli.write_gate_reason()}, 200


ACTIONS = {"run": run, "drill": drill, "inventory_export": inventory_export, "inventory_tag": inventory_tag, "tags_apply": tags_apply, "tag_candidate": tag_candidate,
           "detections_decide": detections_decide, "detections_export": detections_export,
           "registry": registry}
