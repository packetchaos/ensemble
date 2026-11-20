"""Scan Confirmation — HTTP actions (thin wrappers over core/scan_confirm.py).

Reads (ungated): run, status, lookups, plugin_info, plan, runs, run_get, verdicts, export, events,
job_poll, deletable. `plan` stores a PLANNED run (app state in tag_jobs.db) — it touches nothing in
Tenable or navi.db.

Writes — each checks confirm (JSON true) FIRST, then writes + NAVI_SCAN_LAUNCH, before doing
anything: scan_launch, scan_stop, scan_pause, scan_resume, scan_resume_watch, scan_reverify,
scan_delete_old. argv is only ever built by core/scan_confirm.build_* from validated values.
"""
import csv
import io
import re
import time

from core import cli_jobs, navi_cli, scan_confirm as sc
from core.gates import confirmed
from .agent import ScanConfirmAgent

AGENT = ScanConfirmAgent()
_RUN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
MAX_UI_TARGETS = 5000                       # never more than ~5,000 identifiers in one reply


def _need_confirm(what):
    return {"ok": False, "error": "confirm=true required — %s" % what}, 400


def _blocked():
    r = navi_cli.scan_launch_gate_reason()
    if r:
        return {"ok": False, "blocked": True, "status": "blocked", "reason": r, "message": r,
                **_gates()}, 200
    return None


def _gates():
    return {"scan_launch_enabled": navi_cli.scan_launch_enabled(), "gate_reason": navi_cli.scan_launch_gate_reason(),
            "allow_writes": navi_cli.allow_writes()}


def _run_of(p):
    rid = str((p or {}).get("run_id") or "")
    if not _RUN_ID.match(rid):
        return None, ({"ok": False, "error": "run_id required"}, 400)
    run = sc.get_run(rid)
    if not run:
        return None, ({"ok": False, "error": "no such run"}, 404)
    return run, None


# ── reads ────────────────────────────────────────────────────────────────────────────────
def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def status(p):
    resumable = [r for r in sc.nonterminal_runs() if not sc.is_active(r)]
    return {"ok": True, **_gates(), "resumable": resumable, "retention_days": sc.retention_days()}, 200


def lookups(p):
    try:
        lk = sc.lookups(force=(p or {}).get("refresh") is True)
    except Exception as e:
        return {"ok": False, "error": "could not read Tenable: %s" % e}, 200
    return {"ok": True, **lk, "features": {k: v for k, v in sc.features().items() if k != "help"}}, 200


def scan_lookup(p):
    """One scan by id (read) — for a scan the picker doesn't list. Adds its policy_id when the list has it."""
    sid = str((p or {}).get("scan_id") or "").strip()
    if not re.match(r"^\d{1,12}$", sid):
        return {"ok": False, "error": "scan id must be digits"}, 200
    info = sc.scan_info(sid)
    row = next((x for x in (sc.lookups().get("scans") or []) if x.get("id") == sid), None)
    if not info and not row:
        return {"ok": False, "error": "scan #%s can't be read in Tenable" % sid}, 200
    return {"ok": True, "scan": dict(info or {}, **(row or {}))}, 200


def plugin_info(p):
    ids = []
    for x in ((p or {}).get("plugins") or [])[:sc.MAX_PLUGINS]:
        if re.match(r"^\d{1,7}$", str(x).strip()):
            ids.append(int(str(x).strip()))
    names, fams = sc.plugin_names(ids), sc.plugin_families(ids)
    return {"ok": True, "plugins": [{"id": i, "name": names.get(i), "family": fams.get(i),
                                     "local": sc.is_local(fams.get(i))} for i in ids]}, 200


def _scan_view(ps, cred, srow=None):
    srow = srow or {}
    return {"plan_index": ps["plan_index"], "plugins": ps["plugins"], "targets": len(ps["targets"]),
            "targets_sample": ps["targets"][:8], "argv": sc.mask_argv(ps.get("argv") or [], cred),
            "reuse": bool(sc.reusable_scan(ps["reuse_key"])), "scan_id": srow.get("scan_id"),
            "history_id": srow.get("history_id"), "status": srow.get("status"), "launched": srow.get("launched"),
            "ended": srow.get("ended"), "time_start": srow.get("time_start"), "note": srow.get("note")}


def _view(run):
    norm = run.get("request") or {}
    res = run.get("resolved") or {}
    cred = norm.get("credential_uuid")
    rows = {s["plan_index"]: s for s in run.get("scans") or []}
    pl = run.get("plan") or {}
    infos = res.get("assets") or {}
    crown = sorted({(i.get("host") or i.get("ip") or u) for u, i in infos.items() if i.get("crown")})
    targets = res.get("targets") or []
    return {"run_id": run["run_id"], "state": run["state"], "created": run["created"], "updated": run["updated"],
            "job_id": run.get("job_id"), "note": run.get("note"), "request": norm,
            "plan_sha256": run.get("plan_sha256"), "multi_plugin": pl.get("multi_plugin"),
            "scans": [_scan_view(ps, cred, rows.get(ps["plan_index"])) for ps in pl.get("scans") or []],
            "preflight": run.get("preflight") or [], "summary": run.get("summary"),
            "targets": len(targets), "targets_sample": targets[:MAX_UI_TARGETS // 10],
            "excluded": len(res.get("excluded") or []), "excluded_sample": (res.get("excluded") or [])[:50],
            "assets": len(infos), "public_targets": sc.public_targets(targets)[:200], "crown": crown[:200],
            "active": sc.is_active(run["run_id"]), "terminal": run["state"] in sc.TERMINAL_STATES}


def plan(p):
    """Normalize → resolve → baseline → plan → preflight; stores a PLANNED run. No Tenable writes."""
    p = dict(p or {})
    via = None
    if p.get("mode") == "oneoff" and p.get("via_scan_id") and not p.get("rerun_scan_id"):
        # send new hosts through an existing scan: its policy + its scanner, on the targets given here
        if not re.match(r"^\d{1,12}$", str(p["via_scan_id"])):
            return {"ok": False, "error": "pick the scan to send the new hosts through"}, 200
        via = sc.via_scan(p["via_scan_id"], sc.lookups())
        if via.get("error"):
            return {"ok": False, "error": via["error"]}, 200
        p.update(policy_id=via["policy_id"], plugins=[], template=None,
                 scanner_id=p.get("scanner_id") or via.get("scanner_id") or "")
    norm, errs = sc.normalize(p)
    if errs:
        return {"ok": False, "error": "; ".join(errs), "errors": errs}, 200
    resolved = sc.resolve(norm)
    if len(resolved["targets"]) > sc.MAX_TARGETS:
        return {"ok": False, "error": "more than %d targets — narrow the selection" % sc.MAX_TARGETS}, 200
    feats = sc.features()
    try:
        pl = sc.plan(norm, resolved, multi_plugin=feats.get("multi_plugin"), named=feats.get("name"))
    except ValueError as e:
        return {"ok": False, "error": str(e)}, 200
    assets = sorted({u for us in resolved["asset_map"].values() for u in us})
    base = sc.baseline(assets, norm["plugins"])
    try:
        lk = sc.lookups()
    except Exception:
        lk = {"scanners": None, "credentials": None, "policies": None, "scans": None}
    ctx = {"write_gate": navi_cli.write_gate_reason(),
           "scan_gate": "" if navi_cli.scan_launch_enabled() else (navi_cli.scan_launch_gate_reason()
                                                                   or "scan launch is off"),
           "scanners": lk.get("scanners"), "credentials": lk.get("credentials"),
           "policies": lk.get("policies"), "scans": lk.get("scans"),
           "scan_direct": (sc.scan_info(norm["rerun_scan_id"]) if norm.get("rerun_scan_id") and not any(
               x.get("id") == norm["rerun_scan_id"] for x in (lk.get("scans") or [])) else None),
           "families": sc.plugin_families(norm["plugins"]), "plugins_known": sc.plugins_known(norm["plugins"]),
           "active_same": sc.active_same(norm["request_sha256"]), "hx_busy": cli_jobs.hx_busy() is not None,
           "chain_locked": cli_jobs.CHAIN_LOCK.locked()}
    checks = sc.preflight(norm, resolved, pl, ctx)
    rid = sc.create_run(norm, resolved, pl, checks, base)
    run_ = sc.get_run(rid)
    names = sc.plugin_names(norm["plugins"])
    fams = ctx["families"]
    local = [pid for pid in norm["plugins"] if sc.is_local(fams.get(pid))]
    open_now = sum(1 for v in base.values() if v.get("state") in ("open", "reopened"))
    sname = next((s.get("name") for s in (lk.get("scanners") or []) if str(s.get("id")) == str(norm.get("scanner_id"))), None)
    cname = next((c.get("name") for c in (lk.get("credentials") or []) if c.get("uuid") == norm.get("credential_uuid")), None)
    pol = norm.get("policy_id")
    pname = next((x.get("name") for x in (lk.get("policies") or []) if x.get("id") == pol), None) if pol else None
    rr = norm.get("rerun_scan_id")
    rname = next((x.get("name") for x in (lk.get("scans") or []) if x.get("id") == rr), None) if rr else None
    return {"ok": True, **_view(run_), "ready": sc.preflight_ok(checks), **_gates(),
            "policy_name": pname, "rerun_name": rname, "via": via,
            "plugin_names": {str(k): v for k, v in names.items()}, "families": {str(k): v for k, v in fams.items()},
            "scanner_name": sname, "credential_name": cname, "features": {k: v for k, v in feats.items() if k != "help"},
            "glance": {"targets": len(resolved["targets"]), "excluded": len(resolved["excluded"]),
                       "scans": len(pl["scans"]), "plugins": len(norm["plugins"]), "local_plugins": len(local),
                       "open_now": open_now, "cred": bool(norm.get("credential_uuid"))}}, 200


def runs(p):
    return {"ok": True, "runs": sc.list_runs(30), **_gates()}, 200


def run_get(p):
    run_, err = _run_of(p)
    if err:
        return err
    return {"ok": True, **_view(run_), **_gates()}, 200


def verdicts(p):
    run_, err = _run_of(p)
    if err:
        return err
    v = (p or {}).get("verdict")
    v = v if v in sc.VERDICTS else None
    try:
        off = max(0, int((p or {}).get("offset") or 0))
        lim = max(1, min(200, int((p or {}).get("limit") or 50)))
    except (TypeError, ValueError):
        off, lim = 0, 50
    out = sc.verdict_rows(run_["run_id"], v, off, lim)
    names = sc.plugin_names(sorted({r["plugin_id"] for r in out["rows"]}))
    for r in out["rows"]:
        r["plugin_name"] = names.get(r["plugin_id"])
    return {"ok": True, **out, "offset": off, "limit": lim}, 200


def _csv_cell(v):
    s = "" if v is None else str(v)
    return ("'" + s) if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def export(p):
    run_, err = _run_of(p)
    if err:
        return err
    rows = sc.verdict_rows(run_["run_id"], None, 0, 1000000)["rows"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["asset_uuid", "target", "host", "plugin_id", "verdict", "rule", "scan_id", "history_id", "time_start",
                "state_now", "last_found_now", "baseline_state", "auth_evidence"])
    for r in rows:
        e = r.get("evidence") or {}
        now = e.get("row") if isinstance(e.get("row"), dict) else {}
        b = e.get("baseline") if isinstance(e.get("baseline"), dict) else {}
        w.writerow([_csv_cell(x) for x in (r["asset_uuid"], r.get("target"), e.get("host"), r["plugin_id"], r["verdict"],
                                           r["rule"], e.get("scan_id"), e.get("history_id"), e.get("time_start"),
                                           now.get("state") or "absent", now.get("last_found"),
                                           b.get("state") or "absent", e.get("auth_evidence"))])
    return {"ok": True, "filename": "scan-confirmation-%s.csv" % run_["run_id"], "csv": buf.getvalue(),
            "rows": len(rows)}, 200


def events(p):
    run_, err = _run_of(p)
    if err:
        return err
    return {"ok": True, "events": sc.events(run_["run_id"]), "chain": sc.verify_chain()}, 200


def job_poll(p):
    """The run's live CLI window (only scan_confirm jobs are readable here)."""
    jid = (p or {}).get("job_id")
    if not str(jid or "").isdigit():
        return {"ok": False, "error": "job_id required"}, 400
    o = cli_jobs.poll(int(jid), int((p or {}).get("since") or 0) if str((p or {}).get("since") or 0).isdigit() else 0)
    job = (o or {}).get("job") or {}
    if not o or not o.get("ok") or job.get("kind") != "scan_confirm":
        return {"ok": False, "error": "no such Scan Confirmation job"}, 404
    return o, 200


def deletable(p):
    days = sc.retention_days()
    rows = sc.deletable_scans(days)
    return {"ok": True, "days": days, "scans": sorted({r["scan_id"] for r in rows}), **_gates()}, 200


# ── writes (gated) ───────────────────────────────────────────────────────────────────────
_LAUNCH_LOCK = __import__("threading").Lock()


def scan_launch(p):
    """Launch a PLANNED run. Idempotent: an already-launched run returns its job. Refuses when the
    plan hash the page saw differs from the stored one, or a preflight check fails now."""
    if not confirmed(p):
        return _need_confirm("this launches Tenable scans")
    b = _blocked()
    if b:
        return b
    run_, err = _run_of(p)
    if err:
        return err
    with _LAUNCH_LOCK:
        run_ = sc.get_run(run_["run_id"])
        if run_["state"] != "PLANNED":
            if sc.is_active(run_["run_id"]) or run_["state"] not in sc.TERMINAL_STATES:
                return {"ok": True, "already": True, "job_id": run_.get("job_id"), "state": run_["state"]}, 200
            return {"ok": False, "error": "this run already finished (%s) — plan again" % run_["state"]}, 200
        if (p or {}).get("plan_sha256") != run_.get("plan_sha256"):
            return {"ok": False, "error": "the plan changed since you reviewed it — press ▶ Plan again",
                    "plan_changed": True}, 200
        bad = [c for c in (run_.get("preflight") or []) if c.get("level") == "fail" and c.get("id") not in ("P1", "P2", "P8", "P9")]
        if bad:
            return {"ok": False, "error": "preflight failed: " + "; ".join("%s %s" % (c["id"], c["msg"]) for c in bad)}, 200
        if sc.active_same(run_["request_sha256"], exclude=run_["run_id"]):
            return {"ok": False, "error": "P8: an identical run is still running"}, 200
        if cli_jobs.hx_busy() is not None or cli_jobs.CHAIN_LOCK.locked():
            return {"ok": False, "error": "P9: navi.db is locked by ⚡ Optimize or an Automation Station chain — try again "
                                          "when it finishes"}, 200
        if cli_jobs.sample_block_reason():
            return {"ok": False, "error": cli_jobs.sample_block_reason()}, 200
        sc.set_state(run_["run_id"], "PREFLIGHT")
        out = sc.start(run_["run_id"])
    return {"ok": True, **out, "run_id": run_["run_id"]}, 200


def _control(p, sub):
    run_, err = _run_of(p)
    if err:
        return None, err
    sid = str((p or {}).get("scan_id") or "")
    ids = {str(s.get("scan_id")) for s in run_["scans"] if s.get("scan_id")}
    if sid and sid not in ids:
        return None, ({"ok": False, "error": "that scan is not part of this run"}, 400)
    targets = [sid] if sid else sorted(ids)
    out = []
    for i in targets:
        argv = sc.build_control_argv(sub, i)
        r = sc._run_capture(argv, sc.STATUS_TIMEOUT_S)
        st = sc.api_read("/scans/%s/latest-status" % i)
        st = sc.norm_status(st.get("status")) if isinstance(st, dict) else None
        sc.event(run_["run_id"], sub, {"scan_id": i, "rc": r.get("rc"), "status_after": st})
        out.append({"scan_id": i, "status_after": st})
    return out, None


def scan_stop(p):
    """■ Stop: cancel the run's task (it stops every running scan and records ABORTED); with
    scan_id, stop just that scan. Every stop is proven by a status read afterwards (F7)."""
    if not confirmed(p):
        return _need_confirm("this stops Tenable scans")
    b = _blocked()
    if b:
        return b
    run_, err = _run_of(p)
    if err:
        return err
    if not (p or {}).get("scan_id") and sc.is_active(run_["run_id"]):
        r = sc.cancel(run_["run_id"])
        return {"ok": bool(r.get("ok")), "message": "stopping — every running scan gets `navi scan stop`, then the run "
                                                    "is recorded as ABORTED", **({"error": r.get("error")} if not r.get("ok") else {})}, 200
    res, err = _control(p, "stop")
    if err:
        return err
    return {"ok": True, "scans": res}, 200


def scan_pause(p):
    if not confirmed(p):
        return _need_confirm("this pauses Tenable scans")
    b = _blocked()
    if b:
        return b
    res, err = _control(p, "pause")
    if err:
        return err
    return {"ok": True, "scans": res, "proven": all(r["status_after"] in ("paused", "pausing") for r in res)}, 200


def scan_resume(p):
    if not confirmed(p):
        return _need_confirm("this resumes Tenable scans")
    b = _blocked()
    if b:
        return b
    res, err = _control(p, "resume")
    if err:
        return err
    return {"ok": True, "scans": res, "proven": all(r["status_after"] in ("running", "resuming", "pending")
                                                    for r in res)}, 200


def scan_resume_watch(p):
    """↻ Resume watching a run left non-terminal (server restart): polls the recorded scan ids;
    nothing is relaunched."""
    if not confirmed(p):
        return _need_confirm("this resumes a run (it syncs navi.db when the scans finish)")
    b = _blocked()
    if b:
        return b
    run_, err = _run_of(p)
    if err:
        return err
    if run_["state"] not in ("LAUNCHING", "RUNNING", "SCANS_DONE", "SYNCING"):
        return {"ok": False, "error": "this run is %s — nothing to resume" % run_["state"]}, 200
    out = sc.start(run_["run_id"], resume=True, label="Scan Confirmation · resume %s" % run_["run_id"])
    return {"ok": True, **out, "run_id": run_["run_id"]}, 200


def scan_reverify(p):
    """↻ Re-verify: the scoped sync + verdicts again (no scan is launched). Gated: it writes navi.db."""
    if not confirmed(p):
        return _need_confirm("this syncs navi.db")
    b = _blocked()
    if b:
        return b
    run_, err = _run_of(p)
    if err:
        return err
    if run_["state"] not in sc.TERMINAL_STATES or sc.is_active(run_["run_id"]):
        return {"ok": False, "error": "the run is still going"}, 200
    rq = run_.get("request") or {}
    if not rq.get("plugins") or not rq.get("verify", True):
        return {"ok": False, "error": "a one-off scan has no verdicts to re-verify"}, 200
    # a target that had no navi.db asset at plan time may have one now
    res = sc.resolve(run_["request"])
    sc.refresh_resolved(run_["run_id"], res)

    def fn(_rid, emit, live, ev):
        try:
            return sc.sync_and_verify(run_["run_id"], emit, live, ev)
        except sc._Abort:
            emit("■ cancelled")
            sc.set_state(run_["run_id"], "VERIFIED", note="re-verify cancelled")
            return {"cancelled": True}
        finally:
            with sc._RUN_LOCK:
                sc._ACTIVE.pop(run_["run_id"], None)
    out = sc.start(run_["run_id"], label="Scan Confirmation · re-verify %s" % run_["run_id"], fn=fn)
    return {"ok": True, **out, "run_id": run_["run_id"]}, 200


def scan_delete_old(p):
    """🗑 Delete old confirmation scans — only scans THIS agent created, older than
    NAVI_SCAN_RETENTION_DAYS; each delete is proven by a read (the scan no longer reads)."""
    if not confirmed(p):
        return _need_confirm("this deletes Tenable scans")
    b = _blocked()
    if b:
        return b
    rows = sc.deletable_scans(sc.retention_days())
    ids = sorted({r["scan_id"] for r in rows})
    want = (p or {}).get("scan_ids")
    if isinstance(want, list):
        ids = [i for i in ids if i in {str(x) for x in want}]
    done, failed = [], []
    for i in ids[:200]:
        sc._run_capture(sc.build_delete_argv(i), sc.STATUS_TIMEOUT_S)
        gone = sc.api_read("/scans/%s/history" % i) is None
        if gone:
            sc.mark_deleted(i)
            done.append(i)
        else:
            failed.append(i)
        sc.event("-", "delete_scan", {"scan_id": i, "gone": gone})
    return {"ok": True, "deleted": done, "failed": failed, "at": time.time()}, 200


ACTIONS = {"run": run, "status": status, "lookups": lookups, "plugin_info": plugin_info, "plan": plan, "runs": runs,
           "run_get": run_get, "scan_lookup": scan_lookup, "verdicts": verdicts, "export": export, "events": events, "job_poll": job_poll,
           "deletable": deletable, "scan_launch": scan_launch, "scan_stop": scan_stop, "scan_pause": scan_pause,
           "scan_resume": scan_resume, "scan_resume_watch": scan_resume_watch, "scan_reverify": scan_reverify,
           "scan_delete_old": scan_delete_old}
