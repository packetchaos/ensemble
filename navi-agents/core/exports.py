"""Background CSV exports (build 525) — every ⤓ CSV gets ALL of its rows.

A page never holds more than a chunk of a big list (core.payload), so a CSV built in the browser
from what is on screen is only part of the data. Every export now goes through here:

  * up to INLINE_MAX (5,000) rows — built in the request and handed straight back ({inline, csv});
  * more than that — a BACKGROUND JOB (core.cli_jobs.start_task, so it shows in Settings' CLI
    window and Recent runs like any navi run) writes the whole list to a file under the cache dir;
    the page polls `export_status` and pulls the finished file in pieces with `export_fetch`
    (one Blob, one download). No row cap.

Two engines:
  * navi  — a SQL source over navi.db runs as `navi export query "<sql>"` (navi exports the entire
            list). navi runs in a private temp folder whose `navi.db` is a symlink to the database the
            console reads, so its query_data.csv never collides with another export or the user's
            files. Its output is then re-written cell by cell through csv_safe() (spreadsheet formula
            neutralising — navi writes cells raw).
  * python — a result-store section, an app log, a SQL source when navi isn't installed / the
            sample DB is in use / the statement is too long for a command line: rows are streamed
            straight to the file (never all in memory).

Nothing here writes to Tenable or navi.db: exports are reads. Files are kept KEEP_SEC (24 h) and
the newest KEEP_N; ids are random hex, and the fetch path is always <exports dir>/<id>.csv.
"""
import csv
import io
import json
import os
import re
import secrets
import shutil
import tempfile
import threading
import time

INLINE_MAX = int(os.environ.get("NAVI_EXPORT_INLINE_MAX", "5000"))
CHUNK_BYTES = 4 * 1024 * 1024
KEEP_SEC = 24 * 3600
KEEP_N = 30
NAVI_TIMEOUT_S = 6 * 3600            # owner's rule: nothing under 2 h — a full export can be long
_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_FORMULA = ("=", "+", "-", "@", "\t", "\r")
_LOCK = threading.Lock()
_EXPORTS = {}                        # id -> entry (in memory; the files outlive a restart until pruned)


def csv_safe(v):
    """A text cell starting with = + - @ TAB CR gets a leading ' (the acrlog rule, everywhere)."""
    if isinstance(v, str) and v.startswith(_FORMULA):
        return "'" + v
    return v


def cell(v):
    """A row value as one CSV cell: lists of scalars joined with '; ', anything nested as JSON."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple, set)):
        vals = list(v)
        if all(not isinstance(x, (dict, list, tuple, set)) for x in vals):
            return csv_safe("; ".join("" if x is None else str(x) for x in vals))
        return csv_safe(json.dumps(vals, default=str, ensure_ascii=False))
    if isinstance(v, dict):
        return csv_safe(json.dumps(v, default=str, ensure_ascii=False))
    return csv_safe(v)


def _dir():
    from core import snapcache
    d = os.path.join(snapcache.CACHE_DIR, "exports")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def _path(eid):
    return os.path.join(_dir(), eid + ".csv")


def safe_name(name):
    n = re.sub(r"[^A-Za-z0-9._ -]+", "-", str(name or "export")).strip(" .-")[:80] or "export"
    return n if n.lower().endswith(".csv") else n + ".csv"


def _prune():
    now = time.time()
    try:
        for f in os.listdir(_dir()):
            p = os.path.join(_dir(), f)
            try:
                if now - os.path.getmtime(p) > KEEP_SEC:
                    shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.unlink(p)
            except OSError:
                pass
    except OSError:
        pass
    with _LOCK:
        old = sorted(_EXPORTS.values(), key=lambda e: e["created"])
        for e in old[:-KEEP_N] if len(old) > KEEP_N else []:
            if e["status"] != "running":
                _EXPORTS.pop(e["id"], None)
                try:
                    os.unlink(_path(e["id"]))
                except OSError:
                    pass


def _view(e):
    return {k: e.get(k) for k in ("id", "name", "status", "rows", "total", "bytes", "engine", "job_id",
                                  "created", "finished", "error", "agent")}


# --------------------------------------------------------------------------- sources
def inline_sql(sql, args=()):
    """`sql` with its ? placeholders replaced by SQL literals (navi takes one statement, no
    parameters). Strings are quoted with '' doubling; a ? inside a quoted literal is left alone."""
    out, ai, i, n = [], 0, 0, len(sql)
    args = list(args or ())
    while i < n:
        ch = sql[i]
        if ch in ("'", '"'):
            j = i + 1
            while j < n:
                if sql[j] == ch:
                    if j + 1 < n and sql[j + 1] == ch:
                        j += 2
                        continue
                    break
                j += 1
            out.append(sql[i:j + 1])
            i = j + 1
            continue
        if ch == "?":
            if ai >= len(args):
                raise ValueError("more placeholders than arguments")
            v = args[ai]
            ai += 1
            if v is None:
                out.append("NULL")
            elif isinstance(v, bool):
                out.append("1" if v else "0")
            elif isinstance(v, (int, float)):
                out.append(repr(v))
            else:
                s = str(v)
                if "\x00" in s:
                    raise ValueError("NUL in an export argument")
                out.append("'" + s.replace("'", "''") + "'")
            i += 1
            continue
        out.append(ch)
        i += 1
    if ai != len(args):
        raise ValueError("more arguments than placeholders")
    return "".join(out)


def _sql_rows(sql, args, path=None, trusted=False):
    """(header, row iterator) for a read-only SQL source, streamed from navi.db. SQL a person or
    a model wrote (trusted=False) runs under the user-SQL guard — navi's credential tables stay
    unreadable (core.db.harden)."""
    from core import db
    con = db.connect(path)
    if not trusted:
        db.harden(con)
    cur = con.execute(sql, tuple(args or ()))
    header = [d[0] for d in (cur.description or [])]

    def gen():
        try:
            while True:
                b = cur.fetchmany(2000)
                if not b:
                    break
                for r in b:
                    yield list(r)
        finally:
            con.close()
    return header, gen()


def _dict_rows(it, header=None):
    """(header, list-rows) from an iterator of dicts. The header is the given one, else the union
    of keys over the first 1,000 rows (in first-seen order)."""
    it = iter(it)
    head = []
    if header:
        cols = list(header)
    else:
        cols = []
        for r in it:
            head.append(r)
            for k in (r or {}):
                if k not in cols and not str(k).startswith("_"):
                    cols.append(k)
            if len(head) >= 1000:
                break

    def gen():
        for r in head:
            yield [(r or {}).get(c) for c in cols]
        for r in it:
            yield [(r or {}).get(c) for c in cols]
    return cols, gen()


def _write(fh, header, rows, progress=None, cancel=None):
    w = csv.writer(fh, lineterminator="\r\n")
    w.writerow([csv_safe(h) for h in header])
    n = 0
    for r in rows:
        w.writerow([cell(v) for v in r])
        n += 1
        if n % 5000 == 0:
            if progress:
                progress(n)
            if cancel is not None and cancel.is_set():
                raise InterruptedError("cancelled")
    return n


# --------------------------------------------------------------------------- navi engine
def navi_ready(sql=""):
    """navi can run this export: installed, a real navi.db (not the bundled sample), the
    statement fits on a command line, and the owner hasn't forced the python engine."""
    from core import db, navi_cli
    if (os.environ.get("NAVI_EXPORT_ENGINE") or "").strip().lower() == "python":
        return False
    try:
        if not navi_cli._resolve_navi():
            return False
        p = db.db_path()
    except Exception:
        return False
    if not p or p.endswith("sample_navi.db") or not os.path.isfile(p):
        return False
    return not navi_cli.arg_too_big(sql)


def _navi_export(sql, out_path, emit, live, cancel):
    """`navi export query <sql>` in a private folder (navi.db → the console's database), then the
    file re-written through csv_safe into out_path. → rows written."""
    from core import cli_jobs, db
    work = tempfile.mkdtemp(prefix="nv-", dir=_dir())
    try:
        os.symlink(os.path.abspath(db.db_path()), os.path.join(work, "navi.db"))
        r = cli_jobs.run_navi_streamed(["export", "query", sql], emit, live, cancel, NAVI_TIMEOUT_S, cwd=work)
        if r.get("cancelled"):
            raise InterruptedError("cancelled")
        if r.get("timed_out"):
            raise RuntimeError("navi export timed out")
        made = [f for f in os.listdir(work) if f.lower().endswith(".csv")]
        if r.get("rc") != 0 or not made:
            raise RuntimeError("navi export query wrote no file (exit %s)" % r.get("rc"))
        src = os.path.join(work, made[0])
        csv.field_size_limit(1 << 30)
        live("re-writing %s through the spreadsheet-safety pass…" % made[0])
        with open(src, newline="", encoding="utf-8", errors="replace") as fi, \
                open(out_path, "w", newline="", encoding="utf-8") as fo:
            rd = csv.reader(fi)
            header = next(rd, [])
            return _write(fo, header, rd, progress=lambda n: live("%s rows checked" % format(n, ",")), cancel=cancel)
    finally:
        shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------- the API
def start(name, *, sql=None, args=(), rows=None, header=None, total=None, agent="", path=None,
          force_job=False, trusted=False):
    """Export a source to CSV. Exactly one of `sql` (+args, a read over navi.db) or `rows`
    (a zero-arg callable → iterable of dicts, or of lists when `header` is given).
    trusted=True ONLY for SQL the server built itself: that SQL may run through navi (which has no
    user-SQL guard). Anything a person or a model wrote stays on the guarded python engine.
    total ≤ INLINE_MAX (and not force_job) → {"ok", "inline": True, "csv", "rows", "filename"};
    otherwise a background job → {"ok", "inline": False, "export": view, "job": …}."""
    if (sql is None) == (rows is None):
        raise ValueError("give sql or rows")
    fname = safe_name(name)
    if total is not None and int(total) <= INLINE_MAX and not force_job:
        buf = io.StringIO()
        if sql is not None:
            h, it = _sql_rows(sql, args, path, trusted)
        else:
            h, it = (header, (list(r) for r in rows())) if header else _dict_rows(rows())
        n = _write(buf, h, it)
        return {"ok": True, "inline": True, "csv": buf.getvalue(), "rows": n, "filename": fname}
    _prune()
    eid = secrets.token_hex(8)
    e = {"id": eid, "name": fname, "status": "running", "rows": 0, "total": total, "bytes": 0,
         "engine": None, "job_id": None, "created": time.time(), "finished": None, "error": None,
         "agent": agent}
    with _LOCK:
        _EXPORTS[eid] = e
    use_navi = bool(trusted) and sql is not None and navi_ready(inline_sql(sql, args) if args else sql)
    e["engine"] = "navi" if use_navi else "python"

    def fn(emit, live, cancel):
        out = _path(eid)
        tmp = out + ".part"
        try:
            if use_navi:
                q = inline_sql(sql, args) if args else sql
                emit("navi export query → %s (%s rows expected)" % (fname, "?" if total is None else format(total, ",")))
                n = _navi_export(q, tmp, emit, live, cancel)
            else:
                emit("exporting %s (%s rows expected)" % (fname, "?" if total is None else format(total, ",")))

                def prog(k):
                    e["rows"] = k
                    live("%s rows written" % format(k, ","))
                with open(tmp, "w", newline="", encoding="utf-8") as fh:
                    if sql is not None:
                        h, it = _sql_rows(sql, args, path, trusted)
                    else:
                        h, it = (header, (list(r) for r in rows())) if header else _dict_rows(rows())
                    n = _write(fh, h, it, progress=prog, cancel=cancel)
            os.replace(tmp, out)
            e.update(status="done", rows=n, bytes=os.path.getsize(out), finished=time.time())
            emit("✓ %s rows · %.1f MB → ready to download" % (format(n, ","), e["bytes"] / 1048576.0))
            return {"ok": True}
        except InterruptedError:
            e.update(status="cancelled", finished=time.time())
            return {"ok": False, "cancelled": True}
        except Exception as ex:                    # noqa: BLE001 — reported in the job + the page
            e.update(status="error", error=str(ex)[:300], finished=time.time())
            emit("[error] %s" % ex)
            return {"ok": False}
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    from core import cli_jobs
    cmd = ("navi export query … → " if use_navi else "export → ") + fname
    r = cli_jobs.start_task("Export · " + fname, "export", fn, cmd=cmd)
    e["job_id"] = (r.get("job") or {}).get("id")
    return {"ok": True, "inline": False, "export": _view(e), "job": r.get("job")}


def get(eid):
    if not isinstance(eid, str) or not _ID_RE.match(eid):
        return None
    with _LOCK:
        return _EXPORTS.get(eid)


def status(eid):
    e = get(eid)
    if not e:
        return {"ok": False, "error": "no such export (it may have expired — export again)"}
    return {"ok": True, "export": _view(e)}


def fetch(eid, offset=0):
    """One piece of a finished export: ≤ CHUNK_BYTES, cut at a line end so the text is whole
    UTF-8. → {ok, text, offset, next (None at the end), size, name}."""
    e = get(eid)
    if not e:
        return {"ok": False, "error": "no such export (it may have expired — export again)"}
    if e["status"] != "done":
        return {"ok": False, "error": "the export is %s" % e["status"]}
    try:
        off = max(0, int(offset or 0))
    except (TypeError, ValueError):
        return {"ok": False, "error": "bad offset"}
    p = _path(eid)
    try:
        size = os.path.getsize(p)
        with open(p, "rb") as fh:
            fh.seek(off)
            b = fh.read(CHUNK_BYTES)
            if off + len(b) < size and not b.endswith(b"\n"):
                more = b""
                while off + len(b) + len(more) < size and b"\n" not in more:
                    more += fh.read(65536)
                    if len(more) > 8 * 1024 * 1024:
                        break
                cut = more.find(b"\n")
                b += more[:cut + 1] if cut >= 0 else more
    except OSError:
        return {"ok": False, "error": "the export file is gone — export again"}
    nxt = off + len(b)
    return {"ok": True, "text": b.decode("utf-8", "replace"), "offset": off,
            "next": nxt if nxt < size else None, "size": size, "name": e["name"]}


def cancel(eid):
    e = get(eid)
    if not e:
        return {"ok": False, "error": "no such export"}
    if e["status"] != "running" or e.get("job_id") is None:
        return {"ok": True, "export": _view(e)}
    from core import cli_jobs
    cli_jobs.cancel(e["job_id"])
    return {"ok": True, "export": _view(e)}


def recent():
    with _LOCK:
        return [_view(e) for e in sorted(_EXPORTS.values(), key=lambda x: -x["created"])][:KEEP_N]


# --------------------------------------------------------------------------- result-store sections
_SEC_RE = re.compile(r"^[a-z0-9_]{1,40}$")
_FLAG_RE = re.compile(r"^[A-Za-z0-9_:.\- ]{1,80}$")


def store_export(p, name=None):
    """Export a stored run's section (any hDrill table) — every row, with the page's filter and
    search. p = {run, section, filter?, q?, name?}."""
    from core import payload
    p = p or {}
    run, sec = p.get("run"), p.get("section")
    if not isinstance(sec, str) or not _SEC_RE.match(sec):
        return {"ok": False, "error": "unknown section"}
    info = payload.STORE.run_info(run) if isinstance(run, str) else None
    if not info:
        return {"ok": False, "expired": True, "error": "this run's rows are no longer on the server — press ▶ Run again"}
    flt = p.get("filter") or []
    flt = [flt] if isinstance(flt, str) else flt
    if not isinstance(flt, list) or len(flt) > 6 or not all(isinstance(f, str) and _FLAG_RE.match(f) for f in flt):
        return {"ok": False, "error": "bad filter"}
    q = p.get("q") or ""
    if not isinstance(q, str) or len(q) > 200:
        return {"ok": False, "error": "bad search"}
    q = q.strip().lower()
    st = payload.STORE
    if not flt and not q:
        n = st.section_total(run, sec)
    else:
        rows, _l, n, _e = st.page(run, sec, flags=flt, q=q, limit=1)
    hound = run.rsplit("-", 1)[0]
    r = start(name or p.get("name") or ("%s-%s" % (hound, sec)), rows=lambda: st.iter_rows(run, sec, flt, q),
              total=n, agent=hound)
    r["total"] = n
    return r


def start_sql(name, sql, args=(), agent="", trusted=False, path=None):
    """A SQL source, sized first with a capped count (never a full COUNT over a huge table):
    ≤ INLINE_MAX rows → at once, more → a background job (via navi when trusted)."""
    from core import db
    q = "SELECT COUNT(*) AS n FROM (SELECT 1 FROM (%s\n) LIMIT %d)" % (sql, INLINE_MAX + 1)
    rows = (db.query(q, tuple(args or ()), path=path) if trusted
            else db.user_query(q, tuple(args or ()), path=path))
    n = int((rows[0] if rows else {}).get("n") or 0)
    if n <= INLINE_MAX:
        return start(name, sql=sql, args=args, total=n, agent=agent, path=path, trusted=trusted)
    return start(name, sql=sql, args=args, total=None, agent=agent, path=path, trusted=trusted, force_job=True)
