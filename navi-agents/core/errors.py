"""Deliberately ignored exceptions — counted and logged instead of vanishing (build 529).

Many best-effort paths (a cache that can't be written, a log line that can't be appended, an
optional enrichment that fails) must never break the action they decorate. They used to read
`except Exception: pass`, so a real bug there was invisible. They now call `swallowed(e)`:

  * every call site is counted (`counts()`, shown in /api/health as `swallowed_errors`);
  * the 1st, 10th, 100th, 1000th… occurrence at a site is logged to the `hounds.swallowed`
    logger — DEBUG by default, WARNING when HOUNDS_LOG_SWALLOWED=1 (so a noisy loop can't
    flood the log, and an operator chasing a problem can turn it up without a code change).

Standard library only; never raises.
"""
import logging
import os
import sys
import threading

_log = logging.getLogger("hounds.swallowed")
_lock = threading.Lock()
_seen: dict = {}


def _loud() -> bool:
    return (os.environ.get("HOUNDS_LOG_SWALLOWED") or "").strip().lower() in ("1", "true", "yes", "on")


def swallowed(exc=None):
    """Record an exception the caller has decided to ignore. Call it from the except block."""
    try:
        f = sys._getframe(1)
        key = "%s:%d" % (os.path.relpath(f.f_code.co_filename, os.path.dirname(os.path.dirname(__file__))),
                         f.f_lineno)
        with _lock:
            n = _seen.get(key, 0) + 1
            _seen[key] = n
        if n == 1 or n in (10, 100, 1000) or n % 10000 == 0:
            _log.log(logging.WARNING if _loud() else logging.DEBUG, "ignored %s at %s (x%d): %s",
                     type(exc).__name__ if exc is not None else "error", key, n, str(exc)[:300] if exc is not None else "")
    except BaseException:                 # the recorder itself must never break the caller
        return


def counts() -> dict:
    """{ "core/x.py:123": times } for every call site that has swallowed something."""
    with _lock:
        return dict(_seen)


def total() -> int:
    with _lock:
        return sum(_seen.values())
