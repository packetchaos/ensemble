"""Crown jewels — ONE definition for every page (build 527).

A crown jewel is an asset whose Asset Criticality Rating (ACR) is at or above the threshold set in
Settings → Crown jewels (NAVI_CROWN_ACR, default 8). Before this build every specialist carried
its own line — ACR > 7, ≥ 7 or ≥ 9 — so the same asset could be a crown jewel on one page and not
on the next. Every specialist, widget, evidence list and prompt now asks this module.

ACR comes from Tenable (and Criticality Calibration): tag your business-critical assets there and
they become crown jewels everywhere at once.

The threshold is part of navi.db's cache signature (snapcache.db_signature, launcher._db_sig,
dashmetrics.fingerprint), so changing it in Settings makes every cached result rebuild.
"""
import os

ENV = "NAVI_CROWN_ACR"
DEFAULT = 8
MIN, MAX = 1, 10


def threshold() -> int:
    """The crown-jewel ACR line (an int 1–10); DEFAULT when unset or not a number."""
    v = (os.environ.get(ENV) or "").strip()
    try:
        n = int(float(v))
    except ValueError:
        return DEFAULT
    return n if MIN <= n <= MAX else DEFAULT


def valid(v):
    """(ok, int or None, error) for a value typed in Settings."""
    s = str(v if v is not None else "").strip()
    if s == "":
        return True, None, ""
    try:
        f = float(s)
    except ValueError:
        return False, None, "Crown-jewel ACR must be a whole number from 1 to 10."
    if f != int(f) or not MIN <= int(f) <= MAX:
        return False, None, "Crown-jewel ACR must be a whole number from 1 to 10."
    return True, int(f), ""


def is_crown(acr) -> bool:
    try:
        return acr is not None and acr != "" and float(acr) >= threshold()
    except (TypeError, ValueError):
        return False


def sql(expr="acr") -> str:
    """A SQL predicate: the ACR expression is at or above the line (blank / NULL = not a crown jewel)."""
    return "(CAST(COALESCE(NULLIF(%s,''),0) AS REAL) >= %d)" % (expr, threshold())


def label() -> str:
    return "ACR ≥ %d" % threshold()


def definition() -> dict:
    t = threshold()
    return {"acr_min": t, "label": "ACR ≥ %d" % t, "default": DEFAULT,
            "text": "A crown jewel is an asset with an Asset Criticality Rating of %d or higher "
                    "(Settings → Crown jewels)." % t}


def sig() -> str:
    """Appended to the cache signatures: a new line rebuilds every cached result."""
    return "crown=%d" % threshold()


TOKEN = "{CROWN}"


def fill(o):
    """Static text (evidence labels, widget titles, briefing cards…) writes the line as {CROWN};
    this puts the live definition in ("ACR ≥ 8"). Recurses through dicts / lists; returns a copy."""
    if isinstance(o, str):
        return o.replace(TOKEN, label()) if TOKEN in o else o
    if isinstance(o, dict):
        return {k: fill(v) for k, v in o.items()}
    if isinstance(o, list):
        return [fill(v) for v in o]
    if isinstance(o, tuple):
        return tuple(fill(v) for v in o)
    return o
