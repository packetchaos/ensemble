"""Robust certificate-date parsing.

navi.db can store `certs.not_valid_after` in several formats depending on the
Tenable/plugin source: the OpenSSL/x509 form 'Apr 03 16:07:23 2027 GMT', ISO
'2027-04-03T16:07:23', 'YYYY/MM/DD', US 'MM/DD/YYYY', 'Mon DD, YYYY', 'DD Mon YYYY',
or a Unix epoch. A parser that only understands one of these silently returns 0
(e.g. the Sphinx / insights cert tile showing 0 while certs are really failing).
`parse_cert_date` tries them all and returns a datetime.date (or None).
"""
from core.errors import swallowed as _swallowed  # no silent excepts
import datetime
import re

_MON = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_cert_date(s):
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None

    # OpenSSL / x509:  'Apr 03 16:07:23 2027 [GMT]'   (single OR double space before day)
    m = re.match(r"([A-Za-z]{3})\s+(\d{1,2})\s+[\d:]+\s+(\d{4})", s)
    if m and m.group(1).title() in _MON:
        try:
            return datetime.date(int(m.group(3)), _MON[m.group(1).title()], int(m.group(2)))
        except Exception as _e:
            _swallowed(_e)

    # ISO / dashed / slashed year-first:  '2027-04-03...'  '2027/04/03'
    m = re.match(r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})", s)
    if m:
        try:
            return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except Exception as _e:
            _swallowed(_e)

    # US month-first:  'MM/DD/YYYY'  or 'MM-DD-YYYY'
    m = re.match(r"(\d{1,2})[/-](\d{1,2})[/-](\d{4})$", s.split()[0] if s else s)
    if m:
        try:
            return datetime.date(int(m.group(3)), int(m.group(1)), int(m.group(2)))
        except Exception as _e:
            _swallowed(_e)

    # 'Mon DD, YYYY'  /  'Mon DD YYYY'
    m = re.match(r"([A-Za-z]{3,})\s+(\d{1,2}),?\s+(\d{4})", s)
    if m and m.group(1)[:3].title() in _MON:
        try:
            return datetime.date(int(m.group(3)), _MON[m.group(1)[:3].title()], int(m.group(2)))
        except Exception as _e:
            _swallowed(_e)

    # 'DD Mon YYYY'
    m = re.match(r"(\d{1,2})\s+([A-Za-z]{3,})\s+(\d{4})", s)
    if m and m.group(2)[:3].title() in _MON:
        try:
            return datetime.date(int(m.group(3)), _MON[m.group(2)[:3].title()], int(m.group(1)))
        except Exception as _e:
            _swallowed(_e)

    # Unix epoch (seconds or millis)
    if re.fullmatch(r"\d{10,13}", s):
        try:
            ts = int(s)
            if ts > 1e12:
                ts //= 1000
            return datetime.datetime.utcfromtimestamp(ts).date()
        except Exception as _e:
            _swallowed(_e)

    # Last resort: Python's own ISO parser
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "").strip()).date()
    except Exception:
        return None
