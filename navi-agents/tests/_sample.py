"""Shared test helper: the bundled demo database (sample_navi.db).

A fresh clone doesn't contain sample_navi.db — run.py builds it on first start. Tests that copy it
call ensure_sample(ROOT) instead of joining the path themselves, so the suite also runs straight
after a clone: the fixture is built the same way run.py builds it (make_sample_db.py, in the repo
root) when it is missing, then its path is returned.
"""
import os
import subprocess
import sys


def ensure_sample(root):
    path = os.path.join(root, "sample_navi.db")
    if not os.path.exists(path):
        subprocess.run([sys.executable, "make_sample_db.py"], cwd=root, check=True,
                       stdout=subprocess.DEVNULL)
    return path
