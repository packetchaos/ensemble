"""Write web/assets/brand.js from core/brand.py (the single source of truth for the UI's names).

Run:  python3 tools/brand_js.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from core import brand  # noqa: E402

OUT = os.path.join(ROOT, "web", "assets", "brand.js")


def render():
    data = json.dumps(brand.as_dict(), ensure_ascii=False, indent=1, sort_keys=False)
    return ("/* navi Ensemble — the UI's names, written by tools/brand_js.py from core/brand.py.\n"
            "   Do not edit by hand: change core/brand.py and re-run the tool. */\n"
            "window.BRAND = " + data + ";\n"
            "/* \"Codename · Plain job\" for a hero, the plain name for everyone else */\n"
            "window.brandName = function(id){ var r=(window.BRAND.roster||{})[id]; if(!r) return id;"
            " return (r.hero && r.codename) ? r.codename+' · '+r.name : r.name; };\n"
            "window.brandTitle = function(page){ return page ? page+' — '+window.BRAND.brand : window.BRAND.brand; };\n")


if __name__ == "__main__":
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(render())
    print("wrote", os.path.relpath(OUT, ROOT))
