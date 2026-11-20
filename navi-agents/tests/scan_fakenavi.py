#!/usr/bin/env python3
"""A fake `navi` for the Scan Confirmation tests (NAVI_BIN=<this file>). No network, no Tenable.

It reproduces the REAL output strings of navi/plugins/scan.py and explore api (SCAN_CONFIRM_SPEC §1):
  · `scan create` print()s the payload dict (credential uuid inside), then
    "I started your scan, your scan ID is: N"; without --scanner it calls input() (F2);
  · start / stop / pause / resume / status exit 0 even when they did nothing (F7);
  · `scan status` prints "Last Status update : <status>" (F9);
  · `explore api <url> -raw` prints a Python dict repr, or None for an unknown scan (F10).
`config update vulns` writes rows into the fixture navi.db ($NAVI_DB_PATH) from the scenario —
`--since` returns state CHANGES only, `--days 1` re-observes still-open findings (the blind spot).

Env: FAKE_NAVI_LOG (argv, one JSON line per call), FAKE_SCAN_STATE (JSON state file),
FAKE_SCAN_SCENARIO (JSON): {"results": {"ip|plugin": "open"|"fixed"|"absent"}, "reads_to_complete": 2,
"start_noop": false, "hosts_missing": [ip], "no_ingest": [ip], "cred": {ip: "yes"|"no"}, "multi": false}
"""
import json
import os
import sqlite3
import sys
import time
import uuid as _uuid

argv = sys.argv[1:]
if os.environ.get("FAKE_NAVI_LOG"):
    with open(os.environ["FAKE_NAVI_LOG"], "a") as f:
        f.write(json.dumps(argv) + "\n")
SCN = json.load(open(os.environ["FAKE_SCAN_SCENARIO"])) if os.environ.get("FAKE_SCAN_SCENARIO") else {}
SP = os.environ.get("FAKE_SCAN_STATE") or "/tmp/fake_scan_state.json"


def load():
    try:
        return json.load(open(SP))
    except (OSError, ValueError):
        return {"next": 9001, "scans": {}}


def save(st):
    json.dump(st, open(SP, "w"))


def opt(name, many=False):
    out = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == name]
    return out if many else (out[-1] if out else None)


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(t))


st = load()
if "13" not in st["scans"]:                   # the scan Casey sends new hosts through — old, so last in the list
    st["scans"]["13"] = {"targets": ["10.1.99.13"], "plugins": [], "name": "New hosts", "policy_id": 1313, "enabled": True,
                         "modified": int(time.time()) - 400 * 86400,
                         "history": [{"id": 130, "uuid": str(_uuid.uuid4()), "status": "completed",
                                      "time_start": int(time.time()) - 400 * 86400}], "reads": 0}
    save(st)
if "500" not in st["scans"]:                  # an existing scan someone built in the UI (policy 77)
    st["scans"]["500"] = {"targets": ["10.1.0.3"], "plugins": [], "name": "Weekly internal", "policy_id": 77,
                          "history": [{"id": 5000, "uuid": str(_uuid.uuid4()), "status": "completed",
                                       "time_start": int(time.time()) - 86400}], "reads": 0}
    st["scans"]["501"] = {"targets": ["10.1.0.4"], "plugins": [], "name": "PCI quarterly", "policy_id": 88,
                          "history": [{"id": 5010, "uuid": str(_uuid.uuid4()), "status": "running",
                                       "time_start": int(time.time()) - 60}], "reads": -10 ** 9}
    save(st)
cmd = argv[:2]

if cmd == ["scan", "create"]:
    if "--help" in argv:
        print("Usage: navi scan create [OPTIONS] TARGETS\n\nOptions:\n  --plugin TEXT   Plugin ID"
              + (" — may be given multiple times" if SCN.get("multi") else "")
              + "\n  --scanner TEXT  Scanner ID\n  --policy TEXT   Policy ID\n  --cred TEXT     Credential UUID\n  --help")
        sys.exit(0)
    targets = argv[2]
    if not opt("--scanner"):
        print("Here are your scanners:\n  1234 lab scanner")
        sys.stdout.flush()
        input("Which scanner would you like to use? ")       # EOF on /dev/null → traceback, exit 1
    sid = str(st["next"])
    st["next"] += 1
    payload = {"uuid": "ab3c4330-0e4e-4b2a-a0f3-35aeb0f0c1f1", "settings": {"name": "navi Created Scan of " + targets,
               "enabled": True, "scanner_id": opt("--scanner"), "text_targets": targets},
               "plugins": opt("--plugin", many=True), "credentials": {"add": {"Host": {"SSH": [{"id": opt("--cred")}]}}}}
    print(payload)                                         # navi print()s the payload dict (F6)
    st["scans"][sid] = {"targets": targets.split(","), "plugins": [int(p) for p in opt("--plugin", many=True)],
                        "policy_id": int(opt("--policy")) if opt("--policy") else None,
                        "history": [{"id": int(sid) * 10, "uuid": str(_uuid.uuid4()), "status": "running",
                                     "time_start": int(time.time()) - 5}], "reads": 0}
    save(st)
    print("I started your scan, your scan ID is: %s" % sid)
    sys.exit(0)

if argv[:1] == ["scan"] and len(argv) >= 3 and argv[1] in ("start", "stop", "pause", "resume", "status"):
    s = st["scans"].get(argv[2])
    if not s:
        print("Something went wrong")                    # swallowed error, exit 0 (F7)
        sys.exit(0)
    h = s["history"][-1]
    if argv[1] == "start":
        if not SCN.get("start_noop"):
            s["history"].append({"id": h["id"] + 1, "uuid": str(_uuid.uuid4()), "status": "running",
                                 "time_start": int(time.time()) - 5})
            s["reads"] = 0
        print("I started your scan")
    elif argv[1] == "stop":
        h["status"] = "canceled"
    elif argv[1] == "pause":
        h["status"] = "paused"
    elif argv[1] == "resume":
        h["status"] = "running"
    elif argv[1] == "status":
        print("Last Status update : %s" % h["status"])
    save(st)
    sys.exit(0)

if cmd == ["explore", "api"]:
    url = argv[2]
    if url == "/scanners":
        print({"scanners": [{"id": 1234, "uuid": "00000000-0000-0000-0000-00000000aaaa", "name": "lab scanner",
                             "status": "on", "type": "managed"}]})
        sys.exit(0)
    if url == "/credentials":
        print({"credentials": [{"uuid": "11111111-2222-3333-4444-555555555555", "name": "lab ssh",
                                "type": {"name": "SSH"}, "category": {"name": "Host"}}]})
        sys.exit(0)
    if url == "/policies":
        print({"policies": [{"id": 77, "name": "Internal Basic", "description": "", "template_uuid": "t-1"}]})
        sys.exit(0)
    if url == "/scans":
        print({"folders": [], "scans": [{"id": int(k), "name": v.get("name") or "navi Created Scan of " + ",".join(v["targets"]),
                                         "status": v["history"][-1]["status"], "uuid": "u-" + k, "type": "remote",
                                         "policy_id": v.get("policy_id", 1000 + int(k)), "enabled": v.get("enabled", k != "501"),
                                         "last_modification_date": v.get("modified") or v["history"][-1]["time_start"]}
                                        for k, v in st["scans"].items()]})
        sys.exit(0)
    parts = url.split("?")[0].strip("/").split("/")
    s = st["scans"].get(parts[1]) if len(parts) > 1 else None
    if not s:
        print("None")
        sys.exit(0)
    h = s["history"][-1]
    if parts[2:] == ["history"]:
        print({"pagination": {"total": len(s["history"])}, "history": s["history"]})
    elif parts[2:] == ["latest-status"]:
        s["reads"] += 1
        if h["status"] == "running" and s["reads"] >= int(SCN.get("reads_to_complete", 2)):
            h["status"] = "completed"
            h["time_end"] = int(time.time())
        save(st)
        print({"status": h["status"], "id": h["id"]})
    elif parts[2:] == []:
        miss = set(SCN.get("hosts_missing") or [])
        print({"info": {"status": h["status"], "name": s.get("name") or "navi Created Scan of " + ",".join(s["targets"]),
                        "scanner_name": "lab scanner", "targets": ",".join(s["targets"]), "policy": "p"}, "hosts": [{"host_id": i, "hostname": t} for i, t in
                                                           enumerate(s["targets"]) if t not in miss],
               "vulnerabilities": []})
    else:
        print("None")
    sys.exit(0)

if argv[:3] == ["config", "update", "vulns"]:
    p = int(opt("--plugin_id"))
    since = opt("--since")
    days = opt("--days")
    con = sqlite3.connect(os.environ["NAVI_DB_PATH"])
    n = 0
    for s in st["scans"].values():
        h = s["history"][-1]
        if h["status"] != "completed" or (p not in s["plugins"] and p != 19506):
            continue
        t0 = h["time_start"]
        for ip in s["targets"]:
            if ip in (SCN.get("no_ingest") or []) or ip in (SCN.get("hosts_missing") or []):
                continue
            a = con.execute("SELECT uuid FROM assets WHERE ip_address=?", (ip,)).fetchone()
            if not a:
                continue
            u = a[0]
            row = con.execute("SELECT state FROM vulns WHERE asset_uuid=? AND plugin_id=?", (u, str(p))).fetchone()
            if p == 19506:
                if since:
                    con.execute("DELETE FROM vulns WHERE asset_uuid=? AND plugin_id='19506'", (u,))
                    con.execute("INSERT INTO vulns(asset_uuid, plugin_id, plugin_name, plugin_family, state, last_found, "
                                "scan_uuid, output) VALUES (?,?,?,?,?,?,?,?)",
                                (u, "19506", "Nessus Scan Information", "Settings", "open", iso(t0 + 60), h["uuid"],
                                 "Credentialed checks : %s\n" % ((SCN.get("cred") or {}).get(ip, "no"))))
                    n += 1
                continue
            res = (SCN.get("results") or {}).get("%s|%d" % (ip, p), "absent")
            cur = row[0] if row else None
            if res == "open":
                if since and cur in ("open", "reopened"):
                    continue                              # since → state CHANGES only (the blind spot)
                if since or days:
                    con.execute("DELETE FROM vulns WHERE asset_uuid=? AND plugin_id=?", (u, str(p)))
                    con.execute("INSERT INTO vulns(asset_uuid, plugin_id, plugin_name, plugin_family, state, last_found, "
                                "scan_uuid, output) VALUES (?,?,?,?,?,?,?,?)",
                                (u, str(p), "p%d" % p, None, "reopened" if cur == "fixed" else "open", iso(t0 + 60),
                                 h["uuid"], ""))
                    n += 1
            elif res == "fixed" and since and cur in ("open", "reopened"):
                con.execute("UPDATE vulns SET state='fixed' WHERE asset_uuid=? AND plugin_id=?", (u, str(p)))
                con.execute("INSERT INTO fixed(asset_uuid, plugin_id, last_fixed, state) VALUES (?,?,?,?)",
                            (u, str(p), iso(t0 + 60), "fixed"))
                n += 1
    con.commit()
    con.close()
    print("Downloading vulns … %d finding(s) written" % n)
    sys.exit(0)

print("fake navi: unhandled %s" % argv)
sys.exit(0)
