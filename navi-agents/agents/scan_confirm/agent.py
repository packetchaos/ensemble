"""Scan Confirmation — prove a fix with Tenable's own scan (build 514).

Read-only here: _run() reports the launch gate, the scanners / credentials Tenable lists (5-min
cache) and the recent runs. Planning, launching and verifying live in agents/scan_confirm/api.py
over core/scan_confirm.py. No model anywhere — every verdict is a rule over Tenable's data.
"""
from core.agents.base import Agent


class ScanConfirmAgent(Agent):
    id = "scan_confirm"
    name = "Scan Confirmation"
    icon = "📡"
    description = ("Scan Confirmation — launch a targeted Tenable scan for given plugins on given assets, sync the "
                   "result back and give one verdict per asset × plugin. Triple-gated launch; deterministic.")

    def summary(self):
        if not self.result:
            return {}
        return {"scan_launch_enabled": self.result.get("scan_launch_enabled"),
                "runs": len(self.result.get("runs") or [])}

    def _run(self, db_path=None, **kwargs):
        from core import navi_cli, scan_confirm as sc
        return {"ready": True, "scan_launch_enabled": navi_cli.scan_launch_enabled(),
                "gate_reason": navi_cli.scan_launch_gate_reason(), "runs": sc.list_runs(10),
                "hint": "Give plugin IDs and assets, press ▶ Plan, then ⚡ Launch. Launching needs "
                        "NAVI_ALLOW_WRITES=1 + NAVI_SCAN_LAUNCH=1 + confirm."}
