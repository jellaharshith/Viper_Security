"""OWASP ZAP baseline probe (v1.2). Run on the VM by ``toolrunner`` as a subprocess.

Benign by design: a spider crawl followed by ZAP's PASSIVE rules only. It NEVER launches an
active/attack scan (``ascan``), so it stays inside the project's safety envelope (the policy
engine still classes ``zap_baseline`` ACTIVE and requires human approval because the spider
sends real requests). Output follows the shared JSONL contract (one alert per line on stdout),
so the existing capture -> audit -> findings-parser pipeline applies unchanged.

``zapv2`` and a running ZAP daemon are required only at scan time; they are imported lazily so
this module loads in the scrubbed VM subprocess env (and in CI) without ZAP installed.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any

try:
    from vmapi.probes._common import emit, parse_args_json
except ImportError:  # run as a bare VM subprocess: only this dir is importable
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _common import emit, parse_args_json  # type: ignore[import-not-found]

ZAP_PROXY = os.environ.get("ZAP_PROXY", "http://127.0.0.1:8090")
_POLL_SECONDS = 2.0


def _alerts_to_records(alerts: list[dict[str, Any]], target: str) -> list[dict[str, Any]]:
    """Map raw ZAP alert dicts to the JSONL record shape the findings parser consumes (pure)."""
    records: list[dict[str, Any]] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        records.append({
            "tool": "zap_baseline",
            "target": target,
            "alert": str(alert.get("alert") or alert.get("name") or ""),
            "risk": str(alert.get("risk") or alert.get("riskdesc") or ""),
            "confidence": str(alert.get("confidence") or ""),
            "url": str(alert.get("url") or ""),
            "cweid": str(alert.get("cweid") or ""),
            "description": str(alert.get("description") or ""),
            "solution": str(alert.get("solution") or ""),
            "reference": str(alert.get("reference") or ""),
        })
    return records


def _run_scan(zap: Any, url: str, deadline: float) -> list[dict[str, Any]]:
    """Spider + wait for passive scanning to drain, bounded by ``deadline`` (monotonic)."""
    scan_id = zap.spider.scan(url)
    while time.monotonic() < deadline and int(zap.spider.status(scan_id)) < 100:
        time.sleep(_POLL_SECONDS)
    # Passive rules run automatically as the spider discovers URLs; let the queue drain.
    while time.monotonic() < deadline and int(zap.pscan.records_to_scan) > 0:
        time.sleep(_POLL_SECONDS)
    alerts = zap.core.alerts(baseurl=url)
    return alerts if isinstance(alerts, list) else []


def run(args: dict[str, Any], *, zap: Any | None = None) -> None:
    target = args.get("target")
    if not isinstance(target, str) or not target:
        return
    minutes = args.get("max_duration_minutes", 5)
    if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= 15:
        minutes = 5
    url = f"https://{target}"
    if zap is None:  # pragma: no cover - requires a live ZAP daemon on the VM
        from zapv2 import ZAPv2  # lazy: not needed to import this module
        apikey = os.environ.get("ZAP_API_KEY", "")
        zap = ZAPv2(apikey=apikey, proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})
    deadline = time.monotonic() + minutes * 60
    for record in _alerts_to_records(_run_scan(zap, url, deadline), target):
        emit(record)


def main(argv: list[str] | None = None) -> int:
    try:
        run(parse_args_json(argv if argv is not None else sys.argv[1:]))
    except Exception as exc:  # noqa: BLE001 - surface to stderr; toolrunner captures it
        sys.stderr.write(f"zap_baseline error: {exc.__class__.__name__}: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
