# ruff: noqa: S101 -- pytest assertions
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from typing import Any

from vmapi.probes import zap_baseline


class FakeZap:
    def __init__(self, alerts: list[dict[str, Any]]) -> None:
        self._alerts = alerts
        self.spider = self._Spider()
        self.pscan = self._Pscan()
        self.core = self._Core(alerts)

    class _Spider:
        def scan(self, url: str) -> str: return "1"
        def status(self, sid: str) -> str: return "100"

    class _Pscan:
        records_to_scan = 0

    class _Core:
        def __init__(self, alerts: list[dict[str, Any]]) -> None: self._alerts = alerts
        def alerts(self, baseurl: str = "") -> list[dict[str, Any]]: return self._alerts


def test_alerts_to_records_maps_fields() -> None:
    recs = zap_baseline._alerts_to_records(
        [{"name": "X-Frame-Options Missing", "risk": "Low", "confidence": "High",
          "url": "https://x.test/", "cweid": "1021", "description": "d", "solution": "s"}],
        "x.test")
    assert recs[0]["tool"] == "zap_baseline" and recs[0]["alert"] == "X-Frame-Options Missing"
    assert recs[0]["cweid"] == "1021" and recs[0]["risk"] == "Low"


def test_run_emits_one_jsonl_record_per_alert() -> None:
    fake = FakeZap([{"alert": "A", "risk": "Medium", "confidence": "High", "url": "https://x.test/"},
                    {"alert": "B", "risk": "High", "confidence": "Low", "url": "https://x.test/p"}])
    buf = io.StringIO()
    with redirect_stdout(buf):
        zap_baseline.run({"target": "x.test", "max_duration_minutes": 1}, zap=fake)
    lines = [json.loads(ln) for ln in buf.getvalue().splitlines() if ln.strip()]
    assert [r["alert"] for r in lines] == ["A", "B"]
    assert all(r["tool"] == "zap_baseline" for r in lines)


def test_run_without_target_emits_nothing() -> None:
    buf = io.StringIO()
    with redirect_stdout(buf):
        zap_baseline.run({}, zap=FakeZap([]))
    assert buf.getvalue() == ""
