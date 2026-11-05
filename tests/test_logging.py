import json
import logging

from viper.logging_setup import JsonFormatter


def test_json_formatter_emits_structured_record() -> None:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "hello %s", ("world",), None)
    record.job_id = "j1"
    data = json.loads(JsonFormatter().format(record))
    assert data["msg"] == "hello world"
    assert data["level"] == "INFO"
    assert data["job_id"] == "j1"
