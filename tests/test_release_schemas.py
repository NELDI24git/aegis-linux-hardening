import json
from pathlib import Path

from aegis.baseline import BASELINE_SCHEMA_VERSION, create_baseline
from aegis.context import SystemContext
from aegis.reporting.json_report import REPORT_SCHEMA_VERSION, render_json


def test_report_schema_is_v2():
    payload = json.loads(render_json([], platform="test", profile="general"))
    assert payload["schema_version"] == REPORT_SCHEMA_VERSION == 2
    assert payload["profile"] == "general"


def test_baseline_schema_is_v2(tmp_path: Path):
    out = tmp_path / "baseline.json"
    create_baseline(SystemContext(tmp_path), out)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == BASELINE_SCHEMA_VERSION == 2
    assert payload["aegis_version"]
