import json
from pathlib import Path

from aegis.context import SystemContext
from aegis.eventlog import emit_event


def test_event_log_is_jsonl_and_fake_root_safe(tmp_path: Path):
    ctx = SystemContext(tmp_path)
    emit_event(ctx, "test.event", details={"answer": 42})
    path = ctx.path("/var/log/aegis/events.jsonl")
    payload = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert payload["event"] == "test.event"
    assert payload["details"]["answer"] == 42
