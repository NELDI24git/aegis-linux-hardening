from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis.context import SystemContext

DEFAULT_EVENT_LOG = "/var/log/aegis/events.jsonl"
EVENT_SCHEMA_VERSION = 1


def emit_event(ctx: SystemContext, event: str, *, outcome: str = "ok", details: dict[str, Any] | None = None) -> None:
    """Best-effort append-only structured event log.

    Logging failures never change the security operation outcome. Operators can
    use `aegis doctor` to check whether the configured log path is writable.
    """
    configured = os.environ.get("AEGIS_EVENT_LOG", DEFAULT_EVENT_LOG)
    try:
        target = ctx.path(configured)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            return
        payload = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "outcome": outcome,
            "details": details or {},
        }
        with target.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    except OSError:
        return
