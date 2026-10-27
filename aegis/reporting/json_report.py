from __future__ import annotations

import json
from datetime import datetime, timezone

from aegis import __version__
from aegis.engine.scoring import score_details
from aegis.models import Finding

REPORT_SCHEMA_VERSION = 2


def render_json(findings: list[Finding], *, platform: str | None = None, profile: str | None = None) -> str:
    score = score_details(findings)
    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "aegis_version": __version__,
        "platform": platform,
        "profile": profile,
        "score": score.score,
        "score_possible_weight": score.possible,
        "scored_findings": score.scored_findings,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)
