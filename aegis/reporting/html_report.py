from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape

from aegis.engine.scoring import score_details
from aegis.models import Finding


def render_html(findings: list[Finding], *, platform: str | None = None, profile: str | None = None) -> str:
    score = score_details(findings)
    counts = Counter(f.status.value for f in findings)
    rows: list[str] = []
    for f in findings:
        evidence = "".join(f"<li>{escape(item)}</li>" for item in f.evidence[:50])
        rows.append(
            "<tr>"
            f"<td><code>{escape(f.check_id)}</code></td>"
            f"<td>{escape(f.module)}</td>"
            f"<td>{escape(f.title)}</td>"
            f"<td class='status {escape(f.status.value.lower())}'>{escape(f.status.value)}</td>"
            f"<td>{escape(f.severity.value)}</td>"
            f"<td>{escape(f.current)}</td>"
            f"<td>{escape(f.expected)}</td>"
            f"<td>{escape(f.remediation)}{('<br><strong>Exception:</strong> ' + escape(f.exception_reason or '') + ' (expires ' + escape(f.exception_expires_at or 'unknown') + ')') if f.status.value == 'EXEMPT' else ''}{('<ul>' + evidence + '</ul>') if evidence else ''}</td>"
            "</tr>"
        )

    generated = datetime.now(timezone.utc).isoformat()
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aegis Security Audit</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.45; }}
header {{ display: flex; gap: 2rem; align-items: end; flex-wrap: wrap; }}
.score {{ font-size: 3rem; font-weight: 700; }}
.summary {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0 2rem; }}
.summary span {{ border: 1px solid #bbb; border-radius: .5rem; padding: .4rem .7rem; }}
table {{ width: 100%; border-collapse: collapse; font-size: .92rem; }}
th, td {{ border: 1px solid #ccc; padding: .55rem; vertical-align: top; text-align: left; }}
th {{ position: sticky; top: 0; background: Canvas; }}
.status {{ font-weight: 700; }}
.pass {{ opacity: .75; }}
.fail, .error {{ font-weight: 800; }}
.warn {{ font-weight: 700; }}
code {{ white-space: nowrap; }}
ul {{ margin: .5rem 0 0 1rem; padding: 0; }}
small {{ opacity: .7; }}
</style>
</head>
<body>
<header>
<div><h1>Aegis Security Audit</h1><div>{escape(platform or 'Linux host')}</div><div>Profile: {escape(profile or 'general')}</div><small>{escape(generated)}</small></div>
<div><div class="score">{score.score}/100</div><small>{score.scored_findings} scored checks</small></div>
</header>
<div class="summary">
<span>PASS {counts['PASS']}</span><span>FAIL {counts['FAIL']}</span><span>WARN {counts['WARN']}</span><span>INFO {counts['INFO']}</span><span>ERROR {counts['ERROR']}</span><span>EXEMPT {counts['EXEMPT']}</span>
</div>
<table>
<thead><tr><th>ID</th><th>Module</th><th>Check</th><th>Status</th><th>Severity</th><th>Current</th><th>Expected</th><th>Remediation / evidence</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</body></html>"""
