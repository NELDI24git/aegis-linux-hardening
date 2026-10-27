from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.context import SystemContext


@dataclass(slots=True)
class RuntimeActionResult:
    kind: str
    ok: bool
    messages: list[str] = field(default_factory=list)


def _parse_sshd_effective(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            values[parts[0].lower()] = parts[1].strip().lower()
    return values


def reload_sshd(ctx: SystemContext) -> tuple[bool, str]:
    if not ctx.which("systemctl"):
        return False, "systemctl not found"
    errors: list[str] = []
    for service in ("ssh", "sshd"):
        result = ctx.run(["systemctl", "reload", service])
        if result.returncode == 0:
            return True, f"reloaded {service}"
        errors.append(f"{service}: {result.stderr.strip() or result.stdout.strip() or result.returncode}")
    return False, "; ".join(errors)


def validate_sshd(ctx: SystemContext, expected: dict[str, str] | None = None, *, reload_service: bool = False) -> RuntimeActionResult:
    if not ctx.is_real_system:
        return RuntimeActionResult("sshd", True, ["runtime validation skipped under fake root"])
    if not ctx.which("sshd"):
        return RuntimeActionResult("sshd", False, ["sshd executable not found"])

    syntax = ctx.run(["sshd", "-t"])
    if syntax.returncode != 0:
        return RuntimeActionResult("sshd", False, [f"sshd -t failed: {syntax.stderr.strip()}"])

    effective = ctx.run(["sshd", "-T"])
    if effective.returncode != 0:
        return RuntimeActionResult("sshd", False, [f"sshd -T failed: {effective.stderr.strip()}"])
    parsed = _parse_sshd_effective(effective.stdout)

    messages = ["sshd syntax valid"]
    for key, wanted in (expected or {}).items():
        if wanted in {"", "unknown", None}:  # type: ignore[comparison-overlap]
            continue
        actual = parsed.get(key.lower())
        if actual != str(wanted).lower():
            return RuntimeActionResult(
                "sshd", False, messages + [f"effective {key}={actual!r}, expected {wanted!r}"],
            )
        messages.append(f"effective {key}={actual}")

    if reload_service:
        ok, detail = reload_sshd(ctx)
        messages.append(detail)
        if not ok:
            return RuntimeActionResult("sshd", False, messages)
    return RuntimeActionResult("sshd", True, messages)


def _proc_sys_path(key: str) -> str:
    return "/proc/sys/" + key.replace(".", "/")


def read_sysctl(ctx: SystemContext, key: str) -> str | None:
    path = _proc_sys_path(key)
    if not ctx.exists(path):
        return None
    try:
        return ctx.read_text(path).strip()
    except OSError:
        return None


def apply_sysctl_values(ctx: SystemContext, expected: dict[str, str]) -> RuntimeActionResult:
    if not ctx.is_real_system:
        # Fake roots carry /proc fixtures for audits, but Aegis deliberately does
        # not mutate them. File-state tests still exercise the transaction path.
        return RuntimeActionResult("sysctl", True, ["runtime sysctl apply skipped under fake root"])
    if not ctx.which("sysctl"):
        return RuntimeActionResult("sysctl", False, ["sysctl executable not found"])

    messages: list[str] = []
    for key, value in expected.items():
        result = ctx.run(["sysctl", "-w", f"{key}={value}"])
        if result.returncode != 0:
            return RuntimeActionResult("sysctl", False, messages + [f"failed to set {key}: {result.stderr.strip()}"])
        actual = read_sysctl(ctx, key)
        if actual != str(value):
            return RuntimeActionResult("sysctl", False, messages + [f"{key}={actual!r}, expected {value!r}"])
        messages.append(f"{key}={actual}")
    return RuntimeActionResult("sysctl", True, messages)


def execute_rollback_action(ctx: SystemContext, action: dict[str, Any]) -> RuntimeActionResult:
    kind = action.get("kind")
    expected_before = action.get("before") or {}
    if not isinstance(expected_before, dict):
        return RuntimeActionResult(str(kind), False, ["invalid runtime action metadata"])
    normalized = {str(k): str(v) for k, v in expected_before.items() if v is not None}

    if kind == "sshd":
        return validate_sshd(ctx, normalized, reload_service=True)
    if kind == "sysctl":
        return apply_sysctl_values(ctx, normalized)
    return RuntimeActionResult(str(kind), False, ["unknown runtime action kind; refusing to execute"])
