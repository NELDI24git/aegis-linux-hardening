from __future__ import annotations

import os
from dataclasses import dataclass

from aegis.context import SystemContext
from aegis.eventlog import DEFAULT_EVENT_LOG
from aegis.platform import detect_platform
from aegis.platforms import get_platform_adapter


@dataclass(slots=True)
class DoctorItem:
    name: str
    status: str
    detail: str


def run_doctor(ctx: SystemContext) -> list[DoctorItem]:
    platform = detect_platform(ctx)
    adapter = get_platform_adapter(ctx)
    items = [DoctorItem("platform", "OK", platform.display), DoctorItem("adapter", "OK" if adapter.family != "generic" else "INFO", f"{adapter.family}; package_manager={adapter.package_manager or 'none'}")]
    event_path = os.environ.get("AEGIS_EVENT_LOG", DEFAULT_EVENT_LOG)
    if not ctx.is_real_system:
        items.append(DoctorItem("runtime", "INFO", f"fake root: {ctx.root_dir}"))
        items.append(DoctorItem("event-log", "OK", str(ctx.path(event_path))))
        return items
    items.append(DoctorItem("privileges", "OK" if ctx.is_root else "WARN", "root" if ctx.is_root else "non-root; some checks will be advisory"))
    parent = ctx.path(event_path).parent
    writable = (parent.exists() and os.access(parent, os.W_OK)) or (not parent.exists() and ctx.is_root)
    items.append(DoctorItem("event-log", "OK" if writable else "WARN", event_path))
    required = ("find",)
    optional = ("ss", "sshd", "systemctl", "systemd-analyze", "sysctl", "nft", "ufw", "firewall-cmd", "dpkg-query", "rpm", "apt-config", "dnf", "timedatectl", "auditctl")
    for command in required:
        path = ctx.which(command)
        items.append(DoctorItem(command, "OK" if path else "WARN", path or "not found"))
    for command in optional:
        path = ctx.which(command)
        items.append(DoctorItem(command, "OK" if path else "INFO", path or "not installed / not in PATH"))
    return items


def render_doctor(items: list[DoctorItem]) -> str:
    lines = ["AEGIS DOCTOR", "=" * 78]
    for item in items:
        lines.append(f"[{item.status:<4}] {item.name:<16} {item.detail}")
    return "\n".join(lines)
