from __future__ import annotations

from aegis.context import SystemContext
from aegis.platforms.base import PlatformAdapter
from aegis.platforms.debian import DebianAdapter
from aegis.platforms.generic import GenericAdapter
from aegis.platforms.rpm import RpmAdapter


DEBIAN_IDS = {"debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian"}
RPM_IDS = {"fedora", "rhel", "centos", "rocky", "almalinux", "ol", "amzn"}


def get_platform_adapter(ctx: SystemContext) -> PlatformAdapter:
    cached = ctx.cache.get("platform:adapter")
    if isinstance(cached, PlatformAdapter):
        return cached

    # Local import avoids a platform.py <-> adapters import cycle.
    from aegis.platform import detect_platform

    info = detect_platform(ctx)
    identifiers = {info.distro_id, *info.id_like}
    if identifiers & DEBIAN_IDS:
        adapter: PlatformAdapter = DebianAdapter()
    elif identifiers & RPM_IDS:
        adapter = RpmAdapter()
    else:
        adapter = GenericAdapter()
    ctx.cache["platform:adapter"] = adapter
    return adapter


__all__ = ["PlatformAdapter", "get_platform_adapter"]
