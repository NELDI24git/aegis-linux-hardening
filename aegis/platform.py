from __future__ import annotations

from dataclasses import dataclass

from aegis.context import SystemContext


@dataclass(slots=True)
class PlatformInfo:
    name: str
    version: str
    distro_id: str
    id_like: tuple[str, ...] = ()

    @property
    def display(self) -> str:
        return f"{self.name} {self.version}".strip()


def detect_platform(ctx: SystemContext) -> PlatformInfo:
    cached = ctx.cache.get("platform:info")
    if isinstance(cached, PlatformInfo):
        return cached

    values: dict[str, str] = {}
    if ctx.exists("/etc/os-release"):
        for raw in ctx.read_text("/etc/os-release").splitlines():
            if "=" not in raw:
                continue
            key, value = raw.split("=", 1)
            values[key] = value.strip().strip('"')
    info = PlatformInfo(
        name=values.get("NAME", "Linux"),
        version=values.get("VERSION_ID", ""),
        distro_id=values.get("ID", "linux").lower(),
        id_like=tuple(x.lower() for x in values.get("ID_LIKE", "").split() if x),
    )
    ctx.cache["platform:info"] = info
    return info
