from __future__ import annotations

import re

from aegis.context import SystemContext
from aegis.platforms.base import AutomaticUpdatesState, PlatformAdapter


class DebianAdapter(PlatformAdapter):
    family = "debian"
    package_manager = "dpkg"

    def package_provenance_available(self, ctx: SystemContext) -> bool:
        return bool(ctx.is_real_system and ctx.which("dpkg-query"))

    def package_owners(self, ctx: SystemContext, paths: list[str]) -> dict[str, str]:
        if not paths or not self.package_provenance_available(ctx):
            return {}
        owners: dict[str, str] = {}
        for start in range(0, len(paths), 64):
            batch = paths[start:start + 64]
            result = ctx.run(["dpkg-query", "-S", *batch], timeout=30)
            for line in result.stdout.splitlines():
                if ": " not in line:
                    continue
                package, path = line.split(": ", 1)
                if path in batch:
                    owners[path] = package.split(",", 1)[0]
        return owners

    @staticmethod
    def _apt_periodic_settings(ctx: SystemContext) -> dict[str, str]:
        directory = ctx.path("/etc/apt/apt.conf.d")
        values: dict[str, str] = {}
        if not directory.is_dir():
            return values
        for path in sorted(p for p in directory.iterdir() if p.is_file()):
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            for key, value in re.findall(r'APT::Periodic::([A-Za-z0-9_-]+)\s+"([^"]+)"\s*;', text):
                values[key] = value
        return values

    def automatic_updates_state(self, ctx: SystemContext) -> AutomaticUpdatesState:
        values = self._apt_periodic_settings(ctx)
        upgrade = values.get("Unattended-Upgrade")
        lists = values.get("Update-Package-Lists")
        enabled = upgrade not in {None, "0", "false", "False"}
        return AutomaticUpdatesState(
            True,
            enabled,
            f"APT::Periodic::Unattended-Upgrade={upgrade or 'unset'}",
            "APT::Periodic::Unattended-Upgrade set to a non-zero schedule",
            [f"Unattended-Upgrade={upgrade!r}", f"Update-Package-Lists={lists!r}"],
        )
