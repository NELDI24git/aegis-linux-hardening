from __future__ import annotations

import configparser

from aegis.context import SystemContext
from aegis.platforms.base import AutomaticUpdatesState, PlatformAdapter


class RpmAdapter(PlatformAdapter):
    family = "rpm"
    package_manager = "rpm"

    def package_provenance_available(self, ctx: SystemContext) -> bool:
        return bool(ctx.is_real_system and ctx.which("rpm"))

    def package_owners(self, ctx: SystemContext, paths: list[str]) -> dict[str, str]:
        if not paths or not self.package_provenance_available(ctx):
            return {}
        owners: dict[str, str] = {}
        # Privileged-file inventories are normally small enough that per-path
        # queries are acceptable, and this keeps path -> package association
        # unambiguous when some files are not package-owned.
        for path in paths[:512]:
            result = ctx.run(["rpm", "-qf", "--qf", "%{NAME}\n", path], timeout=8)
            if result.returncode == 0 and result.stdout.strip():
                owners[path] = result.stdout.strip().splitlines()[0]
        return owners

    @staticmethod
    def _read_automatic_conf(ctx: SystemContext) -> dict[str, str]:
        path = ctx.path("/etc/dnf/automatic.conf")
        if not path.is_file():
            return {}
        parser = configparser.ConfigParser()
        try:
            parser.read(path, encoding="utf-8")
        except (OSError, configparser.Error):
            return {}
        values: dict[str, str] = {}
        if parser.has_section("commands"):
            for key in ("apply_updates", "upgrade_type", "download_updates"):
                if parser.has_option("commands", key):
                    values[key] = parser.get("commands", key)
        return values

    def automatic_updates_state(self, ctx: SystemContext) -> AutomaticUpdatesState:
        values = self._read_automatic_conf(ctx)
        apply_updates = values.get("apply_updates", "no").strip().lower() in {"yes", "true", "1"}
        upgrade_type = values.get("upgrade_type", "default").strip().lower()
        evidence = [f"apply_updates={values.get('apply_updates', 'unset')}", f"upgrade_type={upgrade_type}"]

        if not ctx.is_real_system:
            # Fixture mode can validate config intent but not whether a timer is enabled.
            return AutomaticUpdatesState(
                False,
                None,
                "dnf automatic config inspectable; systemd timer state unavailable under fake root",
                "dnf-automatic install timer enabled with apply_updates=yes",
                evidence,
            )
        if not ctx.which("systemctl"):
            return AutomaticUpdatesState(
                False, None, "systemctl unavailable", "enabled dnf automatic update timer", evidence
            )

        timer_enabled = False
        timer_name = "none"
        for timer in ("dnf-automatic-install.timer", "dnf-automatic.timer"):
            result = ctx.run(["systemctl", "is-enabled", timer])
            state = result.stdout.strip() or result.stderr.strip()
            evidence.append(f"{timer}: {state}")
            if result.returncode == 0 and state in {"enabled", "static"}:
                timer_enabled = True
                timer_name = timer
                break

        # The install timer performs installation directly. The generic timer
        # follows automatic.conf and therefore requires apply_updates=yes.
        enabled = timer_enabled and (timer_name == "dnf-automatic-install.timer" or apply_updates)
        return AutomaticUpdatesState(
            True,
            enabled,
            f"timer={timer_name}; apply_updates={str(apply_updates).lower()}; upgrade_type={upgrade_type}",
            "enabled dnf automatic install schedule (prefer security-only policy when appropriate)",
            evidence,
        )
