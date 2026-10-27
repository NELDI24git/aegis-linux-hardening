from __future__ import annotations

import re
from dataclasses import dataclass, field

from aegis.context import SystemContext


@dataclass(slots=True)
class FirewallState:
    authoritative: bool
    active: bool | None
    backends: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AutomaticUpdatesState:
    authoritative: bool
    enabled: bool | None
    current: str
    expected: str
    evidence: list[str] = field(default_factory=list)


class PlatformAdapter:
    family = "generic"
    package_manager: str | None = None

    def package_provenance_available(self, ctx: SystemContext) -> bool:
        return False

    def package_owners(self, ctx: SystemContext, paths: list[str]) -> dict[str, str]:
        return {}

    def firewall_state(self, ctx: SystemContext) -> FirewallState:
        if not ctx.is_real_system:
            return FirewallState(False, None, evidence=["runtime firewall state unavailable under fake root"])
        if not ctx.is_root:
            return FirewallState(False, None, evidence=["root privileges required for authoritative firewall inspection"])

        active = False
        detected: list[str] = []
        evidence: list[str] = []

        if ctx.which("ufw"):
            detected.append("ufw")
            result = ctx.run(["ufw", "status"])
            first = result.stdout.strip().splitlines()[:1]
            evidence.extend(first)
            if result.returncode == 0 and "status: active" in result.stdout.lower():
                active = True

        if ctx.which("firewall-cmd"):
            detected.append("firewalld")
            result = ctx.run(["firewall-cmd", "--state"])
            evidence.append(f"firewalld: {result.stdout.strip() or result.stderr.strip()}")
            if result.returncode == 0 and result.stdout.strip().lower() == "running":
                active = True

        if ctx.which("nft"):
            detected.append("nftables")
            result = ctx.run(["nft", "list", "ruleset"], timeout=20)
            if result.returncode == 0 and result.stdout.strip():
                ruleset = result.stdout.lower()
                restrictive_input = bool(
                    re.search(r"hook\s+input\b[\s\S]{0,1000}?policy\s+(?:drop|reject)\s*;", ruleset)
                )
                if restrictive_input:
                    evidence.append("nftables has an input base chain with drop/reject policy")
                    active = True
                else:
                    evidence.append("nftables rules exist, but no restrictive input base-chain policy was confirmed")

        return FirewallState(True, active, detected, evidence)

    def automatic_updates_state(self, ctx: SystemContext) -> AutomaticUpdatesState:
        return AutomaticUpdatesState(
            False,
            None,
            f"unsupported adapter family={self.family}",
            "distribution-specific automatic security update policy",
            [],
        )
