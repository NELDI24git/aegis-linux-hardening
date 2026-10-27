from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class RoleProfile:
    name: str
    description: str
    default_public_ports: frozenset[int] = frozenset()
    include_modules: frozenset[str] = frozenset()
    exclude_modules: frozenset[str] = frozenset()
    include_checks: frozenset[str] = frozenset()
    exclude_checks: frozenset[str] = frozenset()
    tags: frozenset[str] = frozenset()

    def check_enabled(self, *, check_id: str, module: str) -> bool:
        if check_id in self.exclude_checks or module in self.exclude_modules:
            return False
        if self.include_checks or self.include_modules:
            return check_id in self.include_checks or module in self.include_modules
        return True


PROFILES: dict[str, RoleProfile] = {
    "general": RoleProfile(
        "general",
        "General-purpose Linux server. Runs the complete portable control set.",
        frozenset({22}),
        tags=frozenset({"general"}),
    ),
    "web-server": RoleProfile(
        "web-server",
        "Internet-facing web server. HTTP(S) exposure is expected; data stores are not public by default.",
        frozenset({22, 80, 443}),
        tags=frozenset({"server", "internet-facing", "web"}),
    ),
    "database": RoleProfile(
        "database",
        "Database host. Database listeners should normally use private/loopback addresses unless explicitly overridden.",
        frozenset({22}),
        tags=frozenset({"server", "database"}),
    ),
    "bastion": RoleProfile(
        "bastion",
        "Administrative jump host. Minimal public exposure and strict SSH controls are expected.",
        frozenset({22}),
        tags=frozenset({"server", "internet-facing", "bastion"}),
    ),
    "container-host": RoleProfile(
        "container-host",
        "Host running Docker/OCI workloads. Container checks are retained alongside host controls.",
        frozenset({22}),
        tags=frozenset({"server", "containers"}),
    ),
    "minimal": RoleProfile(
        "minimal",
        "Small high-signal control pack for rapid host review.",
        frozenset({22}),
        include_checks=frozenset({
            "SSH-001", "SSH-002", "SSH-003", "ACC-001", "ACC-002",
            "FS-001", "FS-002", "NET-002", "NET-003", "NET-004",
            "PRIV-001", "PRIV-002", "UPD-001",
        }),
        include_modules=frozenset(),
        tags=frozenset({"quick"}),
    ),
}


def get_profile(name: str | None) -> RoleProfile:
    key = (name or "general").strip().lower()
    if key not in PROFILES:
        raise ValueError(f"unknown role profile {name!r}; choose one of: {', '.join(sorted(PROFILES))}")
    return PROFILES[key]


def profile_names() -> list[str]:
    return sorted(PROFILES)
