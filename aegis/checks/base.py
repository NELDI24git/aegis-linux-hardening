from __future__ import annotations

from abc import ABC, abstractmethod

from aegis.context import SystemContext
from aegis.models import Finding


MODULE_TAGS = {
    "ssh": ("authentication", "remote-access"),
    "accounts": ("identity", "authentication"),
    "pam": ("authentication", "password-policy"),
    "filesystem": ("filesystem", "permissions"),
    "mounts": ("filesystem", "mount-hardening"),
    "network": ("network", "attack-surface"),
    "kernel": ("kernel", "hardening"),
    "privilege": ("privilege-escalation", "attack-surface"),
    "logging": ("logging", "detection"),
    "services": ("service-hardening",),
    "systemd": ("systemd", "service-hardening"),
    "time": ("time", "logging"),
    "containers": ("containers", "attack-surface"),
    "updates": ("patching", "maintenance"),
}


class Check(ABC):
    check_id: str
    module: str
    title: str
    tags: tuple[str, ...] = ()

    @abstractmethod
    def run(self, ctx: SystemContext) -> Finding:
        raise NotImplementedError

    def effective_tags(self) -> list[str]:
        return sorted(set((self.module, *MODULE_TAGS.get(self.module, ()), *self.tags)))
