from __future__ import annotations

import stat

from aegis.checks.base import Check
from aegis.context import SystemContext
from aegis.inventory.sockets import collect_listening_sockets
from aegis.models import Finding, Severity, Status


class DockerSocketPermissionsCheck(Check):
    check_id = "CTR-001"
    module = "containers"
    title = "Docker control socket is not world writable"

    def run(self, ctx: SystemContext) -> Finding:
        path = ctx.path("/var/run/docker.sock")
        if not path.exists():
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.HIGH,
                "Docker socket not present", "not world writable if Docker is used",
                "Write access to the Docker daemon is effectively a powerful host-control capability on typical installations.",
                "No action unless Docker is expected on this host.", scored=False,
            )
        st = path.stat()
        mode = stat.S_IMODE(st.st_mode)
        risky = bool(mode & 0o002) or st.st_uid != 0
        return Finding(
            self.check_id, self.title, self.module,
            Status.FAIL if risky else Status.PASS,
            Severity.CRITICAL,
            f"mode={oct(mode)} uid={st.st_uid} gid={st.st_gid}",
            "root-owned and not world writable",
            "Users able to control the Docker daemon can commonly create privileged containers or mount host filesystems.",
            "Restore root ownership and remove world-write permissions; separately review membership of the docker group as privileged access.",
            auto_fix=False,
        )


class DockerPlaintextAPIExposureCheck(Check):
    check_id = "CTR-002"
    module = "containers"
    title = "Unauthenticated Docker TCP API is not publicly exposed"

    def run(self, ctx: SystemContext) -> Finding:
        sockets, source = collect_listening_sockets(ctx)
        exposed = [s for s in sockets if s.wildcard and s.port == 2375]
        return Finding(
            self.check_id, self.title, self.module,
            Status.FAIL if exposed else (Status.PASS if sockets else Status.INFO),
            Severity.CRITICAL,
            f"{len(exposed)} wildcard listener(s) on TCP/2375 ({source})",
            "0 public listeners on unauthenticated Docker API port 2375",
            "A reachable plaintext Docker API can provide direct control over containers and often the host.",
            "Disable the TCP listener or bind/protect it with an authenticated transport appropriate to the environment.",
            auto_fix=False,
            evidence=[s.display() for s in exposed],
            scored=bool(sockets),
        )


CHECKS = [DockerSocketPermissionsCheck(), DockerPlaintextAPIExposureCheck()]


class DockerGroupMembershipCheck(Check):
    check_id = "CTR-003"
    module = "containers"
    title = "Docker group membership is explicitly reviewed"

    def run(self, ctx: SystemContext) -> Finding:
        if not ctx.exists("/etc/group"):
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.HIGH,
                "/etc/group unavailable", "only explicitly authorized administrators in docker group",
                "Membership in the docker group is commonly equivalent to high-privilege host control.",
                "Review group membership on the target host.", scored=False,
            )
        members: list[str] = []
        found = False
        for line in ctx.read_text("/etc/group").splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and parts[0] == "docker":
                found = True
                members = [x for x in parts[3].split(",") if x]
                break
        if not found:
            return Finding(
                self.check_id, self.title, self.module, Status.INFO, Severity.HIGH,
                "docker group not present", "review only when Docker is installed",
                "Docker group access is security-sensitive.",
                "No action unless Docker is expected.", scored=False,
            )
        return Finding(
            self.check_id, self.title, self.module,
            Status.WARN if members else Status.PASS,
            Severity.HIGH,
            "members: " + (", ".join(members) if members else "none"),
            "only users explicitly authorized for root-equivalent Docker control",
            "Docker daemon access can usually be leveraged to mount host filesystems or start privileged containers.",
            "Remove unnecessary members. Treat retained docker-group membership as privileged administrative access.",
            auto_fix=False,
            evidence=members,
            scored=False,
        )


CHECKS.append(DockerGroupMembershipCheck())
