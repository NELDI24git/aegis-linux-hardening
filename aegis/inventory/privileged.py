from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from aegis.context import SystemContext
from aegis.platforms import get_platform_adapter


@dataclass(slots=True)
class PrivilegedFile:
    path: str
    mode: int
    uid: int
    gid: int
    package: str | None = None

    @property
    def suid(self) -> bool:
        return bool(self.mode & stat.S_ISUID)

    @property
    def sgid(self) -> bool:
        return bool(self.mode & stat.S_ISGID)

    @property
    def group_or_world_writable(self) -> bool:
        return bool(self.mode & 0o022)

    def display(self) -> str:
        flags = "/".join(x for x, enabled in (("SUID", self.suid), ("SGID", self.sgid)) if enabled)
        package = self.package or "unowned/unknown"
        return f"{self.path} mode={oct(self.mode)} uid={self.uid} gid={self.gid} {flags} package={package}"


def _scan_fake_root(ctx: SystemContext) -> list[PrivilegedFile]:
    results: list[PrivilegedFile] = []
    root = ctx.root_dir
    for base, dirs, files in os.walk(root):
        # Keep development fixtures small and avoid walking synthetic proc/sys trees.
        dirs[:] = [d for d in dirs if d not in {"proc", "sys", "dev", "run"}]
        for name in files:
            path = Path(base) / name
            try:
                st = path.lstat()
            except OSError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISREG(st.st_mode) and mode & (stat.S_ISUID | stat.S_ISGID):
                relative = "/" + str(path.relative_to(root))
                results.append(PrivilegedFile(relative, mode, st.st_uid, st.st_gid))
    return results


def _parse_find_output(text: str) -> list[PrivilegedFile]:
    results: list[PrivilegedFile] = []
    for raw in text.splitlines():
        parts = raw.split("\t")
        if len(parts) != 4:
            continue
        path, mode_raw, uid_raw, gid_raw = parts
        try:
            # GNU find %m emits octal-looking permissions without the type bits.
            mode = int(mode_raw, 8)
            uid = int(uid_raw)
            gid = int(gid_raw)
        except ValueError:
            continue
        results.append(PrivilegedFile(path, mode, uid, gid))
    return results


def _attach_package_owners(ctx: SystemContext, files: list[PrivilegedFile]) -> str:
    if not files:
        return "none"
    adapter = get_platform_adapter(ctx)
    owners = adapter.package_owners(ctx, [item.path for item in files])
    for item in files:
        if item.path in owners:
            item.package = owners[item.path]
    return adapter.package_manager or "unavailable"


def collect_privileged_files(ctx: SystemContext) -> tuple[list[PrivilegedFile], str]:
    cache_key = "inventory:privileged_files"
    cached = ctx.cache.get(cache_key)
    if isinstance(cached, tuple):
        return cached  # type: ignore[return-value]

    if not ctx.is_real_system:
        output = (_scan_fake_root(ctx), "fake-root filesystem scan")
        ctx.cache[cache_key] = output
        return output

    if not ctx.which("find"):
        output = ([], "find command not found")
        ctx.cache[cache_key] = output
        return output

    # -xdev avoids recursively entering mounted network/removable filesystems.
    result = ctx.run(
        ["find", "/", "-xdev", "-type", "f", "-perm", "/6000", "-printf", "%p\\t%m\\t%U\\t%G\\n"],
        timeout=120,
    )
    files = _parse_find_output(result.stdout)
    package_source = _attach_package_owners(ctx, files)
    if result.returncode not in {0, 1} and not files:
        output = ([], f"find failed: {result.stderr.strip()}")
    else:
        output = (files, f"find / -xdev -perm /6000; package provenance={package_source}")
    ctx.cache[cache_key] = output
    return output
