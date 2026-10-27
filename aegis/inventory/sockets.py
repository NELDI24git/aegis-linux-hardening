from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.context import SystemContext


@dataclass(slots=True)
class ListeningSocket:
    protocol: str
    address: str
    port: int
    process: str | None = None
    pid: int | None = None

    @property
    def wildcard(self) -> bool:
        return self.address in {"0.0.0.0", "*", "::", "[::]"}

    def display(self) -> str:
        proc = self.process or "unknown"
        pid = f" pid={self.pid}" if self.pid is not None else ""
        return f"{self.protocol} {self.address}:{self.port} process={proc}{pid}"


def _split_endpoint(endpoint: str) -> tuple[str, int] | None:
    endpoint = endpoint.strip()
    if endpoint.startswith("[") and "]:" in endpoint:
        host, port = endpoint.rsplit(":", 1)
        host = host[1:-1]
    elif ":" in endpoint:
        host, port = endpoint.rsplit(":", 1)
    else:
        return None
    try:
        return host, int(port)
    except ValueError:
        return None


def _parse_process(text: str) -> tuple[str | None, int | None]:
    # ss usually renders: users:(("sshd",pid=694,fd=3))
    name_match = re.search(r'\("([^"\\]+)"', text)
    pid_match = re.search(r"pid=(\d+)", text)
    return (
        name_match.group(1) if name_match else None,
        int(pid_match.group(1)) if pid_match else None,
    )


def parse_ss_output(text: str) -> list[ListeningSocket]:
    sockets: list[ListeningSocket] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # `ss -H -lntup` starts with protocol, state, recv-q, send-q,
        # then local endpoint. We only need those stable first columns.
        parts = line.split(None, 6)
        if len(parts) < 5:
            continue
        protocol = parts[0].lower()
        endpoint = _split_endpoint(parts[4])
        if endpoint is None:
            continue
        address, port = endpoint
        process, pid = _parse_process(parts[6] if len(parts) > 6 else "")
        sockets.append(ListeningSocket(protocol, address, port, process, pid))
    return sockets


def collect_listening_sockets(ctx: SystemContext) -> tuple[list[ListeningSocket], str]:
    cache_key = "inventory:listening_sockets"
    cached = ctx.cache.get(cache_key)
    if isinstance(cached, tuple):
        return cached  # type: ignore[return-value]

    if not ctx.is_real_system:
        fixture = "/var/lib/aegis/fixtures/ss.txt"
        if ctx.exists(fixture):
            result = (parse_ss_output(ctx.read_text(fixture)), "fixture")
        else:
            result = ([], "socket inventory unavailable under fake root")
        ctx.cache[cache_key] = result
        return result

    if not ctx.which("ss"):
        result = ([], "ss command not found")
        ctx.cache[cache_key] = result
        return result
    result = ctx.run(["ss", "-H", "-lntup"], timeout=20)
    if result.returncode != 0:
        output = ([], f"ss failed: {result.stderr.strip()}")
    else:
        output = (parse_ss_output(result.stdout), "ss -H -lntup")
    ctx.cache[cache_key] = output
    return output
