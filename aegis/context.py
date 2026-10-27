from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class SystemContext:
    """Small abstraction over the host to keep checks testable.

    AEGIS_ROOT can point at a fake filesystem during tests/development.
    Commands are executed only when root_dir is '/'.
    """

    def __init__(self, root_dir: str | Path | None = None) -> None:
        self.root_dir = Path(root_dir or os.environ.get("AEGIS_ROOT", "/")).resolve()
        self.cache: dict[str, object] = {}

    @property
    def is_real_system(self) -> bool:
        return self.root_dir == Path("/")

    @property
    def is_root(self) -> bool:
        return (not self.is_real_system) or os.geteuid() == 0

    def path(self, absolute_path: str | Path) -> Path:
        raw_path = os.fspath(absolute_path)
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            raise ValueError(f"Expected an absolute POSIX path, got {absolute_path!r}")
        posix_path = PurePosixPath(raw_path)
        if ".." in posix_path.parts:
            raise ValueError(f"Path traversal is not allowed: {absolute_path!r}")
        return self.root_dir.joinpath(*posix_path.parts[1:])

    def read_text(self, absolute_path: str | Path) -> str:
        return self.path(absolute_path).read_text(encoding="utf-8")

    def exists(self, absolute_path: str | Path) -> bool:
        return self.path(absolute_path).exists()

    def which(self, command: str) -> str | None:
        if not self.is_real_system:
            return None
        return shutil.which(command)

    def run(self, args: list[str], *, timeout: int = 15) -> CommandResult:
        if not self.is_real_system:
            return CommandResult(127, "", "command execution disabled under AEGIS_ROOT")
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            return CommandResult(124, stdout, (stderr + f"\ncommand timed out after {timeout}s").strip())
        except OSError as exc:
            return CommandResult(127, "", str(exc))
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)
