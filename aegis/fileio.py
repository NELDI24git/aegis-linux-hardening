from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_bytes(path: str | Path, data: bytes, *, mode: int | None = None) -> Path:
    """Replace a file atomically without following an existing destination symlink."""
    target = Path(path)
    parent = target.parent
    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, target)
        return target
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_write_text(path: str | Path, text: str, *, mode: int | None = None) -> Path:
    return atomic_write_bytes(path, text.encode("utf-8"), mode=mode)