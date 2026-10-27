from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from pathlib import Path

from aegis.integrity import sign_file, signature_path


def publish_artifact(
    target: str | Path,
    writer: Callable[[Path], object],
    *,
    sign_key: str | Path | None = None,
    force: bool = False,
) -> Path | None:
    """Stage and safely publish one artifact and its optional integrity sidecar."""
    destination = Path(target)
    signature = signature_path(destination)
    if sign_key is not None:
        key_path = os.path.normcase(os.path.abspath(sign_key))
        if key_path in {
            os.path.normcase(os.path.abspath(destination)),
            os.path.normcase(os.path.abspath(signature)),
        }:
            raise ValueError("integrity key path conflicts with the artifact or its signature")
    if not force and any(path.exists() or path.is_symlink() for path in (destination, signature)):
        raise FileExistsError(f"{destination} or its signature already exists; use --force to replace it")

    fd, staged_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(fd)
    staged = Path(staged_name)
    staged_signature = staged.with_name(staged.name + ".sig")
    try:
        writer(staged)
        if sign_key is not None:
            sign_file(staged, sign_key, signature=staged_signature, target_name=destination.name)

        if force:
            os.replace(staged, destination)
        elif os.name == "nt":
            os.rename(staged, destination)
        else:
            os.link(staged, destination)
            staged.unlink()

        if sign_key is not None:
            if force:
                os.replace(staged_signature, signature)
            elif os.name == "nt":
                os.rename(staged_signature, signature)
            else:
                os.link(staged_signature, signature)
                staged_signature.unlink()
        elif force and (signature.exists() or signature.is_symlink()):
            signature.unlink()
        return signature if sign_key is not None else None
    finally:
        for temporary in (staged, staged_signature):
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
