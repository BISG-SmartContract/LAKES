"""Serialize SmartBugs compiler preparation and publish verified downloads."""

from __future__ import annotations

import fcntl
from functools import wraps
import os
from pathlib import Path
import tempfile
from typing import Callable, Any


def compiler_path_locked(resolve: Callable, cache_root: Path, version):
    """Keep existence checks, installation and final chmod in one process lock."""
    if version is None:
        return resolve(version)
    cache_root.mkdir(parents=True, exist_ok=True)
    with (cache_root / ".lakes-solc-install.lock").open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            return resolve(version)
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def download_verified_artifact(manager: Any, artifact: Any) -> None:
    """Never expose an empty or partially downloaded compiler at its public path."""
    target = Path(artifact.file_path)
    response = manager.session.get(artifact.download_url, stream=True)
    temporary: Path | None = None
    try:
        response.raise_for_status()
        fd, name = tempfile.mkstemp(prefix=f".{target.name}.lakes-", dir=target.parent)
        temporary = Path(name)
        with os.fdopen(fd, "w+b") as handle:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    handle.write(chunk)
            handle.flush()
            manager.verify_checksum(artifact, handle)
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        response.close()


def install_compiler_guards(solc_module, cache_root: Path, artifact_manager=None) -> None:
    """Apply once in both CLI and spawned SmartBugs workers."""
    original = solc_module.path
    if not getattr(original, "_lakes_compiler_lock", False):
        @wraps(original)
        def guarded(version):
            return compiler_path_locked(original, cache_root, version)

        guarded._lakes_compiler_lock = True
        solc_module.path = guarded
    if artifact_manager is not None:
        artifact_manager._download_artifact = download_verified_artifact
