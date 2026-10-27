"""Shared Docker runtime contract for independently supervised LAKES jobs.

The scheduler owns the daemon and mounts the same shared root at the same
absolute path in the daemon and workers. Only the daemon mounts its data volume.
This module deliberately uses the Docker CLI/stdlib so native adapters and the
pinned SmartBugs virtualenv share the same contract without extra dependencies.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from typing import Iterator, Mapping
from uuid import uuid4


JOB_LABEL = "lakes.service.job"
TOOL_LABEL = "lakes.service.tool"
ATTEMPT_LABEL = "lakes.service.attempt"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_MEMORY = re.compile(r"([1-9][0-9]*)([bkmg]i?b?)?\Z", re.IGNORECASE)


def memory_bytes(value: str | int) -> int:
    match = _MEMORY.fullmatch(str(value))
    if match is None:
        raise ValueError("LAKES_DOCKER_MEMORY must be positive bytes or a b/k/m/g size")
    unit = (match[2] or "b").lower()[0]
    amount = int(match[1]) * 1024 ** "bkmg".index(unit)
    if amount < 6 * 1024 * 1024 or amount >= 2**63:
        raise ValueError("LAKES_DOCKER_MEMORY must be at least 6 MiB and fit int64")
    return amount


@dataclass(frozen=True)
class RuntimeConfig:
    job_id: str
    shared_root: Path
    cpu_quota: int | None = None
    memory: int | None = None

    @property
    def job_root(self) -> Path:
        return self.shared_root / self.job_id

    @property
    def temporary_root(self) -> Path:
        return self.job_root / "tmp"


def config(env: Mapping[str, str] | None = None) -> RuntimeConfig | None:
    source = os.environ if env is None else env
    mode = source.get("LAKES_DOCKER_MODE", "auto")
    if mode not in {"auto", "external"}:
        raise ValueError("LAKES_DOCKER_MODE must be auto or external")
    if mode == "auto":
        return None
    if not source.get("DOCKER_HOST", "").strip():
        raise ValueError("DOCKER_HOST is required in external Docker mode")
    job_id = source.get("LAKES_JOB_ID", "")
    if not _IDENTIFIER.fullmatch(job_id) or job_id in {".", ".."}:
        raise ValueError("LAKES_JOB_ID must be a nonempty safe identifier of at most 128 characters")
    root = Path(source.get("LAKES_SHARED_ROOT", ""))
    if not root.is_absolute() or root == Path("/"):
        raise ValueError("LAKES_SHARED_ROOT must be an absolute shared directory other than /")
    root = root.resolve()
    if not root.is_dir():
        raise ValueError("LAKES_SHARED_ROOT must already exist in the worker and Docker runtime")
    if (root / job_id).resolve() != root / job_id:
        raise ValueError("LAKES_JOB_ID directory must not be a symbolic link")
    quota = None
    if source.get("LAKES_DOCKER_CPUS"):
        try:
            cpus = Decimal(source["LAKES_DOCKER_CPUS"])
            if not cpus.is_finite() or cpus <= 0 or cpus > 100000:
                raise ValueError
            quota = int(cpus * 100000)
            if quota < 1000:
                raise ValueError
        except (InvalidOperation, ValueError, OverflowError) as exc:
            raise ValueError("LAKES_DOCKER_CPUS must be between 0.01 and 100000") from exc
    memory = memory_bytes(source["LAKES_DOCKER_MEMORY"]) if source.get("LAKES_DOCKER_MEMORY") else None
    return RuntimeConfig(job_id, root, quota, memory)


def configure(*job_paths: str | Path | None) -> RuntimeConfig | None:
    """Select per-job temporary storage before spawning any analyzer threads."""
    runtime = config()
    if runtime is None:
        return None
    for path in job_paths:
        if path is not None:
            resolved = Path(path).expanduser().resolve()
            if not resolved.is_relative_to(runtime.job_root):
                raise ValueError("external Docker inputs and results must be inside LAKES_SHARED_ROOT/LAKES_JOB_ID")
    runtime.temporary_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if runtime.temporary_root.resolve() != runtime.temporary_root:
        raise ValueError("external Docker temporary directory must not contain symbolic links")
    os.environ["TMPDIR"] = str(runtime.temporary_root)
    tempfile.tempdir = str(runtime.temporary_root)
    return runtime


def shared_path(path: str | Path) -> str:
    """Validate every daemon-side bind source, including non-source adapters."""
    resolved = Path(path).expanduser().resolve()
    runtime = config()
    if runtime is not None and not resolved.is_relative_to(runtime.shared_root):
        raise ValueError("Docker bind source is outside LAKES_SHARED_ROOT; stage it in the job workspace")
    return str(resolved)


def stage_bind_file(path: str | Path) -> str:
    """Copy a worker-local compiler into the daemon-visible job workspace."""
    runtime = config()
    if runtime is None:
        return str(path)
    configure()
    source = Path(path).resolve(strict=True)
    if source.is_relative_to(runtime.shared_root):
        return str(source)
    if not source.is_file():
        raise ValueError("Docker compiler bind source must be a regular file")
    destination = runtime.temporary_root / "bind-files"
    destination.mkdir(exist_ok=True)
    if destination.resolve() != destination:
        raise ValueError("compiler staging directory must not be a symbolic link")
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    final = destination / (digest.hexdigest() + "-" + source.name)
    if final.exists():
        if final.is_symlink() or not final.is_file():
            raise ValueError("staged compiler must be a regular file")
        return str(final)
    # Copy to a private file before publishing; concurrent tools never mount a
    # partial compiler. Identical compilers are reused across this job's inputs.
    with tempfile.NamedTemporaryFile(dir=destination, delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        shutil.copy2(source, temporary_path)
        os.replace(temporary_path, final)
        return str(final)
    finally:
        temporary_path.unlink(missing_ok=True)


def labels(tool: str, env: Mapping[str, str] | None = None) -> dict[str, str]:
    source = os.environ if env is None else env
    runtime = config(source)
    if runtime is None:
        return {}
    values = {JOB_LABEL: runtime.job_id, TOOL_LABEL: tool}
    attempt = source.get("LAKES_DOCKER_ATTEMPT", "")
    if attempt:
        if not _IDENTIFIER.fullmatch(attempt):
            raise ValueError("LAKES_DOCKER_ATTEMPT must be a safe identifier")
        values[ATTEMPT_LABEL] = attempt
    return values


def container_args(args: dict, tool: str) -> dict:
    """Apply job metadata and upper resource bounds to SmartBugs SDK calls."""
    runtime = config()
    if runtime is None:
        return args
    for source in args.get("volumes", {}):
        shared_path(source)
    args = dict(args)
    args["labels"] = {**args.get("labels", {}), **labels(tool)}
    if runtime.cpu_quota is not None:
        quota = runtime.cpu_quota
        existing = args.get("cpu_quota", 0)
        if existing and existing > 0:
            quota = min(quota, int(existing * 100000 / (args.get("cpu_period") or 100000)))
        args["cpu_period"], args["cpu_quota"] = 100000, quota
    if runtime.memory is not None:
        memory = runtime.memory
        if args.get("mem_limit"):
            memory = min(memory, memory_bytes(args["mem_limit"]))
        args["mem_limit"] = memory
    return args


def cli_args(tool: str) -> list[str]:
    runtime = config()
    if runtime is None:
        return []
    result = [part for key, value in labels(tool).items() for part in ("--label", f"{key}={value}")]
    if runtime.cpu_quota is not None:
        result += ["--cpu-period", "100000", "--cpu-quota", str(runtime.cpu_quota)]
    if runtime.memory is not None:
        result += ["--memory", str(runtime.memory)]
    return result


@contextmanager
def image_lock(image: str) -> Iterator[None]:
    """Serialize first pulls/builds across workers sharing the same daemon."""
    runtime = config()
    if runtime is None:
        yield
        return
    lock_root = runtime.shared_root / ".lakes-runtime-locks"
    lock_root.mkdir(exist_ok=True)
    if lock_root.resolve() != lock_root:
        raise ValueError("runtime lock directory must not be a symbolic link")
    filename = hashlib.sha256(image.encode()).hexdigest() + ".lock"
    with (lock_root / filename).open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def process_env(env: Mapping[str, str] | None) -> Mapping[str, str] | None:
    source = os.environ if env is None else env
    runtime = config(source)
    if runtime is None:
        return env
    result = dict(source)
    result.setdefault("LAKES_DOCKER_ATTEMPT", uuid4().hex)
    labels("worker", result)  # Validate a caller-supplied attempt identifier.
    runtime.temporary_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if runtime.temporary_root.resolve() != runtime.temporary_root:
        raise ValueError("external Docker temporary directory must not contain symbolic links")
    result["TMPDIR"] = str(runtime.temporary_root)
    return result


def cleanup(env: Mapping[str, str] | None = None, *, whole_job: bool = False) -> None:
    """Remove only this job/attempt's containers; never prune shared caches."""
    source = os.environ if env is None else env
    runtime = config(source)
    if runtime is None:
        return
    attempt = source.get("LAKES_DOCKER_ATTEMPT")
    if not whole_job and not attempt:
        return
    labels("cleanup", source)
    filters = ["--filter", f"label={JOB_LABEL}={runtime.job_id}"]
    if not whole_job:
        filters += ["--filter", f"label={ATTEMPT_LABEL}={attempt}"]
    deadline = time.monotonic() + 10
    try:
        listed = subprocess.run(
            ["docker", "ps", "--all", "--quiet", *filters], env=dict(source),
            capture_output=True, text=True, timeout=max(0.01, deadline - time.monotonic()),
        )
        if listed.returncode != 0:
            raise RuntimeError("cannot inspect shared-runtime containers for cleanup")
        containers = listed.stdout.split()
        if any(not re.fullmatch(r"[0-9a-f]{12,64}", item) for item in containers):
            raise RuntimeError("invalid Docker container IDs during runtime cleanup")
        if containers:
            subprocess.run(
                ["docker", "rm", "--force", *containers], env=dict(source),
                capture_output=True, text=True, timeout=max(0.01, deadline - time.monotonic()),
            )
            # A tool may have already removed its --rm container. Verify the
            # filtered set instead of treating that benign race as a failure.
            verified = subprocess.run(
                ["docker", "ps", "--all", "--quiet", *filters], env=dict(source),
                capture_output=True, text=True, timeout=max(0.01, deadline - time.monotonic()),
            )
            if verified.returncode != 0 or verified.stdout.strip():
                raise RuntimeError("shared-runtime analyzer cleanup incomplete")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("shared-runtime analyzer cleanup unavailable") from exc


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Shared Docker runtime job utilities")
    parser.add_argument("command", choices=["check", "cleanup"])
    args = parser.parse_args()
    try:
        if config() is None:
            parser.error("LAKES_DOCKER_MODE=external is required")
        configure()
        if args.command == "cleanup":
            cleanup(whole_job=True)
        else:
            subprocess.run(
                ["docker", "info"], check=True, timeout=10,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
    except ValueError as exc:
        parser.error(str(exc))
    except (OSError, RuntimeError, subprocess.SubprocessError):
        parser.exit(1, "shared Docker runtime check/cleanup failed\n")


if __name__ == "__main__":
    main()
