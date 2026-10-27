"""Shared killable subprocess boundary for analyzer execution."""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
from typing import Mapping, Sequence

from toolrank import docker_runtime


_PROCESS_REAP_TIMEOUT_SECONDS = 0.2


@dataclass(frozen=True)
class DeadlineProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    elapsed_seconds: float = 0.0


def _terminate_process_group(proc: subprocess.Popen[str]) -> None:
    if os.name != "posix" and proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGTERM)
        else:  # pragma: no cover - the supported production runner is POSIX.
            proc.terminate()
    except (ProcessLookupError, PermissionError):
        pass
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:  # pragma: no cover - the supported production runner is POSIX.
            proc.kill()
    except ProcessLookupError:
        pass
    except PermissionError:
        # macOS can report EPERM when the process-group leader exits between
        # SIGTERM and SIGKILL. Reap/kill the direct child without allowing that
        # race to escape the typed timeout boundary.
        try:
            proc.kill()
        except (ProcessLookupError, PermissionError):
            pass
    try:
        proc.wait(timeout=_PROCESS_REAP_TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, ProcessLookupError, PermissionError):
        pass


def _communicate_after_termination(
    proc: subprocess.Popen[str],
) -> tuple[str | None, str | None]:
    """Drain closed pipes without introducing an unbounded timeout grace."""
    try:
        return proc.communicate(timeout=_PROCESS_REAP_TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None, None


def run_process_with_deadline(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
    capture_output: bool = True,
    display_command: Sequence[str] | None = None,
    ready_file: str | Path | None = None,
    startup_timeout_seconds: float = 10.0,
) -> DeadlineProcessResult:
    runtime_env = docker_runtime.process_env(env)
    try:
        result = _run_process_with_deadline(
            command, timeout_seconds=timeout_seconds, cwd=cwd, env=runtime_env,
            input_text=input_text, capture_output=capture_output,
            display_command=display_command, ready_file=ready_file,
            startup_timeout_seconds=startup_timeout_seconds,
        )
    except BaseException:
        try:
            docker_runtime.cleanup(runtime_env)
        except RuntimeError:
            print("[warn] shared-runtime cleanup unavailable; scheduler must retry", file=sys.stderr)
        raise
    # Killing a client process does not stop containers on a shared daemon.
    # Preserve an original failure/timeout if cleanup also fails. A successful
    # report cannot be published as successful while cleanup remains uncertain.
    try:
        docker_runtime.cleanup(runtime_env)
    except RuntimeError as exc:
        print(f"[warn] {exc}; scheduler must retry cleanup", file=sys.stderr)
        return replace(result, returncode=result.returncode or 1,
                       stderr=(result.stderr + "\n" + str(exc)).strip())
    return result


def _run_process_with_deadline(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
    capture_output: bool = True,
    display_command: Sequence[str] | None = None,
    ready_file: str | Path | None = None,
    startup_timeout_seconds: float = 10.0,
) -> DeadlineProcessResult:
    """Run one process group and kill the complete group at its hard deadline."""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    logged = list(display_command) if display_command is not None else list(command)
    if cwd is not None:
        print(f"[run] (cwd={cwd}) {shlex.join(logged)}")
    else:
        print(f"[run] {shlex.join(logged)}")
    started = time.monotonic()
    deadline = started + timeout_seconds
    proc = subprocess.Popen(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        env=dict(env) if env is not None else None,
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
        text=True,
        start_new_session=True,
    )
    timed_out = False
    communicate_input = input_text
    if ready_file is not None:
        if proc.stdin is None:
            raise ValueError("ready_file requires input_text")
        try:
            proc.stdin.write(input_text or "")
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            try:
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        finally:
            proc.stdin = None
        communicate_input = None
        startup_deadline = min(
            deadline,
            time.monotonic() + startup_timeout_seconds,
        )
        ready_path = Path(ready_file)
        while not ready_path.exists() and proc.poll() is None:
            if time.monotonic() >= startup_deadline:
                timed_out = True
                _terminate_process_group(proc)
                break
            time.sleep(0.01)
    try:
        if timed_out:
            stdout, stderr = _communicate_after_termination(proc)
            returncode = 124
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(list(command), timeout_seconds)
            stdout, stderr = proc.communicate(
                input=communicate_input,
                timeout=remaining,
            )
            returncode = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_group(proc)
        stdout, stderr = _communicate_after_termination(proc)
        returncode = 124
    return DeadlineProcessResult(
        returncode=returncode,
        stdout=stdout or "",
        stderr=stderr or "",
        timed_out=timed_out,
        elapsed_seconds=(time.monotonic() - started),
    )
