"""Bounded failure evidence that is never scanned as an analyzer report."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import uuid
from typing import Iterator, Sequence, TextIO

from toolrank.report_validity import OUTPUT_CLEANUP_FAILURE_RETURN_CODE, atomic_write_text, describe_report_failure
from toolrank.schemas import ToolExecutionStatus, ToolFailureDiagnostic


MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_FILES_PER_INPUT = 64
_TRUNCATED = b"[diagnostic output truncated]\n"
_COPY_LOCK = threading.Lock()


def secret_values(*extra: str) -> tuple[str, ...]:
    return tuple(sorted({
        value for name, value in os.environ.items()
        if value and (
            any(part in name.upper() for part in ("KEY", "TOKEN", "SECRET", "PASSWORD"))
            or name.upper() == "EMBEDDINGAPI"
        )
    } | {value for value in extra if value}, key=len, reverse=True))


def redact(text: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, "***")
    return text


class _DiagnosticTee:
    def __init__(self, stream: TextIO, handle, secrets: Sequence[str]):
        self.stream, self.handle, self.secrets = stream, handle, secrets
        self.lock = threading.Lock()
        self.failed = False

    def write(self, text: str) -> int:
        safe = redact(text, self.secrets)
        self.stream.write(safe)
        raw = safe.encode("utf-8", errors="replace")
        with self.lock:
            if not self.failed:
                try:
                    if self.handle.tell() + len(raw) > MAX_FILE_BYTES:
                        self.handle.seek(0)
                        self.handle.truncate()
                        self.handle.write(_TRUNCATED)
                        raw = raw[-(MAX_FILE_BYTES - len(_TRUNCATED)):]
                    self.handle.write(raw)
                except OSError:
                    self.failed = True
        return len(text)

    def flush(self) -> None:
        self.stream.flush()

    def fileno(self) -> int:
        return self.stream.fileno()


@contextmanager
def capture_worker_logs(directory: Path, secrets: Sequence[str]) -> Iterator[None]:
    """Keep streamed worker output, including evidence left by a killed worker."""
    with ExitStack() as stack:
        try:
            stdout = stack.enter_context((directory / "worker.stdout.log").open("wb", buffering=0))
            stderr = stack.enter_context((directory / "worker.stderr.log").open("wb", buffering=0))
        except OSError:
            # Diagnostic storage must not prevent a tool from executing.
            yield
            return
        with redirect_stdout(_DiagnosticTee(sys.stdout, stdout, secrets)), redirect_stderr(
            _DiagnosticTee(sys.stderr, stderr, secrets)
        ):
            yield


def _component(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", value)[:80]
    return safe if safe not in {"", ".", ".."} else "input"


def _log_tail(directory: Path | None) -> str:
    if directory is None:
        return ""
    for name in ("worker.stderr.log", "worker.stdout.log"):
        try:
            text = (directory / name).read_bytes()[-4000:].decode("utf-8", errors="replace").strip()
        except OSError:
            continue
        if text:
            return text
    return ""


def record_failure(
    *,
    diagnostics_root: Path,
    tool_id: str,
    input_id: str,
    return_code: int,
    timeout_seconds: float,
    staged_root: Path | None = None,
    log_directory: Path | None = None,
    stdout: str = "",
    stderr: str = "",
    failure_code: str = "",
    detail: str = "",
    secrets: Sequence[str] = (),
) -> ToolFailureDiagnostic:
    """Save an isolated failed attempt; storage errors never replace its outcome."""
    if not failure_code:
        if return_code == 124:
            failure_code, detail = "TOOL_TIMEOUT", f"tool exceeded its {timeout_seconds:g}s outer deadline"
        elif return_code == 65:
            failure_code, detail = "INPUT_UNSUPPORTED", "tool does not support this input kind"
        else:
            failure_code, detail = "TOOL_EXIT_ERROR", f"tool exited with code {return_code}"
            if staged_root is not None:
                report_code, report_detail = describe_report_failure(staged_root)
                if report_code == "ANALYZER_ERROR":
                    failure_code, detail = report_code, report_detail
    tail = stderr.strip()[-4000:] or _log_tail(log_directory)
    if failure_code in {"TOOL_EXIT_ERROR", "REPORT_MISSING"} and tail:
        detail += ": " + tail
    detail = redact(detail, secrets)[:4000]
    result = ToolFailureDiagnostic(
        input_id=input_id, return_code=return_code, failure_code=failure_code, detail=detail,
    )
    digest = hashlib.sha256(input_id.encode()).hexdigest()[:16]
    tool_directory = diagnostics_root / _component(tool_id)
    destination = tool_directory / (_component(Path(input_id).stem) + "-" + digest + "-" + uuid.uuid4().hex[:12])
    try:
        with _COPY_LOCK:
            if diagnostics_root.is_symlink() or tool_directory.is_symlink():
                raise OSError("diagnostics directory is a symlink")
            destination.mkdir(parents=True, exist_ok=True)
            used = sum(p.stat().st_size for p in diagnostics_root.rglob("*") if p.is_file() and not p.is_symlink())
            files: list[str] = []
            omitted: list[str] = []
            truncated = False
            # Read enough overlap to redact a credential that straddles the file cap.
            read_limit = MAX_FILE_BYTES + max((len(value.encode()) for value in secrets), default=0) + 1

            def save(relative: Path, raw: bytes) -> None:
                nonlocal used, truncated
                safe = redact(raw.decode("utf-8", errors="replace"), secrets).encode("utf-8")
                if len(safe) > MAX_FILE_BYTES:
                    safe = safe[:MAX_FILE_BYTES - len(_TRUNCATED)] + _TRUNCATED
                    truncated = True
                truncated = truncated or _TRUNCATED in safe
                if used + len(safe) > MAX_TOTAL_BYTES:
                    omitted.append(relative.as_posix())
                    return
                path = destination / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(safe)
                used += len(safe)
                files.append(relative.as_posix())

            if staged_root is not None and staged_root.is_dir():
                count = 0
                visited_directories = 0
                for current, directories, names in os.walk(staged_root, followlinks=False):
                    visited_directories += 1
                    if visited_directories > MAX_FILES_PER_INPUT:
                        omitted.append("additional report directories")
                        break
                    directories[:] = sorted(name for name in directories if not (Path(current) / name).is_symlink())
                    for name in sorted(names):
                        if count >= MAX_FILES_PER_INPUT:
                            omitted.append("additional report files")
                            break
                        count += 1
                        source = Path(current) / name
                        if source.is_symlink() or not source.is_file():
                            continue
                        if source.suffix.lower() not in {".json", ".log", ".txt", ".sarif"}:
                            continue
                        relative = Path("reports") / source.relative_to(staged_root)
                        with source.open("rb") as handle:
                            save(relative, handle.read(read_limit))
                    if count >= MAX_FILES_PER_INPUT:
                        if not omitted:
                            omitted.append("report file inspection limit reached")
                        break
            if log_directory is not None:
                for name in ("worker.stdout.log", "worker.stderr.log"):
                    path = log_directory / name
                    if path.is_file() and not path.is_symlink():
                        with path.open("rb") as handle:
                            save(Path(name), handle.read(read_limit))
            for name, text in (("stdout.log", stdout), ("stderr.log", stderr)):
                if text:
                    save(Path(name), text.encode("utf-8", errors="replace"))
            result = result.model_copy(update={
                "directory": destination.relative_to(diagnostics_root.parent).as_posix(),
                "truncated": truncated or bool(omitted),
            })
            manifest = {
                "schema_version": "execution_diagnostic_v1",
                "tool": tool_id, "timeout_seconds": timeout_seconds,
                **result.model_dump(mode="json"), "files": files, "omitted_files": omitted,
            }
            atomic_write_text(destination / "diagnostic.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    except OSError as exc:
        result = result.model_copy(update={
            "directory": None, "preservation_error": redact(str(exc), secrets)[:1000],
        })
    return result


def record_rejected_report(**kwargs) -> ToolFailureDiagnostic:
    code, detail = describe_report_failure(kwargs["staged_root"])
    return record_failure(**kwargs, failure_code=code, detail=detail)


def status_from_outcome(
    return_code: int,
    runtime_minutes: float | None = None,
    diagnostics: Sequence[ToolFailureDiagnostic] = (),
) -> ToolExecutionStatus:
    if return_code == 0:
        return ToolExecutionStatus(status="SUCCESS", return_code=0, runtime_minutes=runtime_minutes)
    diagnostic = diagnostics[0] if diagnostics else None
    return ToolExecutionStatus(
        status="TIMEOUT" if return_code == 124 else "FAIL",
        return_code=return_code, runtime_minutes=runtime_minutes,
        failure_code=diagnostic.failure_code if diagnostic else (
            "OUTPUT_CLEANUP_FAILED" if return_code == OUTPUT_CLEANUP_FAILURE_RETURN_CODE else "TOOL_TIMEOUT" if return_code == 124 else "TOOL_EXIT_ERROR"
        ),
        detail=diagnostic.detail if diagnostic else (
            "output cleanup failed" if return_code == OUTPUT_CLEANUP_FAILURE_RETURN_CODE else ""
        ),
        diagnostics=list(diagnostics),
    )


def write_diagnostic_index(results_root: Path, statuses: dict[str, ToolExecutionStatus]) -> None:
    tools = {tool: [item.model_dump(mode="json") for item in status.diagnostics]
             for tool, status in statuses.items() if status.diagnostics}
    if not tools:
        return
    try:
        if (results_root / "diagnostics").is_symlink():
            raise OSError("diagnostics directory is a symlink")
        atomic_write_text(results_root / "diagnostics" / "index.json", json.dumps({
            "schema_version": "execution_diagnostics_v1", "tools": tools,
        }, ensure_ascii=False, indent=2) + "\n")
    except OSError:
        print("[warn] diagnostic index could not be saved", file=sys.stderr)
