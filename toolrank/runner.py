"""Packaged analyzer runner for LAKES execution plans.

The runner follows the command contract produced by ``toolrank.execution``:

    python -m toolrank.runner TARGET RESULTS --tools slither,mythril \
        --primary_tool slither --tool_categories mythril:ARITHMETIC

It executes the selected tools, stores per-tool JSON reports, and enriches
findings with canonical DASP categories so the LAKES fusion layer can apply
category ownership.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterator, Literal, Mapping, Optional, Sequence

from toolrank.categories import normalize_category
from toolrank.adapter_capabilities import adapter_supports_input
from toolrank.compilation import (
    CompilationBundleError,
    CompilationStatus,
    Stage3CompilationBundle,
    build_compilation_bundle,
    failed_compilation_bundle,
    load_compilation_bundle,
    validate_compilation_bundle,
    write_compilation_manifest,
)
from toolrank.execution_status import aggregate_tool_status_history
from toolrank.fusion import compact_fused_report_payload, fuse_reports
from toolrank.openai_compat import (
    DEFAULT_DEEPSEEK_BASE_URL,
    DEFAULT_DEEPSEEK_MODEL,
    resolve_api_key_from_env,
)
from toolrank.process_deadline import run_process_with_deadline
from toolrank.report_validity import (
    OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
    atomic_write_text,
    canonical_contract_output_dir,
    clear_canonical_final_artifacts,
    clear_selected_run_artifacts,
    find_valid_report,
    load_valid_report,
    make_run_quarantine_root,
    promote_valid_report_tree,
    remove_or_quarantine_tree,
)
from toolrank.report_parser import REPORT_INPUT_FILENAME_KEY, load_per_tool_findings_from_run_dir
from toolrank.runner_adapter import (
    _enrich_report_with_categories,
    _load_mapping,
    _map_tool_name,
    _parse_tools,
)
from toolrank.schemas import CompositionPlan, FusedReport, ToolExecutionStatus
from toolrank.source_project import (
    copy_dependency_tree,
    dependency_closure,
    mask_solidity_noncode_for_pragmas,
    solidity_imports,
    source_entrypoints,
)
from toolrank.solc_range import (
    representative_solidity_version,
    version_satisfies_solidity_constraint,
)
from toolrank.target_inputs import classify_target_input

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _repo_path(relative: str) -> Path:
    return _REPO_ROOT / relative


def _env_value(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


def _env_value_from(
    env: Mapping[str, str] | None,
    *names: str,
    default: str = "",
) -> str:
    if env is None:
        return _env_value(*names, default=default)
    for name in names:
        value = env.get(name)
        if value:
            return value
    return default


SECURIFY2_RUNNER = Path(_env_value("LAKES_SECURIFY2_RUNNER", "TOOLRANK_SECURIFY2_RUNNER", default=str(_repo_path("docker/vendor/securify2/securifyjson.py"))))
SECURIFY2_PLATFORM = _env_value("LAKES_SECURIFY2_PLATFORM", "TOOLRANK_SECURIFY2_PLATFORM", default="linux/amd64")
SECURIFY2_DEFAULT_SOLC = _env_value("LAKES_SECURIFY2_DEFAULT_SOLC", "TOOLRANK_SECURIFY2_DEFAULT_SOLC", default="0.5.12")
SECURIFY2_IMAGE_TEMPLATE = _env_value("LAKES_SECURIFY2_IMAGE_TEMPLATE", "TOOLRANK_SECURIFY2_IMAGE_TEMPLATE", default="securify:{version}")
GPTSCAN_ROOT = Path(_env_value("LAKES_GPTSCAN_ROOT", "TOOLRANK_GPTSCAN_ROOT", default=str(_repo_path("docker/vendor/gptscan"))))
GPTSCAN_PY = GPTSCAN_ROOT / ".venv" / "bin" / "python"
GPTSCAN_MAIN = GPTSCAN_ROOT / "src" / "main.py"
GPTSCAN_DEFAULT_API_BASE = DEFAULT_DEEPSEEK_BASE_URL
GPTSCAN_DEFAULT_MODEL_GPT4 = DEFAULT_DEEPSEEK_MODEL
SAILFISH_RUNNER = Path(_env_value("LAKES_SAILFISH_RUNNER", "TOOLRANK_SAILFISH_RUNNER", default=str(_repo_path("docker/runners/run_sailfish.py"))))
SAILFISH_DEFAULT_SOLC = _env_value("LAKES_SAILFISH_DEFAULT_SOLC", "TOOLRANK_SAILFISH_DEFAULT_SOLC", default="0.4.25")
SMARTIAN_RUNNER = Path(_env_value("LAKES_SMARTIAN_RUNNER", "TOOLRANK_SMARTIAN_RUNNER", default=str(_repo_path("docker/runners/run_smartian.py"))))
SMARTBUGS_PROJECT_RUNNER = Path(__file__).with_name("smartbugs_project.py")

_PRAGMA_SOLIDITY_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_SOLC_SELECT_VERSION_RE = re.compile(r"(?<![0-9.])(\d+\.\d+\.\d+)(?![0-9.])")
_SECURIFY2_IMAGE_CACHE: set[str] = set()
_SECURIFY2_IMAGE_INSPECT_ATTEMPTS = 3
_SECURIFY2_IMAGE_INSPECT_TIMEOUT_SECONDS = 5.0
_SECURIFY2_IMAGE_INSPECT_BACKOFF_SECONDS = 0.05
_SECURIFY2_IMAGE_INSPECT_MAX_BACKOFF_SECONDS = 0.1
_SECURIFY2_IMAGE_INSPECT_STDERR_LIMIT = 2048
_ADAPTER_WORKER_ARG = "--_adapter-worker"
UNSUPPORTED_INPUT_RETURN_CODE = 65
COMPILATION_FAILURE_RETURN_CODE = 66


def _resolve_gptscan_api_base(
    explicit: str = "",
    *,
    env: Mapping[str, str] | None = None,
) -> str:
    return (
        explicit.strip()
        or _env_value_from(env, "OPENAI_API_BASE").strip()
        or _env_value_from(env, "OPENAI_BASE_URL").strip()
        or _env_value_from(
            env,
            "LAKES_GPTSCAN_DEFAULT_API_BASE",
            "TOOLRANK_GPTSCAN_DEFAULT_API_BASE",
        ).strip()
        or _env_value_from(env, "LAKES_OPENAI_BASE_URL").strip()
        or _env_value_from(env, "TOOLRANK_OPENAI_BASE_URL").strip()
        or GPTSCAN_DEFAULT_API_BASE.strip()
        or DEFAULT_DEEPSEEK_BASE_URL
    )


def _resolve_gptscan_api_key(
    explicit: str = "",
    api_base: str = "",
    *,
    env: Mapping[str, str] | None = None,
) -> str:
    explicit_key = explicit.strip()
    if explicit_key:
        return explicit_key
    return resolve_api_key_from_env(
        _resolve_gptscan_api_base(api_base, env=env),
        env=env,
    ).strip()


def _resolve_gptscan_model(*, env: Mapping[str, str] | None = None) -> str:
    return (
        _env_value_from(env, "GPTSCAN_MODEL_GPT4", "GPTSCAN_MODEL").strip()
        or _env_value_from(
            env,
            "LAKES_GPTSCAN_DEFAULT_MODEL_GPT4",
            "TOOLRANK_GPTSCAN_DEFAULT_MODEL_GPT4",
        ).strip()
        or _env_value_from(env, "LAKES_OPENAI_MODEL").strip()
        or _env_value_from(env, "TOOLRANK_OPENAI_MODEL").strip()
        or GPTSCAN_DEFAULT_MODEL_GPT4.strip()
        or DEFAULT_DEEPSEEK_MODEL
    )


@dataclass(frozen=True)
class SmartBugsInvocation:
    command: list[str]
    cwd: Path
    env: dict[str, str] | None


class SmartBugsPreparationError(RuntimeError):
    """The requested input cannot be converted into a SmartBugs invocation."""


def _die(message: str, code: int = 1) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)


def _stream_process(
    command: list[str],
    cwd: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
    display_command: Optional[list[str]] = None,
    redactions: Sequence[str] = (),
) -> int:
    logged_command = display_command or command
    if cwd is not None:
        print(f"[run] (cwd={cwd}) {shlex.join(logged_command)}")
    else:
        print(f"[run] {shlex.join(logged_command)}")
    proc = subprocess.Popen(
        command,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            safe_line = line
            for secret in redactions:
                if secret:
                    safe_line = safe_line.replace(secret, "***")
            print(safe_line, end="")
    finally:
        proc.stdout.close()
    return proc.wait()


def _run_securify2_build_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    display_command: Optional[list[str]] = None,
    redactions: Sequence[str] = (),
) -> int:
    logged_command = display_command or command
    print(f"[run] (cwd={cwd}) {shlex.join(logged_command)}")
    # BuildKit helpers may retain stdout after the docker client exits. A
    # regular file lets this worker wait for the direct child and replay the
    # available output without blocking on a descendant-held pipe.
    try:
        with tempfile.NamedTemporaryFile(mode="w+b") as captured:
            proc = subprocess.Popen(
                command,
                cwd=str(cwd),
                env=env,
                stdout=captured,
                stderr=subprocess.STDOUT,
            )
            returncode = proc.wait()
            captured.flush()
            with open(captured.name, "rb") as replay:
                for raw_line in replay:
                    safe_line = raw_line.decode("utf-8", errors="replace")
                    for secret in redactions:
                        if secret:
                            safe_line = safe_line.replace(secret, "***")
                    print(safe_line, end="")
    except OSError:
        print("[warn] securify2 image build process could not start", file=sys.stderr)
        return 1
    return returncode


def _inspect_docker_image(image: str) -> Literal["exists", "missing", "error"]:
    ambiguous_failure: str | None = None
    for attempt in range(_SECURIFY2_IMAGE_INSPECT_ATTEMPTS):
        try:
            completed = subprocess.run(
                ["docker", "image", "inspect", image],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
                timeout=_SECURIFY2_IMAGE_INSPECT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            ambiguous_failure = "Docker image inspection timed out"
        except OSError:
            print(
                "[warn] docker executable unavailable for securify2 image "
                "inspection; refusing to build",
                file=sys.stderr,
            )
            return "error"
        else:
            if completed.returncode == 0:
                return "exists"
            stderr = completed.stderr or ""
            if not isinstance(stderr, str):
                stderr = stderr.decode("utf-8", errors="replace")
            bounded_stderr = stderr[:_SECURIFY2_IMAGE_INSPECT_STDERR_LIMIT]
            normalized_stderr = bounded_stderr.casefold()
            if "no such image" not in normalized_stderr:
                if "cannot connect to the docker daemon" in normalized_stderr:
                    ambiguous_failure = "Docker daemon unavailable"
                elif "context deadline exceeded" in normalized_stderr:
                    ambiguous_failure = "Docker context deadline exceeded"
                elif "permission denied" in normalized_stderr:
                    ambiguous_failure = "Docker access denied"
                elif "error during connect" in normalized_stderr:
                    ambiguous_failure = "Docker daemon connection failed"
                else:
                    ambiguous_failure = (
                        f"Docker returned exit code {completed.returncode}"
                    )

        if attempt + 1 < _SECURIFY2_IMAGE_INSPECT_ATTEMPTS:
            time.sleep(
                min(
                    _SECURIFY2_IMAGE_INSPECT_BACKOFF_SECONDS * (attempt + 1),
                    _SECURIFY2_IMAGE_INSPECT_MAX_BACKOFF_SECONDS,
                )
            )

    if ambiguous_failure is None:
        return "missing"
    print(
        f"[warn] securify2 image inspection failed after "
        f"{_SECURIFY2_IMAGE_INSPECT_ATTEMPTS} attempts ({ambiguous_failure}); "
        "refusing to build",
        file=sys.stderr,
    )
    return "error"


def _normalize_category_label(label: str) -> str:
    return normalize_category(label).upper()


def _parse_tool_category_filters(raw: str) -> dict[str, list[str] | None]:
    if not raw:
        return {}
    parsed: dict[str, list[str] | None] = {}
    for part in raw.replace("\uFF0C", ",").split(","):
        item = part.strip()
        if not item:
            continue
        if ":" in item:
            tool_part, categories_part = item.split(":", 1)
        else:
            tool_part, categories_part = item, "ALL"
        tool_key = _map_tool_name(tool_part)
        if not tool_key:
            continue
        if not categories_part.strip() or categories_part.strip().upper() == "ALL":
            parsed[tool_key] = None
            continue
        categories = [
            _normalize_category_label(token).lower()
            for token in re.split(r"[|;/]", categories_part)
            if token.strip()
        ]
        parsed[tool_key] = sorted(dict.fromkeys(categories)) or None
    return parsed


@dataclass(frozen=True)
class RunnerInput:
    path: Path
    kind: str


def _discover_target_inputs(target_path: Path) -> list[RunnerInput]:
    if target_path.is_file():
        kind = classify_target_input(target_path)
        return [RunnerInput(target_path, kind)] if kind is not None else []
    if not target_path.is_dir():
        return []

    classified = [
        (path, kind)
        for path in sorted(target_path.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and (kind := classify_target_input(path)) is not None
    ]
    source_files = [path for path, kind in classified if kind == "sol"]
    source_roots = source_entrypoints(source_files, target_path)
    inputs = [RunnerInput(path, "sol") for path in source_roots]
    inputs.extend(
        RunnerInput(path, kind)
        for path, kind in classified
        if kind != "sol"
    )
    return inputs


def _relative_contract_path(contract_path: Path, target_root: Path) -> Path:
    if target_root.is_file():
        return Path(".")
    try:
        return contract_path.relative_to(target_root)
    except ValueError:
        return Path(contract_path.name)


def _logical_input_id(contract_path: Path, target_root: Path) -> str:
    project_root = target_root if target_root.is_dir() else contract_path.parent
    try:
        return contract_path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return contract_path.name


def _find_result_json(out_dir: Path) -> Optional[Path]:
    return find_valid_report(out_dir)


def _load_report(report_path: Path) -> Optional[dict]:
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return None
    return payload if isinstance(payload, dict) else None


def _load_valid_gptscan_raw(report_path: Path) -> Optional[dict]:
    """Accept only an explicit successful GPTScan result list."""
    payload = _load_report(report_path)
    if payload is None:
        return None
    if payload.get("success") is not True:
        return None
    if not isinstance(payload.get("results"), list):
        return None
    return payload


def _write_enriched_report(
    report_path: Path,
    tool_id: str,
    mapping: dict[tuple[str, str], str],
    input_filename: str | None = None,
) -> bool:
    report = load_valid_report(report_path)
    if report is None:
        return False
    try:
        enriched = _enrich_report_with_categories(report, tool_id, mapping)
        if input_filename is not None:
            enriched[REPORT_INPUT_FILENAME_KEY] = input_filename
        report_path.write_text(
            json.dumps(enriched, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except (OSError, TypeError, ValueError):
        return False
    return load_valid_report(report_path) is not None


def _collect_pragma_specs(
    contract_path: Path,
    *,
    target_root: Path | None = None,
) -> list[str]:
    source_paths = [contract_path]
    if target_root is not None:
        project_root = target_root if target_root.is_dir() else contract_path.parent
        try:
            source_paths = dependency_closure(contract_path, project_root)
        except ValueError:
            source_paths = [contract_path]
    specs: list[str] = []
    for source_path in source_paths:
        try:
            text = source_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        stripped = mask_solidity_noncode_for_pragmas(text)
        specs.extend(
            match.group(1).strip()
            for match in _PRAGMA_SOLIDITY_RE.finditer(stripped)
        )
    return specs


def _solc_lower_bound(
    contract_path: Path,
    *,
    target_root: Path | None = None,
) -> Optional[str]:
    return representative_solidity_version(
        _collect_pragma_specs(contract_path, target_root=target_root)
    )


def _write_skip_report(out_dir: Path, tool_id: str, message: str) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "result.json").write_text(
        json.dumps(
            {
                "errors": [],
                "fails": [],
                "findings": [],
                "infos": [message],
                "parser": {"tool": tool_id, "status": "skipped"},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[skip] {tool_id}: {message}", file=sys.stderr)
    return UNSUPPORTED_INPUT_RETURN_CODE


def _installed_solc_select_versions() -> list[str]:
    try:
        completed = subprocess.run(
            ["solc-select", "versions"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0:
        return []
    versions = set(
        _SOLC_SELECT_VERSION_RE.findall(
            f"{completed.stdout or ''}\n{completed.stderr or ''}"
        )
    )
    return sorted(
        versions,
        key=lambda value: tuple(int(part) for part in value.split(".")),
    )


def _run_solc_select(
    contract_path: Path,
    tool_label: str,
    *,
    target_root: Path | None = None,
) -> bool:
    constraints = _collect_pragma_specs(contract_path, target_root=target_root)
    if not constraints:
        print(f"[warn] pragma lower-bound not found; keep current solc for {tool_label}", file=sys.stderr)
        return True
    installed = _installed_solc_select_versions()
    compatible = [
        version
        for version in installed
        if all(
            version_satisfies_solidity_constraint(version, constraint)
            for constraint in constraints
        )
    ]
    if not compatible:
        joined = "; ".join(constraints)
        print(
            f"[warn] no installed solc satisfies {tool_label} constraints: {joined}",
            file=sys.stderr,
        )
        return False
    version = compatible[0]
    try:
        rc = _stream_process(["solc-select", "use", version])
    except FileNotFoundError:
        print("[warn] solc-select not found in PATH", file=sys.stderr)
        return False
    if rc != 0:
        print(f"[warn] solc-select use {version} failed (rc={rc})", file=sys.stderr)
        return False
    return True


def _run_gptscan(
    contract_path: Path,
    out_dir: Path,
    api_key: str,
    gptscan_timeout: int,
    openai_api_base: str,
    *,
    model: str = "",
    target_root: Path | None = None,
) -> int:
    if not GPTSCAN_MAIN.exists():
        print(f"[warn] GPTScan main.py not found: {GPTSCAN_MAIN}", file=sys.stderr)
        return 1
    resolved_root = target_root or contract_path
    if not _run_solc_select(
        contract_path,
        "gptscan",
        target_root=resolved_root,
    ):
        return 1
    temp_dir: Optional[tempfile.TemporaryDirectory[str]] = tempfile.TemporaryDirectory(
        prefix="gptscan_src_"
    )
    scan_source = Path(temp_dir.name)
    try:
        if resolved_root.is_dir():
            source_files = [
                path
                for path in sorted(resolved_root.rglob("*.sol"))
                if path.is_file() and not path.is_symlink()
            ]
            entrypoints = source_entrypoints(source_files, resolved_root)
            for entrypoint in entrypoints:
                copy_dependency_tree(entrypoint, resolved_root, scan_source)
        else:
            copy_dependency_tree(
                contract_path,
                contract_path.parent,
                scan_source,
            )
    except (OSError, ValueError) as exc:
        print(f"[warn] GPTScan source staging failed: {exc}", file=sys.stderr)
        temp_dir.cleanup()
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)
    gpt_out = out_dir / "gptscan_output.json"
    result_path = out_dir / "result.json"
    try:
        result_path.unlink(missing_ok=True)
    except OSError:
        print("[warn] GPTScan result preparation failed", file=sys.stderr)
        return 1
    api_base = _resolve_gptscan_api_base(openai_api_base)
    key = _resolve_gptscan_api_key(api_key, api_base)
    wrapper = Path(__file__).with_name("gptscan_safe_entry.py")
    command = [
        str(GPTSCAN_PY if GPTSCAN_PY.exists() else Path(sys.executable)),
        str(wrapper),
    ]
    env = _sanitized_adapter_env()
    env["OPENAI_API_KEY"] = key
    env["OPENAI_API_BASE"] = api_base
    env["OPENAI_BASE_URL"] = env["OPENAI_API_BASE"]
    env["GPTSCAN_USE_GPT4"] = env.get("GPTSCAN_USE_GPT4", "1")
    env["GPTSCAN_MODEL_GPT4"] = model.strip() or _resolve_gptscan_model()
    env["GPTSCAN_TIMEOUT_SECONDS"] = str(gptscan_timeout)
    env["LAKES_GPTSCAN_MAIN"] = str(GPTSCAN_MAIN)
    env["LAKES_GPTSCAN_SOURCE"] = str(scan_source)
    env["LAKES_GPTSCAN_OUTPUT"] = str(gpt_out)
    masked = command[:]
    if "-k" in masked:
        key_index = masked.index("-k") + 1
        if key_index < len(masked):
            masked[key_index] = "***"
    try:
        rc = _stream_process(
            command,
            cwd=GPTSCAN_MAIN.parent,
            env=env,
            display_command=masked,
            redactions=[key],
        )
        if rc != 0:
            return rc
        raw_report = _load_valid_gptscan_raw(gpt_out)
        if raw_report is None:
            print("[warn] GPTScan output missing or structurally invalid", file=sys.stderr)
            return 1
        report = _normalize_gptscan_report(
            raw_report,
            staged_source_root=scan_source,
            original_source_root=(
                resolved_root if resolved_root.is_dir() else contract_path.parent
            ),
        )
        result_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return 0
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def _normalize_gptscan_report(
    payload: dict,
    *,
    staged_source_root: Path | None = None,
    original_source_root: Path | None = None,
) -> dict:
    report = {"errors": [], "fails": [], "findings": [], "infos": [], "parser": {"tool": "gptscan"}}
    if payload.get("success") is False:
        report["errors"].append("GPTSCAN_FAILED")
        if payload.get("message"):
            report["fails"].append(str(payload["message"]))
    for item in payload.get("results") or []:
        if not isinstance(item, dict):
            continue
        name = item.get("code") or item.get("title") or "gptscan_issue"
        message = item.get("description") or ""
        recommendation = item.get("recommendation") or ""
        if recommendation:
            message = f"{message}\nRecommendation: {recommendation}" if message else f"Recommendation: {recommendation}"
        base_finding = {
            **deepcopy(item),
            "name": str(name),
            "message": message,
            "explanation": message,
        }
        files = item.get("affectedFiles") or []
        start_count = len(report["findings"])
        for file_item in files:
            if not isinstance(file_item, dict):
                continue
            finding = deepcopy(base_finding)
            if file_item.get("filePath"):
                filename = str(file_item["filePath"])
                if staged_source_root is not None and original_source_root is not None:
                    staged_path = Path(filename)
                    if not staged_path.is_absolute():
                        staged_path = staged_source_root / staged_path
                    try:
                        relative = staged_path.resolve().relative_to(staged_source_root.resolve())
                    except ValueError:
                        pass
                    else:
                        filename = str((original_source_root / relative).resolve())
                finding["filename"] = filename
            range_item = file_item.get("range") or {}
            start = (range_item.get("start") or {}).get("line")
            end = (range_item.get("end") or {}).get("line")
            if start is not None:
                finding["line"] = int(start)
                finding["line_end"] = int(end) if end is not None else int(start)
            report["findings"].append(finding)
        if len(report["findings"]) == start_count:
            report["findings"].append(base_finding)
    return report


def _run_securify2(
    contract_path: Path,
    out_dir: Path,
    *,
    target_root: Path,
) -> int:
    if not SECURIFY2_RUNNER.exists():
        print(f"[warn] securify2 runner not found: {SECURIFY2_RUNNER}", file=sys.stderr)
        return 1
    version = _solc_lower_bound(contract_path, target_root=target_root)
    if version and not version_satisfies_solidity_constraint(version, ">=0.5.0"):
        return _write_skip_report(
            out_dir,
            "securify2",
            f"securify2 supports Solidity ASTs from 0.5.0; detected {version}",
        )
    version = version or SECURIFY2_DEFAULT_SOLC
    image = SECURIFY2_IMAGE_TEMPLATE.format(version=version)
    if image not in _SECURIFY2_IMAGE_CACHE:
        image_state = _inspect_docker_image(image)
        if image_state == "error":
            return 1
        if image_state == "exists":
            print("[cache] securify2 image inspect confirmed existing tag; skipping build")
        if image_state == "missing":
            dockerfile = SECURIFY2_RUNNER.parent / "Dockerfile"
            if not dockerfile.is_file():
                print(f"[warn] securify2 Dockerfile not found: {dockerfile}", file=sys.stderr)
                return 1
            build_env = os.environ.copy()
            build_env["DOCKER_BUILDKIT"] = "1"
            build_env["DOCKER_DEFAULT_PLATFORM"] = SECURIFY2_PLATFORM
            rc = _run_securify2_build_process(
                ["docker", "build", "--platform", SECURIFY2_PLATFORM, "--build-arg", f"SOLC={version}", "-t", image, "."],
                cwd=SECURIFY2_RUNNER.parent,
                env=build_env,
            )
            if rc != 0:
                return rc
        _SECURIFY2_IMAGE_CACHE.add(image)
    out_dir.mkdir(parents=True, exist_ok=True)
    return _stream_process(
        [
            "python3",
            str(SECURIFY2_RUNNER),
            str(contract_path),
            "-o",
            str(out_dir / "result.json"),
            "--image",
            image,
            "--platform",
            SECURIFY2_PLATFORM,
            "--debug-cmd",
            "--project-root",
            str(target_root if target_root.is_dir() else contract_path.parent),
        ],
        cwd=SECURIFY2_RUNNER.parent,
    )


def _run_sailfish(
    contract_path: Path,
    out_dir: Path,
    timeout: int,
    *,
    target_root: Path,
) -> int:
    if not SAILFISH_RUNNER.exists():
        print(f"[warn] sailfish runner not found: {SAILFISH_RUNNER}", file=sys.stderr)
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)
    solc_ver = (
        _solc_lower_bound(contract_path, target_root=target_root)
        or SAILFISH_DEFAULT_SOLC
    )
    workspace = target_root if target_root.is_dir() else contract_path.parent
    try:
        source_name = contract_path.relative_to(workspace).as_posix()
    except ValueError:
        source_name = contract_path.name
    return _stream_process(
        [
            sys.executable,
            str(SAILFISH_RUNNER),
            str(workspace),
            source_name,
            solc_ver,
            "--artifacts_root",
            str(out_dir),
            "--timeout",
            str(timeout),
        ],
    )


def _run_smartian(
    contract_path: Path,
    out_dir: Path,
    timeout: float,
    *,
    target_root: Path,
    compilation_bundle: Stage3CompilationBundle,
    logical_input_id: str,
) -> int:
    if not SMARTIAN_RUNNER.exists():
        print(f"[warn] smartian runner not found: {SMARTIAN_RUNNER}", file=sys.stderr)
        return 1
    route = compilation_bundle.route_for("smartian", logical_input_id)
    if route is None:
        print("[warn] Smartian shared compilation route not found", file=sys.stderr)
        return 1
    compiled = compilation_bundle.contracts.get(route.fully_qualified_contract)
    if (
        compiled is None
        or compiled.abi is None
        or not compiled.creation_bytecode
    ):
        print("[warn] Smartian shared artifacts are incomplete", file=sys.stderr)
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="smartian_") as tmp:
        tmp_path = Path(tmp)
        abi_path = tmp_path / "contract.abi.json"
        bytecode_path = tmp_path / "contract.bin"
        abi_path.write_text(
            json.dumps(compiled.abi, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        bytecode_path.write_text(compiled.creation_bytecode, encoding="utf-8")
        rc = _stream_process(
            [
                sys.executable,
                str(SMARTIAN_RUNNER),
                str(contract_path),
                tmp,
                "--timeout",
                format(float(timeout), ".15g"),
                "--project-root",
                str(target_root if target_root.is_dir() else contract_path.parent),
                "--shared-abi",
                str(abi_path),
                "--shared-bytecode",
                str(bytecode_path),
                "--shared-contract-key",
                route.fully_qualified_contract,
                "--shared-bundle-id",
                compilation_bundle.manifest.bundle_id or "",
                "--shared-compiler-version",
                compilation_bundle.manifest.compiler_version or "",
                "--shared-compiler-binary",
                compilation_bundle.manifest.compiler_binary or "",
            ],
        )
        produced = next(Path(tmp).rglob("result.json"), None)
        if produced is not None:
            shutil.copy2(produced, out_dir / "result.json")
        else:
            print("[warn] smartian produced no result.json", file=sys.stderr)
        return rc


def _compile_runtime_hex_for_vandal(
    contract_path: Path,
    *,
    target_root: Path,
) -> Optional[str]:
    if not _run_solc_select(
        contract_path,
        "vandal",
        target_root=target_root,
    ):
        return None
    try:
        proc = subprocess.run(
            ["solc", "--combined-json", "bin-runtime", str(contract_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        print("[warn] solc not found in PATH for vandal runtime compile", file=sys.stderr)
        return None
    if proc.returncode != 0:
        print(f"[warn] solc compile failed for vandal: {proc.stderr.strip()}", file=sys.stderr)
        return None
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    contracts = payload.get("contracts")
    if not isinstance(contracts, dict):
        return None
    preferred = [key for key in contracts if str(key).endswith(f":{contract_path.stem}")]
    for key in preferred + [key for key in contracts if key not in preferred]:
        runtime_hex = str((contracts.get(key) or {}).get("bin-runtime") or "").strip()
        if runtime_hex:
            return runtime_hex
    return None


def _prepare_runtime_hex_file_for_vandal(
    contract_path: Path,
    *,
    target_root: Path,
    compilation_bundle: Stage3CompilationBundle,
    logical_input_id: str,
) -> tuple[Optional[Path], Optional[tempfile.TemporaryDirectory[str]]]:
    route = compilation_bundle.route_for("vandal", logical_input_id)
    compiled = (
        compilation_bundle.contracts.get(route.fully_qualified_contract)
        if route is not None
        else None
    )
    runtime_hex = compiled.runtime_bytecode if compiled is not None else None
    if not runtime_hex:
        return None, None
    temp_dir = tempfile.TemporaryDirectory(prefix="vandal_rt_")
    path = Path(temp_dir.name) / f"{contract_path.stem}.rt.hex"
    path.write_text(runtime_hex, encoding="utf-8")
    return path, temp_dir


@contextmanager
def prepare_smartbugs_invocation(
    tool_id: str,
    contract_path: Path,
    out_dir: Path,
    *,
    target_root: Path,
    smartbugs_dir: Optional[Path],
    timeout: int | float,
    input_kind: str,
    compilation_bundle: Stage3CompilationBundle | None = None,
    logical_input_id: str | None = None,
) -> Iterator[SmartBugsInvocation]:
    """Prepare one typed generic SmartBugs invocation and clean temp input."""

    temp_input_dir: Optional[tempfile.TemporaryDirectory[str]] = None
    target_input = contract_path
    runtime_mode = False
    effective_kind = input_kind
    if tool_id == "vandal" and input_kind == "sol":
        if compilation_bundle is None or logical_input_id is None:
            raise SmartBugsPreparationError(
                "Vandal source execution requires a ready shared compilation bundle"
            )
        target_input, temp_input_dir = _prepare_runtime_hex_file_for_vandal(
            contract_path,
            target_root=target_root,
            compilation_bundle=compilation_bundle,
            logical_input_id=logical_input_id,
        )
        if target_input is None:
            raise SmartBugsPreparationError("Vandal runtime projection is missing")
        runtime_mode = True
        effective_kind = "runtime"
        print(f"[vandal] runtime_input={target_input}")
    elif input_kind in {"bytecode", "runtime"}:
        temp_input_dir = tempfile.TemporaryDirectory(prefix=f"lakes_{input_kind}_")
        suffix = ".rt.hex" if input_kind == "runtime" else ".hex"
        target_input = Path(temp_input_dir.name) / f"{contract_path.stem}{suffix}"
        try:
            bytecode = contract_path.read_text(encoding="utf-8", errors="ignore")
            target_input.write_text(
                "".join(bytecode.split()).removeprefix("0x"),
                encoding="utf-8",
            )
        except OSError as exc:
            temp_input_dir.cleanup()
            temp_input_dir = None
            raise SmartBugsPreparationError(f"bytecode input unreadable: {exc}") from exc
        runtime_mode = input_kind == "runtime"

    try:
        resolved_smartbugs_dir = smartbugs_dir or _resolve_smartbugs_dir(target_root)
        env: dict[str, str] | None = None
        smartbugs_api_available = all(
            (resolved_smartbugs_dir / relative).is_file()
            for relative in ("sb/cli.py", "sb/docker.py")
        )
        exact_execution_solc = (
            compilation_bundle.manifest.compiler_version
            if compilation_bundle is not None
            else None
        )
        requires_project_bridge = effective_kind == "sol" and (
            bool(exact_execution_solc)
            or not (target_root.is_file() and not solidity_imports(contract_path))
        )
        if requires_project_bridge and not smartbugs_api_available:
            raise SmartBugsPreparationError(
                "SmartBugs Python API unavailable; cannot preserve source imports"
            )
        if effective_kind == "sol" and smartbugs_api_available:
            smartbugs_python = resolved_smartbugs_dir / ".venv" / "bin" / "python"
            command_prefix = [
                str(smartbugs_python if smartbugs_python.exists() else Path(sys.executable)),
                str(SMARTBUGS_PROJECT_RUNNER),
            ]
            env = os.environ.copy()
            pythonpath = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = os.pathsep.join(
                part
                for part in (
                    str(_REPO_ROOT),
                    str(resolved_smartbugs_dir),
                    pythonpath,
                )
                if part
            )
            project_root = target_root if target_root.is_dir() else contract_path.parent
            env["LAKES_PROJECT_ROOT"] = str(project_root.resolve())
            env["LAKES_SOLIDITY_CONSTRAINTS"] = json.dumps(
                [exact_execution_solc]
                if exact_execution_solc
                else _collect_pragma_specs(
                    contract_path,
                    target_root=target_root,
                )
            )
            if exact_execution_solc:
                env["LAKES_EXECUTION_SOLC_VERSION"] = exact_execution_solc
        else:
            command_prefix = ["./smartbugs"]
        command = [
            *command_prefix,
            "-t",
            tool_id,
            "-f",
            str(target_input),
            "--timeout",
            str(max(1, int(math.ceil(float(timeout))))),
            "--continue-on-errors",
            "--results",
            str(out_dir),
            "--sarif",
            "--json",
        ]
        if runtime_mode:
            command.append("--runtime")
        yield SmartBugsInvocation(command, resolved_smartbugs_dir, env)
    finally:
        if temp_input_dir is not None:
            temp_input_dir.cleanup()


def _candidate_smartbugs_dirs(target_path: Path) -> list[Path]:
    candidates: list[Path] = []
    smartbugs_dir = _env_value("LAKES_SMARTBUGS_DIR", "TOOLRANK_SMARTBUGS_DIR")
    if smartbugs_dir:
        candidates.append(Path(smartbugs_dir))
    for base in [Path.cwd(), target_path if target_path.is_dir() else target_path.parent, Path(__file__).resolve()]:
        for parent in [base, *base.parents]:
            candidates.append(parent / "smartbugs")
    deduped: list[Path] = []
    for candidate in candidates:
        resolved = candidate.expanduser()
        if resolved not in deduped:
            deduped.append(resolved)
    return deduped


def _resolve_smartbugs_dir(target_path: Path) -> Path:
    for candidate in _candidate_smartbugs_dirs(target_path):
        executable = candidate / "smartbugs"
        if candidate.is_dir() and executable.exists() and os.access(executable, os.X_OK):
            return candidate
    checked = ", ".join(str(path) for path in _candidate_smartbugs_dirs(target_path)[:5])
    raise RuntimeError(f"SmartBugs executable not found. Set LAKES_SMARTBUGS_DIR. Checked: {checked}")


def _run_smartbugs_tool(
    tool_id: str,
    contract_path: Path,
    out_dir: Path,
    *,
    target_root: Path,
    smartbugs_dir: Optional[Path],
    timeout: int | float,
    gptscan_timeout: int,
    openai_api_key: str,
    openai_api_base: str,
    gptscan_model: str = "",
    input_kind: str = "sol",
    compilation_bundle: Stage3CompilationBundle | None = None,
    logical_input_id: str | None = None,
) -> int:
    if not adapter_supports_input(tool_id, input_kind):
        print(
            f"[unsupported] tool={tool_id} input_kind={input_kind}",
            file=sys.stderr,
        )
        return UNSUPPORTED_INPUT_RETURN_CODE
    if tool_id == "securify2":
        return _run_securify2(contract_path, out_dir, target_root=target_root)
    if tool_id == "gptscan":
        return _run_gptscan(
            contract_path,
            out_dir,
            openai_api_key,
            gptscan_timeout,
            openai_api_base,
            model=gptscan_model,
            target_root=target_root,
        )
    if tool_id == "sailfish":
        return _run_sailfish(contract_path, out_dir, timeout, target_root=target_root)
    if tool_id == "smartian":
        if compilation_bundle is None or logical_input_id is None:
            print("[warn] Smartian source route requires shared compilation", file=sys.stderr)
            return 1
        return _run_smartian(
            contract_path,
            out_dir,
            timeout,
            target_root=target_root,
            compilation_bundle=compilation_bundle,
            logical_input_id=logical_input_id,
        )

    try:
        with prepare_smartbugs_invocation(
            tool_id,
            contract_path,
            out_dir,
            target_root=target_root,
            smartbugs_dir=smartbugs_dir,
            timeout=timeout,
            input_kind=input_kind,
            compilation_bundle=compilation_bundle,
            logical_input_id=logical_input_id,
        ) as invocation:
            return _stream_process(
                invocation.command,
                cwd=invocation.cwd,
                env=invocation.env,
            )
    except (OSError, RuntimeError) as exc:
        print(f"[warn] SmartBugs input preparation failed: {exc}", file=sys.stderr)
        return 1


def _adapter_worker_main() -> int:
    """Run one adapter in an isolated process group from a private stdin request."""
    try:
        request = json.load(sys.stdin)
        ready_path = request.get("ready_path")
        if ready_path:
            Path(ready_path).touch()
        raw_bundle = request.get("compilation_bundle")
        bundle = (
            Stage3CompilationBundle.model_validate(raw_bundle)
            if isinstance(raw_bundle, dict)
            else None
        )
        return _run_smartbugs_tool(
            str(request["tool_id"]),
            Path(request["contract_path"]),
            Path(request["out_dir"]),
            target_root=Path(request["target_root"]),
            smartbugs_dir=(
                Path(request["smartbugs_dir"])
                if request.get("smartbugs_dir")
                else None
            ),
            timeout=request["timeout"],
            gptscan_timeout=int(request["gptscan_timeout"]),
            openai_api_key=str(request.get("openai_api_key") or ""),
            openai_api_base=str(request.get("openai_api_base") or ""),
            gptscan_model=str(request.get("gptscan_model") or ""),
            input_kind=str(request.get("input_kind") or "sol"),
            compilation_bundle=bundle,
            logical_input_id=str(request.get("logical_input_id") or "") or None,
        )
    except Exception as exc:
        print(
            f"[warn] adapter worker failed: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1


def _sanitized_adapter_env() -> dict[str, str]:
    """Remove chat and embedding credentials from generic worker environments."""
    env = os.environ.copy()
    provider_secrets = {
        "DEEPSEEK_API_KEY",
        "SILICONFLOW_API_KEY",
        "QWEN_API_KEY",
        "WHATAI_API_KEY",
        "EMBEDDINGAPI",
    }
    for name in list(env):
        if "OPENAI" in name.upper() or name.upper() in provider_secrets:
            env.pop(name, None)
    return env


def _run_adapter_with_deadline(
    tool_id: str,
    contract_path: Path,
    out_dir: Path,
    *,
    target_root: Path,
    smartbugs_dir: Optional[Path],
    timeout: float,
    gptscan_timeout: int,
    openai_api_key: str,
    openai_api_base: str,
    gptscan_model: str = "",
    mapping: dict[tuple[str, str], str] | None = None,
    quarantine_root: Path,
    input_kind: str | None = None,
    compilation_bundle: Stage3CompilationBundle | None = None,
    logical_input_id: str | None = None,
) -> int:
    """Enforce one outer deadline around the complete adapter implementation."""
    if not remove_or_quarantine_tree(out_dir, quarantine_root):
        print(f"[warn] output cleanup failed tool={tool_id}", file=sys.stderr)
        return OUTPUT_CLEANUP_FAILURE_RETURN_CODE
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"lakes_{tool_id}_attempt_") as tmp:
        staged_out = Path(tmp) / "result"
        ready_path = Path(tmp) / "worker.ready"
        request = {
            "tool_id": tool_id,
            "contract_path": str(contract_path),
            "out_dir": str(staged_out),
            "target_root": str(target_root),
            "smartbugs_dir": str(smartbugs_dir) if smartbugs_dir is not None else None,
            "timeout": (
                float(timeout)
                if tool_id == "smartian"
                else max(1, int(math.ceil(float(timeout))))
            ),
            "gptscan_timeout": gptscan_timeout,
            "ready_path": str(ready_path),
            "input_kind": input_kind or classify_target_input(contract_path) or "sol",
            "logical_input_id": logical_input_id,
        }
        if compilation_bundle is not None:
            request["compilation_bundle"] = compilation_bundle.model_dump(mode="json")
        if tool_id == "gptscan":
            resolved_api_base = _resolve_gptscan_api_base(openai_api_base)
            request["openai_api_key"] = _resolve_gptscan_api_key(
                openai_api_key,
                resolved_api_base,
            )
            request["openai_api_base"] = resolved_api_base
            request["gptscan_model"] = (
                gptscan_model.strip() or _resolve_gptscan_model()
            )
        command = [sys.executable, "-m", "toolrank.runner", _ADAPTER_WORKER_ARG]
        completed = run_process_with_deadline(
            command,
            timeout_seconds=timeout,
            cwd=_REPO_ROOT,
            input_text=json.dumps(request),
            capture_output=False,
            display_command=command,
            ready_file=ready_path,
            env=_sanitized_adapter_env(),
        )
        if completed.timed_out:
            print(
                f"[warn] outer tool timeout tool={tool_id} timeout_seconds={timeout}",
                file=sys.stderr,
            )
            return 124
        if completed.returncode != 0:
            return completed.returncode
        result_path = find_valid_report(staged_out)
        if result_path is None:
            print(f"[warn] invalid current-run report tool={tool_id}", file=sys.stderr)
            return 1
        input_filename = (
            str(contract_path.resolve())
            if request["input_kind"] in {"bytecode", "runtime"} or tool_id == "vandal"
            else None
        )
        if not _write_enriched_report(result_path, tool_id, mapping or {}, input_filename):
            print(f"[warn] report enrichment failed tool={tool_id}", file=sys.stderr)
            return 1
        if not promote_valid_report_tree(
            staged_out,
            out_dir,
            quarantine_root=quarantine_root,
        ):
            print(f"[warn] report promotion failed tool={tool_id}", file=sys.stderr)
            return (
                OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                if out_dir.exists()
                else 1
            )
        return 0


def _run_one_tool_for_contract(
    tool_name: str,
    contract_path: Path,
    *,
    target_root: Path,
    results_root: Path,
    mapping: dict[tuple[str, str], str],
    smartbugs_dir: Optional[Path],
    timeout: float,
    gptscan_timeout: int,
    openai_api_key: str,
    openai_api_base: str,
    quarantine_root: Path,
    input_kind: str | None = None,
    compilation_bundle: Stage3CompilationBundle | None = None,
    logical_input_id: str | None = None,
) -> tuple[str, int, float]:
    rel = _relative_contract_path(contract_path, target_root)
    tool_id = _map_tool_name(tool_name)
    out_dir = results_root / tool_id / rel
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    rc = _run_adapter_with_deadline(
        tool_id,
        contract_path,
        out_dir,
        target_root=target_root,
        smartbugs_dir=smartbugs_dir,
        timeout=timeout,
        gptscan_timeout=gptscan_timeout,
        openai_api_key=openai_api_key,
        openai_api_base=openai_api_base,
        mapping=mapping,
        quarantine_root=quarantine_root,
        input_kind=input_kind or classify_target_input(contract_path) or "sol",
        compilation_bundle=compilation_bundle,
        logical_input_id=logical_input_id,
    )
    if rc != 0:
        print(f"[warn] tool run failed tool={tool_id} exit_code={rc}", file=sys.stderr)
        return tool_id, rc, (time.monotonic() - started) / 60.0
    result_path = _find_result_json(out_dir)
    if result_path is None or not _write_enriched_report(result_path, tool_id, mapping):
        cleanup_ok = remove_or_quarantine_tree(out_dir, quarantine_root)
        print(f"[warn] result.json missing or invalid for tool={tool_id}", file=sys.stderr)
        return (
            tool_id,
            1 if cleanup_ok else OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
            (time.monotonic() - started) / 60.0,
        )
    return tool_id, 0, (time.monotonic() - started) / 60.0


def _run_one_contract(
    contract_path: Path,
    *,
    target_root: Path,
    results_root: Path,
    selected_tools: list[str],
    mapping: dict[tuple[str, str], str],
    smartbugs_dir: Optional[Path],
    timeout: float,
    gptscan_timeout: int,
    openai_api_key: str,
    openai_api_base: str,
    jobs: int,
    quarantine_root: Path,
    input_kind: str | None = None,
    compilation_bundle: Stage3CompilationBundle | None = None,
    logical_input_id: str | None = None,
) -> tuple[int, dict[str, ToolExecutionStatus]]:
    exit_code = 0
    statuses: dict[str, ToolExecutionStatus] = {}
    if jobs <= 1 or len(selected_tools) <= 1:
        for tool_name in selected_tools:
            _tool_id, rc, runtime_minutes = _run_one_tool_for_contract(
                tool_name,
                contract_path,
                target_root=target_root,
                results_root=results_root,
                mapping=mapping,
                smartbugs_dir=smartbugs_dir,
                timeout=timeout,
                gptscan_timeout=gptscan_timeout,
                openai_api_key=openai_api_key,
                openai_api_base=openai_api_base,
                quarantine_root=quarantine_root,
                input_kind=input_kind,
                compilation_bundle=compilation_bundle,
                logical_input_id=logical_input_id,
            )
            if rc != 0:
                exit_code = (
                    OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                    if rc == OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                    or exit_code == OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                    else rc
                )
                statuses[_tool_id] = ToolExecutionStatus(
                    status="TIMEOUT" if rc == 124 else "FAIL",
                    runtime_minutes=runtime_minutes,
                    return_code=rc,
                    detail=(
                        "output cleanup failed"
                        if rc == OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                        else ""
                    ),
                )
            else:
                statuses[_tool_id] = ToolExecutionStatus(
                    status="SUCCESS",
                    runtime_minutes=runtime_minutes,
                    return_code=0,
                )
            if rc == OUTPUT_CLEANUP_FAILURE_RETURN_CODE:
                break
        return exit_code, statuses

    max_workers = min(jobs, len(selected_tools))
    print(f"[parallel] jobs={max_workers} tools={','.join(selected_tools)}")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _run_one_tool_for_contract,
                tool_name,
                contract_path,
                target_root=target_root,
                results_root=results_root,
                mapping=mapping,
                smartbugs_dir=smartbugs_dir,
                timeout=timeout,
                gptscan_timeout=gptscan_timeout,
                openai_api_key=openai_api_key,
                openai_api_base=openai_api_base,
                quarantine_root=quarantine_root,
                input_kind=input_kind,
                compilation_bundle=compilation_bundle,
                logical_input_id=logical_input_id,
            ): tool_name
            for tool_name in selected_tools
        }
        for future in as_completed(futures):
            tool_name = futures[future]
            try:
                _tool_id, rc, runtime_minutes = future.result()
            except Exception as exc:  # pragma: no cover - defensive guard around external tools.
                print(f"[warn] tool run crashed tool={tool_name} error={exc}", file=sys.stderr)
                if exit_code != OUTPUT_CLEANUP_FAILURE_RETURN_CODE:
                    exit_code = 1
                statuses[_map_tool_name(tool_name)] = ToolExecutionStatus(
                    status="FAIL", return_code=1, detail=str(exc)
                )
                continue
            if rc != 0:
                exit_code = (
                    OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                    if rc == OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                    or exit_code == OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                    else rc
                )
                statuses[_tool_id] = ToolExecutionStatus(
                    status="TIMEOUT" if rc == 124 else "FAIL",
                    runtime_minutes=runtime_minutes,
                    return_code=rc,
                    detail=(
                        "output cleanup failed"
                        if rc == OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                        else ""
                    ),
                )
            else:
                statuses[_tool_id] = ToolExecutionStatus(
                    status="SUCCESS",
                    runtime_minutes=runtime_minutes,
                    return_code=0,
                )
    return exit_code, statuses


def _aggregate_tool_status_history(
    history: Sequence[ToolExecutionStatus],
) -> ToolExecutionStatus:
    return aggregate_tool_status_history(history)


def _write_fusion_plan(
    results_root: Path,
    *,
    selected_tools: list[str],
    primary_tool: str,
    tool_categories: dict[str, list[str] | None],
) -> None:
    results_root.mkdir(parents=True, exist_ok=True)
    payload = {
        "selected_tools": selected_tools,
        "primary_tool": primary_tool,
        "category_owners": {
            category: [primary_tool, tool]
            for tool, categories in tool_categories.items()
            if tool != primary_tool and categories is not None
            for category in categories
        },
    }
    atomic_write_text(
        results_root / "fusion_plan.json",
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )


def _write_tool_status_manifest(
    results_root: Path,
    statuses: dict[str, ToolExecutionStatus],
) -> None:
    results_root.mkdir(parents=True, exist_ok=True)
    (results_root / "tool_run_statuses.json").write_text(
        json.dumps(
            {
                tool: status.model_dump(mode="json")
                for tool, status in statuses.items()
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _compilation_failure_statuses(
    tools: Sequence[str],
    bundle: Stage3CompilationBundle,
) -> dict[str, ToolExecutionStatus]:
    reason = bundle.manifest.failure_reason
    detail = (
        f"compilation {reason.code}: {reason.detail}" if reason is not None else "compilation failed"
    )
    return {
        tool: ToolExecutionStatus(
            status="NOT_RUN",
            detail=detail,
            artifact_consumption=bundle.tool_consumption.get(tool),
        )
        for tool in tools
    }


def _tool_results_root(results_root: Path, target_path: Path, *, write_lakes_output: bool) -> Path:
    if not write_lakes_output:
        return results_root
    return canonical_contract_output_dir(results_root, target_path) / "raw"


def _composition_from_runner_inputs(
    *,
    selected_tools: list[str],
    primary_tool: str,
    tool_categories: dict[str, list[str] | None],
) -> CompositionPlan:
    category_owners: dict[str, list[str]] = {}
    for tool_id, categories in tool_categories.items():
        if tool_id == primary_tool or categories is None:
            continue
        for category in categories:
            category_owners[category] = [primary_tool, tool_id]
    return CompositionPlan(
        selected_tool_ids=selected_tools,
        primary_tool_id=primary_tool,
        complementary_tool_ids=[tool for tool in selected_tools if tool != primary_tool],
        estimated_plan_runtime_minutes=0.0,
        category_owners=category_owners,
    )


def _raw_findings_to_finding(tool_id: str, raw_findings: list[dict]) -> list:
    from toolrank.engine import _normalize_raw_findings

    return _normalize_raw_findings(tool_id, raw_findings)


def _build_fused_report_from_run(
    *,
    results_root: Path,
    composition: CompositionPlan,
    tool_statuses: dict[str, ToolExecutionStatus],
) -> FusedReport:
    raw_by_tool = load_per_tool_findings_from_run_dir(results_root, set(composition.selected_tool_ids))
    findings_by_tool = {
        tool_id: _raw_findings_to_finding(tool_id, raw_findings)
        for tool_id, raw_findings in raw_by_tool.items()
    }
    return fuse_reports(
        findings_by_tool,
        composition,
        tool_statuses=tool_statuses,
        findings_source="execution",
    )


def _write_lakes_outputs(
    results_root: Path,
    *,
    target_path: Path,
    composition: CompositionPlan,
    fused_report: FusedReport,
) -> Path:
    lakes_dir = canonical_contract_output_dir(results_root, target_path)
    lakes_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        lakes_dir / "fusion_plan.json",
        json.dumps(composition.model_dump(), indent=2, sort_keys=True) + "\n",
    )
    atomic_write_text(
        lakes_dir / "tool_run_statuses.json",
        json.dumps(
            {
                tool: status.model_dump(mode="json")
                for tool, status in fused_report.tool_statuses.items()
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    atomic_write_text(
        lakes_dir / "fused_report.json",
        json.dumps(
            compact_fused_report_payload(fused_report),
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
    )
    return lakes_dir


def run_targets(
    target_path: str | Path,
    results_root: str | Path,
    selected_tools: Sequence[str],
    *,
    primary_tool: str = "",
    tool_categories: str = "",
    smartbugs_dir: str | Path | None = None,
    timeout: float = 1200,
    gptscan_timeout: int = 600,
    openai_api_key: str = "",
    openai_api_base: str = "",
    jobs: int = 0,
    write_lakes_output: bool = True,
    compilation_bundle: Stage3CompilationBundle | str | Path | None = None,
    selected_tool_solc_ranges: dict[str, str] | None = None,
) -> int:
    target = Path(target_path).resolve()
    root = Path(results_root).expanduser().absolute()
    if not target.exists():
        _die(f"Target path not found: {target}", 1)
    if timeout <= 0:
        _die("--timeout must be positive", 2)
    if gptscan_timeout <= 0:
        _die("--gptscan_timeout must be a positive integer", 2)
    if jobs < 0:
        _die("--jobs must be non-negative", 2)
    tools = [tool for tool in selected_tools if str(tool).strip()]
    if not tools:
        _die("No tools selected. Use --tool or --tools.", 1)

    try:
        target_inputs = _discover_target_inputs(target)
    except ValueError as exc:
        _die(f"Invalid source project: {exc}", 1)
    if not target_inputs:
        _die(f"No supported .sol/.bin/.hex inputs found: {target}", 1)

    mapped_primary = _map_tool_name(primary_tool) if primary_tool else _map_tool_name(tools[0])
    mapped_tools = list(dict.fromkeys(_map_tool_name(tool) for tool in tools))
    if mapped_primary in mapped_tools:
        mapped_tools.remove(mapped_primary)
    mapped_tools.insert(0, mapped_primary)
    if jobs != 0 and jobs < len(mapped_tools):
        _die("--jobs must provide one worker per selected tool", 2)
    effective_jobs = len(mapped_tools) if jobs == 0 else jobs
    parsed_tool_categories = _parse_tool_category_filters(tool_categories)
    composition = _composition_from_runner_inputs(
        selected_tools=mapped_tools,
        primary_tool=mapped_primary,
        tool_categories=parsed_tool_categories,
    )
    if write_lakes_output:
        output_dir = canonical_contract_output_dir(root, target)
        output_dir.mkdir(parents=True, exist_ok=True)
        if not clear_canonical_final_artifacts(output_dir):
            print("[warn] canonical LAKES output cleanup failed", file=sys.stderr)
            return OUTPUT_CLEANUP_FAILURE_RETURN_CODE
        _write_fusion_plan(
            output_dir,
            selected_tools=mapped_tools,
            primary_tool=mapped_primary,
            tool_categories=parsed_tool_categories,
        )

    mapping = _load_mapping()
    resolved_smartbugs_dir = Path(smartbugs_dir).resolve() if smartbugs_dir else None
    tool_results_root = _tool_results_root(root, target, write_lakes_output=write_lakes_output)
    quarantine_root = make_run_quarantine_root(tool_results_root)
    if not clear_selected_run_artifacts(
        tool_results_root,
        mapped_tools,
        quarantine_root=quarantine_root,
    ):
        print("[warn] selected-tool output cleanup failed", file=sys.stderr)
        return OUTPUT_CLEANUP_FAILURE_RETURN_CODE
    if not remove_or_quarantine_tree(
        tool_results_root / "compilation_manifest.json",
        quarantine_root,
    ):
        print("[warn] compilation manifest cleanup failed", file=sys.stderr)
        return OUTPUT_CLEANUP_FAILURE_RETURN_CODE

    if compilation_bundle is None:
        bundle = build_compilation_bundle(
            target,
            mapped_tools,
            selected_tool_solc_ranges=selected_tool_solc_ranges,
        )
    else:
        try:
            bundle = (
                load_compilation_bundle(compilation_bundle)
                if isinstance(compilation_bundle, (str, Path))
                else compilation_bundle
            )
            if bundle.manifest.status != CompilationStatus.FAILED:
                validate_compilation_bundle(bundle, target, mapped_tools)
        except CompilationBundleError as exc:
            bundle = failed_compilation_bundle(
                target,
                mapped_tools,
                code=exc.code,
                detail=exc.detail,
            )
    write_compilation_manifest(bundle, tool_results_root)
    if bundle.manifest.status == CompilationStatus.FAILED:
        statuses = _compilation_failure_statuses(mapped_tools, bundle)
        _write_tool_status_manifest(tool_results_root, statuses)
        reason = bundle.manifest.failure_reason
        print(
            f"[warn] compilation preflight failed: {reason.code if reason else 'unknown'}",
            file=sys.stderr,
        )
        return (
            124
            if reason is not None and reason.code == "COMPILATION_TIMEOUT"
            else COMPILATION_FAILURE_RETURN_CODE
        )
    exit_code = 0
    cleanup_failed = False
    status_history: dict[str, list[ToolExecutionStatus]] = {
        tool: [] for tool in mapped_tools
    }
    successful_shared_consumers: set[str] = set()
    gptscan_source_dispatched = False
    for index, target_input in enumerate(target_inputs, start=1):
        contract = target_input.path
        logical_input_id = _logical_input_id(contract, target)
        print(
            f"\n[batch] {index}/{len(target_inputs)} "
            f"kind={target_input.kind} {contract}"
        )
        tools_for_input = mapped_tools
        if target_input.kind == "sol" and gptscan_source_dispatched:
            tools_for_input = [tool for tool in mapped_tools if tool != "gptscan"]
        elif target_input.kind == "sol" and "gptscan" in mapped_tools:
            gptscan_source_dispatched = True
        if not tools_for_input:
            continue
        rc, contract_statuses = _run_one_contract(
            contract,
            target_root=target,
            results_root=tool_results_root,
            selected_tools=tools_for_input,
            mapping=mapping,
            smartbugs_dir=resolved_smartbugs_dir,
            timeout=timeout,
            gptscan_timeout=gptscan_timeout,
            openai_api_key=openai_api_key,
            openai_api_base=openai_api_base,
            jobs=effective_jobs,
            quarantine_root=quarantine_root,
            input_kind=target_input.kind,
            compilation_bundle=bundle,
            logical_input_id=logical_input_id,
        )
        if rc != 0:
            exit_code = (
                OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                if rc == OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                or exit_code == OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                else rc
            )
        if rc == OUTPUT_CLEANUP_FAILURE_RETURN_CODE:
            cleanup_failed = True
        for tool, status in contract_statuses.items():
            status_history.setdefault(tool, []).append(status)
            if (
                status.status == "SUCCESS"
                and target_input.kind == "sol"
                and bundle.route_for(tool, logical_input_id) is not None
            ):
                successful_shared_consumers.add(tool)
        if cleanup_failed:
            break

    final_statuses: dict[str, ToolExecutionStatus] = {}
    for tool in mapped_tools:
        history = status_history.get(tool, [])
        consumption = bundle.tool_consumption.get(tool)
        if consumption is not None:
            consumption = consumption.model_copy(
                update={"consumed": tool in successful_shared_consumers}
            )
        final_statuses[tool] = _aggregate_tool_status_history(history).model_copy(
            update={"artifact_consumption": consumption}
        )
    _write_tool_status_manifest(tool_results_root, final_statuses)
    if cleanup_failed:
        return OUTPUT_CLEANUP_FAILURE_RETURN_CODE
    if write_lakes_output:
        fused_report = _build_fused_report_from_run(
            results_root=tool_results_root,
            composition=composition,
            tool_statuses=final_statuses,
        )
        lakes_dir = _write_lakes_outputs(root, target_path=target, composition=composition, fused_report=fused_report)
        print(f"[lakes_out] {lakes_dir / 'fused_report.json'}")
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run LAKES-selected SmartBugs-style analyzers.")
    parser.add_argument("contract_or_dir", help="Path to a .sol file or directory.")
    parser.add_argument("results_root", nargs="?", default="LAKES_out", help="Output root for analyzer reports.")
    parser.add_argument("--tool", default="", help="Single tool name to run.")
    parser.add_argument("--tools", default="", help="Comma-separated tool names to run.")
    parser.add_argument("--primary_tool", default="", help="Primary tool whose categories are kept by default.")
    parser.add_argument("--tool_categories", default="", help="Per-tool category ownership, e.g. slither:REENTRANCY|TIME_MANIPULATION.")
    parser.add_argument("--smartbugs-dir", default="", help="SmartBugs checkout directory. Defaults to LAKES_SMARTBUGS_DIR or auto-discovery.")
    parser.add_argument("--timeout", type=float, default=1200, help="Per-tool timeout in seconds.")
    parser.add_argument("--gptscan_timeout", type=int, default=600, help="GPTScan LLM timeout in seconds.")
    parser.add_argument(
        "--jobs",
        type=int,
        default=0,
        help="Max tools to run in parallel per contract; 0 means one job per selected tool.",
    )
    parser.add_argument(
        "--no-lakes-output",
        action="store_true",
        help="Run tools only. Used by LAKES when the engine writes the final LAKES_out files.",
    )
    parser.add_argument(
        "--compilation-bundle",
        default="",
        help="Validated Stage 3 bundle prepared by the parent execution process.",
    )
    parser.add_argument(
        "--tool-solc-ranges",
        default="",
        help="Internal JSON map of selected tool IDs to Solidity ranges.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if raw_args == [_ADAPTER_WORKER_ARG]:
        return _adapter_worker_main()
    args = build_parser().parse_args(raw_args)
    tools = _parse_tools(args.tools)
    if not tools and args.tool:
        tools = [args.tool]
    try:
        tool_solc_ranges = (
            json.loads(args.tool_solc_ranges) if args.tool_solc_ranges else None
        )
    except json.JSONDecodeError:
        _die("--tool-solc-ranges must be a JSON object", 2)
    if tool_solc_ranges is not None and not isinstance(tool_solc_ranges, dict):
        _die("--tool-solc-ranges must be a JSON object", 2)
    gptscan_api_base = _resolve_gptscan_api_base()
    return run_targets(
        args.contract_or_dir,
        args.results_root,
        tools,
        primary_tool=args.primary_tool,
        tool_categories=args.tool_categories,
        smartbugs_dir=args.smartbugs_dir or None,
        timeout=args.timeout,
        gptscan_timeout=args.gptscan_timeout,
        openai_api_key=_resolve_gptscan_api_key(api_base=gptscan_api_base),
        openai_api_base=gptscan_api_base,
        jobs=args.jobs,
        write_lakes_output=not args.no_lakes_output,
        compilation_bundle=args.compilation_bundle or None,
        selected_tool_solc_ranges=tool_solc_ranges,
    )


if __name__ == "__main__":
    raise SystemExit(main())
