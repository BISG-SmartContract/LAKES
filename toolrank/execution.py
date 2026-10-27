from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import math
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Set

from toolrank.compilation import (
    CompilationBundleError,
    CompilationStatus,
    Stage3CompilationBundle,
    build_compilation_bundle,
    failed_compilation_bundle,
    validate_compilation_bundle,
    write_compilation_bundle,
    write_compilation_manifest,
)
from toolrank.process_deadline import run_process_with_deadline
from toolrank.execution_status import (
    aggregate_tool_status_history,
    overall_execution_status,
)
from toolrank.execution_diagnostics import (
    record_failure,
    record_rejected_report,
    redact,
    secret_values,
    status_from_outcome,
    write_diagnostic_index,
)
from toolrank.report_parser import load_per_tool_findings
from toolrank.report_validity import (
    OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
    clear_selected_run_artifacts,
    make_run_quarantine_root,
    promote_valid_report_tree,
    remove_or_quarantine_tree,
)
from toolrank.schemas import (
    CompositionPlan,
    ExecutionResult,
    ToolArtifactConsumption,
    ToolExecutionStatus,
    ToolFailureDiagnostic,
)
from toolrank.source_project import resolve_project_root

logger = logging.getLogger(__name__)
COMPILATION_FAILURE_RETURN_CODE = 66


def _resolved_artifact_consumption(
    fallback: Mapping[str, ToolArtifactConsumption],
    statuses: Mapping[str, ToolExecutionStatus],
) -> dict[str, ToolArtifactConsumption]:
    return {
        tool: status.artifact_consumption or fallback[tool]
        for tool, status in statuses.items()
        if status.artifact_consumption is not None or tool in fallback
    }


def _env_value(*names: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return ""


DEFAULT_RUNNER_SCRIPT = (
    Path(_env_value("LAKES_RUNNER_SCRIPT", "TOOLRANK_RUNNER_SCRIPT"))
    if _env_value("LAKES_RUNNER_SCRIPT", "TOOLRANK_RUNNER_SCRIPT")
    else Path(__file__).resolve().parent / "runner.py"
)
DEFAULT_RUNNER_CWD = (
    Path(_env_value("LAKES_RUNNER_CWD", "TOOLRANK_RUNNER_CWD"))
    if _env_value("LAKES_RUNNER_CWD", "TOOLRANK_RUNNER_CWD")
    else None
)
DEFAULT_SMARTBUGS_DIR = (
    Path(_env_value("LAKES_SMARTBUGS_DIR", "TOOLRANK_SMARTBUGS_DIR"))
    if _env_value("LAKES_SMARTBUGS_DIR", "TOOLRANK_SMARTBUGS_DIR")
    else None
)


def _stream_runner_output(
    command: List[str],
    *,
    cwd: Optional[str],
    env: Mapping[str, str] | None = None,
    tail_chars: int = 4000,
) -> tuple[int, Optional[str], Optional[str]]:
    """Run a command while streaming stdout/stderr to the terminal.

    The process output is also retained in bounded buffers so the caller can
    persist `stdout_tail` / `stderr_tail` into `ExecutionResult`.
    """
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    redactions = [
        value
        for key, value in (env or {}).items()
        if value and any(token in key.upper() for token in ("KEY", "TOKEN", "SECRET"))
    ]
    proc = subprocess.Popen(
        command,
        cwd=cwd or None,
        env=child_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    stdout_buf: deque[str] = deque()
    stderr_buf: deque[str] = deque()
    stdout_len = 0
    stderr_len = 0
    stdout_lock = threading.Lock()
    stderr_lock = threading.Lock()

    def _append(buf: deque[str], lock: threading.Lock, current_len: int, chunk: str) -> int:
        with lock:
            buf.append(chunk)
            current_len += len(chunk)
            while current_len > tail_chars and buf:
                removed = buf.popleft()
                current_len -= len(removed)
        return current_len

    def _pump(stream, sink, buf: deque[str], lock: threading.Lock, is_stdout: bool) -> None:
        nonlocal stdout_len, stderr_len
        if stream is None:
            return
        try:
            for line in stream:
                safe_line = line
                for secret in redactions:
                    safe_line = safe_line.replace(secret, "***")
                sink.write(safe_line)
                sink.flush()
                if is_stdout:
                    stdout_len = _append(buf, lock, stdout_len, safe_line)
                else:
                    stderr_len = _append(buf, lock, stderr_len, safe_line)
        finally:
            stream.close()

    t_out = threading.Thread(
        target=_pump,
        # Stream runner stdout to the parent's stderr so shell redirection of
        # stdout can still capture a clean JSON payload from the CLI.
        args=(proc.stdout, sys.stderr, stdout_buf, stdout_lock, True),
        daemon=True,
    )
    t_err = threading.Thread(
        target=_pump,
        args=(proc.stderr, sys.stderr, stderr_buf, stderr_lock, False),
        daemon=True,
    )
    t_out.start()
    t_err.start()
    return_code = proc.wait()
    t_out.join()
    t_err.join()

    stdout_tail = "".join(stdout_buf) or None
    stderr_tail = "".join(stderr_buf) or None
    return return_code, stdout_tail, stderr_tail


def _tool_category_mapping(plan: CompositionPlan) -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    for category, owners in plan.category_owners.items():
        for tool_id in owners[1:]:
            mapping.setdefault(tool_id, []).append(category)
    for tool_id in mapping:
        mapping[tool_id] = sorted(set(mapping[tool_id]))
    return dict(sorted(mapping.items()))


def _tool_category_arg(mapping: Dict[str, List[str]]) -> str:
    parts: List[str] = []
    for tool_id, categories in mapping.items():
        if not categories:
            continue
        parts.append(f"{tool_id}:{'|'.join(category.upper() for category in categories)}")
    return ",".join(parts)


def _timeout_cli_value(timeout_seconds: float) -> str:
    """Serialize the checked outer deadline without rounding it upward."""
    return format(float(timeout_seconds), ".15g")


def build_execution_plan(
    target_path: str | Path,
    results_root: str | Path,
    composition: CompositionPlan,
    *,
    project_root: str | Path | None = None,
    runner_script: str | Path | None = None,
    runner_cwd: str | Path | None = None,
    gptscan_timeout_sec: int = 600,
    write_lakes_output: bool = True,
    selected_tool_solc_ranges: Mapping[str, str] | None = None,
) -> ExecutionResult:
    resolved_project_root = (
        resolve_project_root(target_path, project_root)
        if project_root is not None
        else None
    )
    target = (
        Path(target_path).expanduser()
        if resolved_project_root is not None
        else Path(target_path)
    ).resolve()
    runner_script_path = Path(runner_script) if runner_script else DEFAULT_RUNNER_SCRIPT
    if runner_script_path is None:
        raise ValueError("No runner script configured. Set LAKES_RUNNER_SCRIPT or pass --runner-script.")
    runner_cwd_path = Path(runner_cwd) if runner_cwd else DEFAULT_RUNNER_CWD
    selected = composition.selected_tool_ids
    schedule = composition.execution_schedule
    if schedule.execution_jobs != 0 and schedule.execution_jobs < len(selected):
        raise ValueError("execution_jobs must provide one worker per selected tool")
    primary = composition.primary_tool_id
    category_mapping = _tool_category_mapping(composition)
    command = [
        sys.executable,
        str(runner_script_path),
        str(target),
        str(Path(results_root).resolve()),
        "--tools",
        ",".join(selected),
        "--primary_tool",
        primary or "",
        "--timeout",
        _timeout_cli_value(schedule.tool_timeout_seconds),
        "--gptscan_timeout",
        str(gptscan_timeout_sec),
    ]
    command.extend(["--jobs", str(schedule.execution_jobs)])
    if resolved_project_root is not None:
        command.extend(["--project-root", str(resolved_project_root)])
    tool_categories = _tool_category_arg(category_mapping)
    if tool_categories:
        command.extend(["--tool_categories", tool_categories])
    if not write_lakes_output:
        command.append("--no-lakes-output")
    normalized_ranges = {
        tool: value
        for tool, value in (selected_tool_solc_ranges or {}).items()
        if tool in selected and value
    }
    if normalized_ranges:
        command.extend(
            [
                "--tool-solc-ranges",
                json.dumps(normalized_ranges, sort_keys=True, separators=(",", ":")),
            ]
        )

    fusion_summary = (
        f"primary={primary}; additive_complements={category_mapping}"
        if primary
        else "no primary tool selected"
    )
    return ExecutionResult(
        status="planned",
        execution_mode="manual_runner",
        target_path=str(target),
        project_root=str(resolved_project_root) if resolved_project_root is not None else None,
        results_root=str(Path(results_root).resolve()),
        runner_script=str(runner_script_path.resolve()),
        runner_cwd=str(runner_cwd_path.resolve()) if runner_cwd_path else None,
        runner_command=command,
        selected_tool_ids=selected,
        primary_tool_id=primary,
        category_owners=composition.category_owners,
        estimated_plan_runtime_minutes=composition.estimated_plan_runtime_minutes,
        execution_schedule=schedule,
        selected_tool_solc_ranges=normalized_ranges,
        tool_statuses={tool: ToolExecutionStatus() for tool in selected},
        fusion_summary=fusion_summary,
    )


def _resolve_execution_project(plan: ExecutionResult) -> ExecutionResult:
    if plan.project_root is None:
        return plan
    project_root = resolve_project_root(plan.target_path, plan.project_root)
    return plan.model_copy(update={
        "target_path": str(Path(plan.target_path).expanduser().resolve()),
        "project_root": str(project_root),
    })


def _prepare_compilation(plan: ExecutionResult) -> tuple[ExecutionResult, Stage3CompilationBundle]:
    target_path = Path(plan.target_path or "")
    selected_tools = list(dict.fromkeys(plan.selected_tool_ids))
    try:
        bundle = plan.compilation_bundle
        if bundle is None:
            bundle = build_compilation_bundle(
                target_path,
                selected_tools,
                project_root=plan.project_root,
                selected_tool_solc_ranges=plan.selected_tool_solc_ranges,
            )
        elif bundle.manifest.status != CompilationStatus.FAILED:
            validate_compilation_bundle(
                bundle, target_path, selected_tools, project_root=plan.project_root
            )
    except CompilationBundleError as exc:
        bundle = failed_compilation_bundle(
            target_path,
            selected_tools,
            project_root=plan.project_root,
            code=exc.code,
            detail=exc.detail,
        )
    return (
        plan.model_copy(
            update={
                "compilation": bundle.manifest,
                "artifact_consumption": bundle.tool_consumption,
                "compilation_bundle": bundle,
            }
        ),
        bundle,
    )


def _compilation_failed_result(
    plan: ExecutionResult,
    bundle: Stage3CompilationBundle,
    *,
    execution_mode: str,
) -> ExecutionResult:
    reason = bundle.manifest.failure_reason
    detail = (
        f"compilation {reason.code}: {reason.detail}" if reason is not None else "compilation failed"
    )
    statuses = {
        tool: ToolExecutionStatus(
            status="NOT_RUN",
            detail=detail,
            artifact_consumption=bundle.tool_consumption.get(tool),
        )
        for tool in plan.selected_tool_ids
    }
    results_root = Path(plan.results_root) if plan.results_root else None
    if results_root is not None:
        results_root.mkdir(parents=True, exist_ok=True)
        write_compilation_manifest(bundle, results_root)
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
    return plan.model_copy(
        update={
            "status": "failed",
            "execution_mode": execution_mode,
            "return_code": (
                124
                if reason is not None and reason.code == "COMPILATION_TIMEOUT"
                else COMPILATION_FAILURE_RETURN_CODE
            ),
            "stderr_tail": detail[-4000:],
            "tool_statuses": statuses,
            "per_tool_findings": {},
            "compilation": bundle.manifest,
            "artifact_consumption": bundle.tool_consumption,
            "compilation_bundle": bundle,
        }
    )


def _native_smartbugs_execute(
    plan: ExecutionResult,
    *,
    runner_env: Mapping[str, str] | None = None,
) -> ExecutionResult:
    from toolrank import runner as packaged_runner
    from toolrank.adapter_capabilities import (
        SPECIAL_ADAPTER_TOOL_IDS,
        adapter_supports_input,
    )

    plan = _resolve_execution_project(plan)
    target_path = Path(plan.target_path or "")
    project_root = Path(plan.project_root) if plan.project_root is not None else None
    results_root = Path(plan.results_root or "")
    selected_tools = list(dict.fromkeys(tool for tool in plan.selected_tool_ids if tool))
    gptscan_api_base = ""
    gptscan_api_key = ""
    gptscan_model = ""
    if "gptscan" in selected_tools:
        effective_runner_env = os.environ.copy()
        if runner_env:
            effective_runner_env.update(runner_env)
        gptscan_api_base = packaged_runner._resolve_gptscan_api_base(
            env=effective_runner_env,
        )
        gptscan_api_key = packaged_runner._resolve_gptscan_api_key(
            api_base=gptscan_api_base,
            env=effective_runner_env,
        )
        gptscan_model = packaged_runner._resolve_gptscan_model(
            env=effective_runner_env,
        )
    schedule = plan.execution_schedule
    if schedule.execution_jobs != 0 and schedule.execution_jobs < len(selected_tools):
        raise ValueError("execution_jobs must provide one worker per selected tool")
    configured_smartbugs_dir = next(
        (
            str((runner_env or {}).get(name) or "").strip()
            for name in ("LAKES_SMARTBUGS_DIR", "TOOLRANK_SMARTBUGS_DIR")
            if str((runner_env or {}).get(name) or "").strip()
        ),
        "",
    )
    smartbugs_dir = (
        Path(configured_smartbugs_dir).expanduser().resolve()
        if configured_smartbugs_dir
        else (
            DEFAULT_SMARTBUGS_DIR.expanduser().resolve()
            if DEFAULT_SMARTBUGS_DIR is not None
            else None
        )
    )
    if smartbugs_dir is None:
        return plan.model_copy(
            update={"status": "failed", "stderr_tail": "No SmartBugs directory configured. Set LAKES_SMARTBUGS_DIR."}
        )
    try:
        target_inputs = packaged_runner._discover_target_inputs(
            target_path, project_root=project_root
        )
    except ValueError as exc:
        return plan.model_copy(
            update={"status": "failed", "stderr_tail": f"Invalid source project: {exc}"}
        )
    if not target_inputs:
        return plan.model_copy(
            update={
                "status": "failed",
                "stderr_tail": "No supported .sol/.bin/.hex inputs found for native execution.",
            }
        )
    results_root.mkdir(parents=True, exist_ok=True)
    quarantine_root = make_run_quarantine_root(results_root)
    if not clear_selected_run_artifacts(
        results_root,
        selected_tools,
        quarantine_root=quarantine_root,
    ):
        statuses = {
            tool: ToolExecutionStatus(
                status="FAIL",
                return_code=OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
                detail="output cleanup failed",
            )
            for tool in selected_tools
        }
        return plan.model_copy(
            update={
                "status": "failed",
                "execution_mode": "native_smartbugs",
                "return_code": OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
                "stderr_tail": "selected execution artifact cleanup failed",
                "tool_statuses": statuses,
                "per_tool_findings": {},
            }
        )
    compilation_manifest_path = results_root / "compilation_manifest.json"
    if compilation_manifest_path.exists() and not remove_or_quarantine_tree(
        compilation_manifest_path,
        quarantine_root,
    ):
        statuses = {
            tool: ToolExecutionStatus(
                status="FAIL",
                return_code=OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
                detail="compilation manifest cleanup failed",
            )
            for tool in selected_tools
        }
        return plan.model_copy(
            update={
                "status": "failed",
                "execution_mode": "native_smartbugs",
                "return_code": OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
                "stderr_tail": "compilation manifest cleanup failed",
                "tool_statuses": statuses,
                "per_tool_findings": {},
            }
        )

    plan, compilation_bundle = _prepare_compilation(plan)
    write_compilation_manifest(compilation_bundle, results_root)
    if compilation_bundle.manifest.status == CompilationStatus.FAILED:
        return _compilation_failed_result(
            plan,
            compilation_bundle,
            execution_mode="native_smartbugs",
        )

    resolved_timeout = float(schedule.tool_timeout_seconds)
    vulnerability_mapping = packaged_runner._load_mapping()
    secrets = secret_values(gptscan_api_key)

    def run_tool(tool_id: str):
        commands: List[str] = []
        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []
        outcomes: list[tuple[str, int]] = []
        history: list[ToolExecutionStatus] = []
        runtime_seconds = 0.0
        shared_source_succeeded = False
        gptscan_source_dispatched = False
        for target_input in target_inputs:
            contract_path = target_input.path
            input_kind = target_input.kind
            logical_input_id = packaged_runner._logical_input_id(
                contract_path, target_path, project_root=project_root,
            )
            diagnostics: list[ToolFailureDiagnostic] = []

            def note_failure(code: int, **reason) -> None:
                diagnostics.append(record_failure(
                    diagnostics_root=results_root / "diagnostics", tool_id=tool_id,
                    input_id=logical_input_id, return_code=code,
                    timeout_seconds=resolved_timeout, secrets=secrets, **reason,
                ))

            if tool_id == "gptscan" and input_kind == "sol":
                if gptscan_source_dispatched:
                    continue
                gptscan_source_dispatched = True
            if not adapter_supports_input(tool_id, input_kind):
                outcomes.append((contract_path.name, 65))
                note_failure(65)
                history.append(status_from_outcome(65, diagnostics=diagnostics))
                stderr_chunks.append(
                    f"[{tool_id}:{contract_path.name}] unsupported input kind: {input_kind}"
                )
                continue
            relative = (
                Path(contract_path.name)
                if target_path.is_file()
                else contract_path.relative_to(target_path)
            )
            out_dir = results_root / tool_id / relative
            out_dir.parent.mkdir(parents=True, exist_ok=True)
            if not remove_or_quarantine_tree(out_dir, quarantine_root):
                outcomes.append(
                    (contract_path.name, OUTPUT_CLEANUP_FAILURE_RETURN_CODE)
                )
                note_failure(OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
                             failure_code="OUTPUT_CLEANUP_FAILED", detail="output cleanup failed")
                history.append(status_from_outcome(OUTPUT_CLEANUP_FAILURE_RETURN_CODE, diagnostics=diagnostics))
                stderr_chunks.append(
                    f"[{tool_id}:{contract_path.name}] output cleanup failed"
                )
                break
            shared_consumption = compilation_bundle.tool_consumption.get(tool_id)
            uses_shared_source_artifact = (
                input_kind == "sol"
                and shared_consumption is not None
                and shared_consumption.mode == "SHARED_ARTIFACT"
            )
            if tool_id in SPECIAL_ADAPTER_TOOL_IDS or uses_shared_source_artifact:
                commands.append(
                    f"packaged-adapter {tool_id} {input_kind} {contract_path}"
                )
                started = time.monotonic()
                returncode = packaged_runner._run_adapter_with_deadline(
                    tool_id,
                    contract_path,
                    out_dir,
                    target_root=target_path,
                    project_root=project_root,
                    smartbugs_dir=smartbugs_dir,
                    timeout=resolved_timeout,
                    gptscan_timeout=int(resolved_timeout),
                    openai_api_key=gptscan_api_key,
                    openai_api_base=gptscan_api_base,
                    gptscan_model=gptscan_model,
                    mapping=vulnerability_mapping,
                    quarantine_root=quarantine_root,
                    input_kind=input_kind,
                    compilation_bundle=compilation_bundle,
                    logical_input_id=logical_input_id,
                    diagnostics_root=results_root / "diagnostics",
                    diagnostics=diagnostics,
                )
                runtime_seconds += time.monotonic() - started
                outcomes.append((contract_path.name, returncode))
                history.append(status_from_outcome(returncode, diagnostics=diagnostics))
                if (
                    returncode == 0
                    and uses_shared_source_artifact
                    and compilation_bundle.route_for(tool_id, logical_input_id)
                    is not None
                ):
                    shared_source_succeeded = True
                continue
            with tempfile.TemporaryDirectory(
                prefix=f"lakes_native_{tool_id}_attempt_"
            ) as tmp:
                staged_out = Path(tmp) / "result"
                try:
                    with packaged_runner.prepare_smartbugs_invocation(
                        tool_id,
                        contract_path,
                        staged_out,
                        target_root=target_path,
                        project_root=project_root,
                        smartbugs_dir=smartbugs_dir,
                        timeout=resolved_timeout,
                        input_kind=input_kind,
                        compilation_bundle=compilation_bundle,
                        logical_input_id=logical_input_id,
                    ) as invocation:
                        cmd = invocation.command
                        commands.append(" ".join(cmd))
                        child_env = packaged_runner._sanitized_adapter_env()
                        if invocation.env is not None:
                            for name in (
                                "PYTHONPATH",
                                "LAKES_PROJECT_ROOT",
                                "LAKES_SOLIDITY_CONSTRAINTS",
                                "LAKES_EXECUTION_SOLC_VERSION",
                                "LAKES_DOCKER_TOOL",
                            ):
                                if name in invocation.env:
                                    child_env[name] = invocation.env[name]
                        completed = run_process_with_deadline(
                            cmd,
                            cwd=invocation.cwd,
                            timeout_seconds=resolved_timeout,
                            capture_output=True,
                            env=child_env,
                        )
                except (OSError, RuntimeError) as exc:
                    outcomes.append((contract_path.name, 1))
                    note_failure(1, staged_root=staged_out,
                                 failure_code="INPUT_PREPARATION_FAILED", detail=f"{type(exc).__name__}: {exc}")
                    history.append(status_from_outcome(1, diagnostics=diagnostics))
                    stderr_chunks.append(
                        f"[{tool_id}:{contract_path.name}] input preparation failed: {diagnostics[-1].detail}"
                    )
                    continue
                effective_returncode = 124 if completed.timed_out else completed.returncode
                if effective_returncode == 0:
                    report_path = packaged_runner._find_result_json(staged_out)
                    if report_path is None:
                        effective_returncode = 1
                        diagnostics.append(record_rejected_report(
                            diagnostics_root=results_root / "diagnostics", tool_id=tool_id,
                            input_id=logical_input_id, return_code=1,
                            timeout_seconds=resolved_timeout, staged_root=staged_out,
                            stdout=completed.stdout, stderr=completed.stderr, secrets=secrets,
                        ))
                    elif not packaged_runner._write_enriched_report(
                        report_path,
                        tool_id,
                        vulnerability_mapping,
                        (
                            str(contract_path.resolve())
                            if input_kind in {"bytecode", "runtime"} or tool_id == "vandal"
                            else None
                        ),
                    ):
                        effective_returncode = 1
                        note_failure(1, staged_root=staged_out, stdout=completed.stdout, stderr=completed.stderr,
                                     failure_code="REPORT_ENRICHMENT_FAILED", detail="report enrichment failed")
                    elif not promote_valid_report_tree(
                        staged_out,
                        out_dir,
                        quarantine_root=quarantine_root,
                    ):
                        effective_returncode = (
                            OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                            if out_dir.exists()
                            else 1
                        )
                        note_failure(effective_returncode, staged_root=staged_out,
                                     stdout=completed.stdout, stderr=completed.stderr,
                                     failure_code="REPORT_PROMOTION_FAILED", detail="report promotion failed")
                if effective_returncode != 0 and not diagnostics:
                    note_failure(effective_returncode, staged_root=staged_out,
                                 stdout=completed.stdout, stderr=completed.stderr)
            runtime_seconds += completed.elapsed_seconds
            outcomes.append((contract_path.name, effective_returncode))
            history.append(status_from_outcome(effective_returncode, diagnostics=diagnostics))
            if completed.stdout:
                stdout_chunks.append(
                    f"[{tool_id}:{contract_path.name}]\n{redact(completed.stdout, secrets)[-2000:]}"
                )
            if completed.stderr:
                stderr_chunks.append(
                    f"[{tool_id}:{contract_path.name}]\n{redact(completed.stderr, secrets)[-2000:]}"
                )

        status = aggregate_tool_status_history(history)
        consumption = compilation_bundle.tool_consumption.get(tool_id)
        if consumption is not None:
            consumption = consumption.model_copy(
                update={"consumed": shared_source_succeeded}
            )
        status = status.model_copy(
            update={
                "runtime_minutes": runtime_seconds / 60.0,
                "artifact_consumption": consumption,
            }
        )
        return commands, stdout_chunks, stderr_chunks, outcomes, status

    tool_results = {}
    workers = len(selected_tools) if schedule.execution_jobs == 0 else schedule.execution_jobs
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {executor.submit(run_tool, tool): tool for tool in selected_tools}
        for future in as_completed(futures):
            tool_id = futures[future]
            try:
                tool_results[tool_id] = future.result()
            except Exception as exc:
                diagnostic = record_failure(
                    diagnostics_root=results_root / "diagnostics", tool_id=tool_id,
                    input_id=target_path.name, return_code=1, timeout_seconds=resolved_timeout,
                    failure_code="ADAPTER_EXCEPTION", detail=f"{type(exc).__name__}: {exc}", secrets=secrets,
                )
                tool_results[tool_id] = (
                    [], [], [diagnostic.detail], [(target_path.name, 1)],
                    status_from_outcome(1, diagnostics=[diagnostic]),
                )

    native_commands: List[str] = []
    combined_stdout: List[str] = []
    combined_stderr: List[str] = []
    failures: List[str] = []
    statuses: dict[str, ToolExecutionStatus] = {}
    for tool_id in selected_tools:
        commands, stdout_chunks, stderr_chunks, outcomes, tool_status = tool_results[tool_id]
        native_commands.extend(commands)
        combined_stdout.extend(stdout_chunks)
        combined_stderr.extend(stderr_chunks)
        statuses[tool_id] = tool_status
        for filename, returncode in outcomes:
            if returncode != 0:
                failures.append(f"{tool_id}:{filename}:{returncode}")

    write_diagnostic_index(results_root, statuses)
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

    fusion_manifest = {
        "primary_tool": plan.primary_tool_id,
        "category_owners": plan.category_owners,
        "fusion_summary": plan.fusion_summary,
    }
    (results_root / "fusion_plan.json").write_text(json.dumps(fusion_manifest, indent=2), encoding="utf-8")

    cleanup_failed = any(
        returncode == OUTPUT_CLEANUP_FAILURE_RETURN_CODE
        for _tool_results in tool_results.values()
        for _filename, returncode in _tool_results[3]
    )
    stderr_tail = "\n".join(combined_stderr) or None
    if failures:
        extra = f"native_smartbugs_failures={','.join(failures)}"
        stderr_tail = f"{stderr_tail}\n{extra}" if stderr_tail else extra

    # Harvest findings from results directory
    per_tool_findings = (
        {} if cleanup_failed else _harvest_findings(plan, results_root)
    )
    status = overall_execution_status(
        statuses,
        fatal_cleanup_failure=cleanup_failed,
    )

    return plan.model_copy(
        update={
            "status": status,
            "execution_mode": "native_smartbugs",
            "native_commands": native_commands,
            "stdout_tail": "\n".join(combined_stdout)[-4000:] or None,
            "stderr_tail": stderr_tail[-4000:] if stderr_tail else None,
            "return_code": (
                0
                if not failures
                else OUTPUT_CLEANUP_FAILURE_RETURN_CODE
                if cleanup_failed
                else 1
            ),
            "tool_statuses": statuses,
            "per_tool_findings": per_tool_findings,
            "compilation": compilation_bundle.manifest,
            "artifact_consumption": _resolved_artifact_consumption(
                compilation_bundle.tool_consumption,
                statuses,
            ),
            "compilation_bundle": compilation_bundle,
        }
    )


def execute_plan(
    plan: ExecutionResult,
    *,
    runner_env: Mapping[str, str] | None = None,
) -> ExecutionResult:
    from toolrank import docker_runtime

    docker_runtime.configure(plan.target_path, plan.results_root)
    plan = _resolve_execution_project(plan)
    if not plan.runner_command:
        return plan.model_copy(update={"status": "failed", "stderr_tail": "missing runner command"})

    results_root = Path(plan.results_root) if plan.results_root else None
    if results_root is not None:
        results_root.mkdir(parents=True, exist_ok=True)
        quarantine_root = make_run_quarantine_root(results_root)
        if not clear_selected_run_artifacts(
            results_root,
            plan.selected_tool_ids,
            quarantine_root=quarantine_root,
        ):
            return plan.model_copy(
                update={
                    "status": "failed",
                    "return_code": OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
                    "stderr_tail": "selected execution artifact cleanup failed",
                    "tool_statuses": {
                        tool: ToolExecutionStatus(
                            status="FAIL",
                            return_code=OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
                            detail="output cleanup failed",
                        )
                        for tool in plan.selected_tool_ids
                    },
                    "per_tool_findings": {},
                }
            )
        compilation_manifest_path = results_root / "compilation_manifest.json"
        if compilation_manifest_path.exists() and not remove_or_quarantine_tree(
            compilation_manifest_path,
            quarantine_root,
        ):
            return plan.model_copy(
                update={
                    "status": "failed",
                    "return_code": OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
                    "stderr_tail": "compilation manifest cleanup failed",
                    "tool_statuses": {
                        tool: ToolExecutionStatus(
                            status="FAIL",
                            return_code=OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
                            detail="compilation manifest cleanup failed",
                        )
                        for tool in plan.selected_tool_ids
                    },
                    "per_tool_findings": {},
                }
            )

    plan, compilation_bundle = _prepare_compilation(plan)
    if results_root is not None:
        write_compilation_manifest(compilation_bundle, results_root)
    if compilation_bundle.manifest.status == CompilationStatus.FAILED:
        return _compilation_failed_result(
            plan,
            compilation_bundle,
            execution_mode="manual_runner",
        )

    if compilation_bundle.manifest.status == CompilationStatus.READY:
        with tempfile.TemporaryDirectory(prefix="lakes_compile_bundle_") as tmp:
            bundle_path = Path(tmp) / "bundle.json"
            write_compilation_bundle(compilation_bundle, bundle_path)
            command = [
                *plan.runner_command,
                "--compilation-bundle",
                str(bundle_path),
            ]
            return_code, stdout_tail, stderr_tail = _stream_runner_output(
                command,
                cwd=plan.runner_cwd,
                env=runner_env,
            )
    else:
        return_code, stdout_tail, stderr_tail = _stream_runner_output(
            plan.runner_command,
            cwd=plan.runner_cwd,
            env=runner_env,
        )
    if return_code == 0:
        per_tool_findings = _harvest_findings(plan, results_root) if results_root else {}
        statuses = _load_tool_statuses(plan, results_root, return_code)
        return plan.model_copy(
            update={
                "status": overall_execution_status(statuses),
                "execution_mode": "manual_runner",
                "return_code": return_code,
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
                "tool_statuses": statuses,
                "artifact_consumption": _resolved_artifact_consumption(
                    compilation_bundle.tool_consumption,
                    statuses,
                ),
                "per_tool_findings": per_tool_findings,
            }
        )

    if return_code == OUTPUT_CLEANUP_FAILURE_RETURN_CODE:
        statuses = _load_tool_statuses(plan, results_root, return_code)
        return plan.model_copy(
            update={
                "status": "failed",
                "execution_mode": "manual_runner",
                "return_code": return_code,
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
                "tool_statuses": statuses,
                "artifact_consumption": _resolved_artifact_consumption(
                    compilation_bundle.tool_consumption,
                    statuses,
                ),
                "per_tool_findings": {},
            }
        )

    per_tool_findings = _harvest_findings(plan, results_root) if results_root else {}
    statuses = _load_tool_statuses(plan, results_root, return_code)
    status = overall_execution_status(statuses)
    plan = plan.model_copy(
        update={
            "status": status,
            "execution_mode": "manual_runner",
            "return_code": return_code,
            "stdout_tail": stdout_tail,
            "stderr_tail": stderr_tail,
            "tool_statuses": statuses,
            "artifact_consumption": _resolved_artifact_consumption(
                compilation_bundle.tool_consumption,
                statuses,
            ),
            "per_tool_findings": per_tool_findings,
        }
    )
    if (
        status == "failed"
        and stderr_tail
        and "Report not found" in stderr_tail
    ):
        return _native_smartbugs_execute(plan, runner_env=runner_env)
    return plan


def _harvest_findings(
    plan: ExecutionResult,
    results_root: Optional[Path],
) -> Dict[str, list]:
    """Scan results directory and parse findings for selected tools only."""
    if results_root is None or not results_root.exists():
        return {}

    # Derive selected tool IDs from the execution plan
    selected: Set[str] = set(plan.selected_tool_ids)

    if not selected:
        return {}

    try:
        return load_per_tool_findings(results_root, selected)
    except Exception as exc:
        logger.warning("Failed to harvest findings from %s: %s", results_root, exc)
        return {}


def _load_tool_statuses(
    plan: ExecutionResult,
    results_root: Optional[Path],
    return_code: int,
) -> Dict[str, ToolExecutionStatus]:
    """Load the runner's per-tool status manifest, with a conservative fallback."""
    payload: dict = {}
    if results_root is not None:
        path = results_root / "tool_run_statuses.json"
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                payload = loaded if isinstance(loaded, dict) else {}
            except (OSError, json.JSONDecodeError):
                payload = {}
    fallback = "SUCCESS" if return_code == 0 else "FAIL"
    statuses: Dict[str, ToolExecutionStatus] = {}
    for tool in plan.selected_tool_ids:
        raw = payload.get(tool)
        if isinstance(raw, str):
            raw = {"status": raw}
        if isinstance(raw, dict):
            try:
                statuses[tool] = ToolExecutionStatus.model_validate(raw)
                continue
            except ValueError:
                pass
        statuses[tool] = ToolExecutionStatus(status=fallback, return_code=return_code)
    return statuses
