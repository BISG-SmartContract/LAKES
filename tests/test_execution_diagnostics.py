from __future__ import annotations

import io
import json
from pathlib import Path
import sys

import pytest

from toolrank import execution, runner
from toolrank import execution_diagnostics as diagnostics
from toolrank.execution_status import aggregate_tool_status_history
from toolrank.process_deadline import DeadlineProcessResult
from toolrank.report_parser import load_per_tool_findings, load_per_tool_findings_from_run_dir
from toolrank.schemas import CompositionPlan, ExecutionSchedule, ToolExecutionStatus


def _smartbugs(tmp_path: Path) -> Path:
    directory = tmp_path / "smartbugs"
    directory.mkdir()
    executable = directory / "smartbugs"
    executable.write_text(
        f"#!{sys.executable}\n" + '''import json, pathlib, sys
args = sys.argv
tool = args[args.index('-t') + 1]
filename = pathlib.Path(args[args.index('-f') + 1]).name
output = pathlib.Path(args[args.index('--results') + 1])
output.mkdir(parents=True, exist_ok=True)
failed = tool == 'mythril' and not filename.startswith('A.')
report = {'findings': [{'name': 'reentrancy-eth', 'filename': filename, 'line': 12}]}
if failed:
    report.update({'errors': ['compiler rejected input'], 'fails': ['analyzer exception']})
    print('compiler rejected input', file=sys.stderr)
elif filename.startswith('A.'):
    report = {'findings': [], 'errors': [], 'fails': []}
(output / 'result.json').write_text(json.dumps(report))
(output / 'result.log').write_text('original analyzer stderr')
(output / 'smartbugs.json').write_text(json.dumps({'temporary_report': str(output)}))
''', encoding="utf-8",
    )
    executable.chmod(0o755)
    return directory


def _execute(path: str, target: Path, root: Path, smartbugs: Path, tools: list[str]):
    composition = CompositionPlan(
        selected_tool_ids=tools, primary_tool_id=tools[0], complementary_tool_ids=tools[1:],
        category_owners={"reentrancy": tools},
        execution_schedule=ExecutionSchedule(tool_timeout_seconds=10),
    )
    plan = execution.build_execution_plan(
        target, root, composition, runner_script=Path(runner.__file__), write_lakes_output=False,
    )
    env = {"LAKES_SMARTBUGS_DIR": str(smartbugs)}
    if path == "manual":
        return execution.execute_plan(plan, runner_env=env)
    return execution._native_smartbugs_execute(plan, runner_env=env)


@pytest.mark.parametrize("path", ["manual", "native"])
def test_failed_report_survives_cleanup_and_never_enters_fusion(path: str, tmp_path: Path) -> None:
    target = tmp_path / "Vault.sol"
    target.write_text("pragma solidity ^0.8.20; contract Vault {}")
    root = tmp_path / "raw"
    completed = _execute(path, target, root, _smartbugs(tmp_path), ["mythril", "slither"])

    assert completed.status == "partial"
    assert completed.tool_statuses["slither"].status == "SUCCESS"
    failed = completed.tool_statuses["mythril"]
    assert failed.status == "FAIL"
    assert failed.return_code == 1
    assert failed.failure_code == "ANALYZER_ERROR"
    assert "compiler rejected input" in failed.detail
    assert "analyzer exception" in failed.detail
    assert "all input runs failed" not in failed.detail
    assert failed.diagnostics[0].input_id == "Vault.sol"
    evidence = root / failed.diagnostics[0].directory
    original = json.loads((evidence / "reports/result.json").read_text())
    assert original["errors"] == ["compiler rejected input"]
    assert (evidence / "reports/result.log").read_text() == "original analyzer stderr"
    temporary = json.loads((evidence / "reports/smartbugs.json").read_text())["temporary_report"]
    assert not Path(temporary).exists()
    assert (evidence / "diagnostic.json").is_file()
    index = json.loads((root / "diagnostics/index.json").read_text())
    assert index["tools"]["mythril"][0]["directory"] == failed.diagnostics[0].directory
    assert not (root / "mythril/result.json").exists()
    assert set(completed.per_tool_findings) == {"slither"}
    assert set(load_per_tool_findings(root, {"mythril", "slither"})) == {"slither"}
    assert set(load_per_tool_findings_from_run_dir(root, {"mythril", "slither"})) == {"slither"}
    restored = execution.ExecutionResult.model_validate_json(completed.model_dump_json())
    assert restored.tool_statuses == completed.tool_statuses


@pytest.mark.parametrize("path", ["manual", "native"])
def test_multiple_inputs_keep_failure_identity_and_valid_empty_success(path: str, tmp_path: Path) -> None:
    target = tmp_path / "inputs"
    target.mkdir()
    (target / "A.bin").write_text("6000")
    (target / "B.bin").write_text("6001")
    completed = _execute(path, target, tmp_path / "raw", _smartbugs(tmp_path), ["mythril"])
    status = completed.tool_statuses["mythril"]

    assert completed.status == "partial"
    assert status.status == "PARTIAL"
    assert status.failure_code == "ANALYZER_ERROR"
    assert "compiler rejected input" in status.detail
    assert [item.input_id for item in status.diagnostics] == ["B.bin"]
    assert completed.per_tool_findings == {}
    assert (tmp_path / "raw/mythril/A.bin/result.json").is_file()


@pytest.mark.parametrize(
    ("mode", "code", "expected"),
    [("missing", 1, "REPORT_MISSING"), ("json", 1, "REPORT_INVALID_JSON"),
     ("semantic", 1, "ANALYZER_ERROR"), ("exit", 7, "TOOL_EXIT_ERROR"),
     ("timeout", 124, "TOOL_TIMEOUT")],
)
def test_adapter_classifies_and_preserves_each_failure(mode, code, expected, tmp_path, monkeypatch) -> None:
    target = tmp_path / "Vault.sol"
    target.write_text("contract Vault {}")
    temporary: list[Path] = []

    def process(command, **kwargs):
        request = json.loads(kwargs["input_text"])
        root = Path(request["out_dir"])
        temporary.append(root.parent)
        if mode != "missing":
            root.mkdir()
        if mode == "json":
            (root / "result.json").write_text('{"findings":')
        elif mode == "semantic":
            (root / "result.json").write_text('{"findings": [], "fails": ["solver crashed"]}')
        elif mode == "timeout":
            (root / "result.json").write_text('{"findings": []}')
        (root.parent / "worker.stderr.log").write_text("original tool failure")
        return DeadlineProcessResult(returncode=7 if mode == "exit" else 0, timed_out=mode == "timeout")

    monkeypatch.setattr(runner, "run_process_with_deadline", process)
    failures = []
    raw = tmp_path / "raw"
    result = runner._run_adapter_with_deadline(
        "mythril", target, raw / "mythril", target_root=target,
        smartbugs_dir=None, timeout=9, gptscan_timeout=9,
        openai_api_key="", openai_api_base="", quarantine_root=tmp_path / "quarantine",
        diagnostics_root=raw / "diagnostics", diagnostics=failures,
    )

    assert result == code
    assert len(failures) == 1
    assert failures[0].failure_code == expected
    assert all(not path.exists() for path in temporary)
    evidence = raw / failures[0].directory
    assert (evidence / "worker.stderr.log").read_text() == "original tool failure"
    assert not (raw / "mythril/result.json").exists()


def test_diagnostics_redact_secrets_and_ignore_symlinks(tmp_path: Path, monkeypatch) -> None:
    secret = "sk-PRIVATE-DIAGNOSTIC-KEY"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "result.json").write_text(json.dumps({"errors": [secret], "findings": []}))
    (staged / "result.log").write_text("traceback " + secret)
    outside = tmp_path / "outside.txt"
    outside.write_text("private file must not be copied")
    (staged / "external.log").symlink_to(outside)
    (staged / "directory").symlink_to(tmp_path, target_is_directory=True)
    root = tmp_path / "raw"
    item = diagnostics.record_rejected_report(
        diagnostics_root=root / "diagnostics", tool_id="mythril", input_id="Vault.sol",
        return_code=1, timeout_seconds=9, staged_root=staged,
        stdout="stdout " + secret, stderr="stderr " + secret,
        secrets=diagnostics.secret_values(),
    )
    diagnostics.write_diagnostic_index(root, {"mythril": diagnostics.status_from_outcome(1, diagnostics=[item])})
    saved = "\n".join(path.read_text() for path in root.rglob("*") if path.is_file())
    assert secret not in saved
    assert secret not in item.model_dump_json()
    assert "***" in saved
    assert "private file must not be copied" not in saved
    assert not list(root.rglob("external.log"))


def test_diagnostic_storage_error_does_not_replace_original_failure(tmp_path, monkeypatch) -> None:
    original = Path.mkdir

    def fail(path, *args, **kwargs):
        if "diagnostics" in path.parts:
            raise OSError("disk unavailable")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail)
    item = diagnostics.record_failure(
        diagnostics_root=tmp_path / "diagnostics", tool_id="mythril", input_id="Vault.sol",
        return_code=7, timeout_seconds=10, failure_code="ANALYZER_ERROR", detail="solver crashed",
    )
    status = diagnostics.status_from_outcome(7, diagnostics=[item])
    assert status.status == "FAIL"
    assert status.return_code == 7
    assert status.detail == "solver crashed"
    assert item.directory is None
    assert "disk unavailable" in item.preservation_error


def test_worker_log_capture_is_bounded_and_redacted(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diagnostics, "MAX_FILE_BYTES", 128)
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)
    with diagnostics.capture_worker_logs(tmp_path, ["secret-value"]):
        print("x" * 200, file=sys.stderr)
        print("last error secret-value", file=sys.stderr)
    saved = (tmp_path / "worker.stderr.log").read_bytes()
    assert len(saved) <= 128
    assert b"last error ***" in saved
    assert b"secret-value" not in saved


def test_worker_log_write_failure_does_not_interrupt_tool_output() -> None:
    class FullDisk:
        def tell(self):
            return 0

        def write(self, _data):
            raise OSError("disk full")

    terminal = io.StringIO()
    tee = diagnostics._DiagnosticTee(terminal, FullDisk(), [])
    tee.write("first tool line\n")
    tee.write("last tool line\n")
    assert terminal.getvalue() == "first tool line\nlast tool line\n"


def test_diagnostic_directory_symlink_is_not_followed(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "raw"
    root.mkdir()
    (root / "diagnostics").symlink_to(outside, target_is_directory=True)
    item = diagnostics.record_failure(
        diagnostics_root=root / "diagnostics", tool_id="mythril", input_id="Vault.sol",
        return_code=1, timeout_seconds=10, detail="tool failed",
    )
    assert item.directory is None
    assert item.preservation_error
    diagnostics.write_diagnostic_index(root, {"mythril": diagnostics.status_from_outcome(1, diagnostics=[item])})
    assert list(outside.iterdir()) == []


def test_diagnostic_copy_budget_marks_omitted_and_truncated_files(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diagnostics, "MAX_FILE_BYTES", 64)
    monkeypatch.setattr(diagnostics, "MAX_TOTAL_BYTES", 64)
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "result.json").write_text("x" * 200)
    (staged / "result.log").write_text("y" * 200)
    item = diagnostics.record_rejected_report(
        diagnostics_root=tmp_path / "diagnostics", tool_id="mythril", input_id="Vault.sol",
        return_code=1, timeout_seconds=9, staged_root=staged,
    )
    manifest = json.loads((tmp_path / item.directory / "diagnostic.json").read_text())
    assert item.truncated
    assert manifest["omitted_files"]
    files = [tmp_path / item.directory / name for name in manifest["files"]]
    assert sum(path.stat().st_size for path in files) <= 64


def test_credential_crossing_file_cap_is_redacted_before_truncation(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diagnostics, "MAX_FILE_BYTES", 128)
    secret = "sk-BOUNDARY-CREDENTIAL-MUST-NOT-LEAK-" + "Z" * 64
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "result.log").write_text("x" * 86 + secret + "remaining output")
    item = diagnostics.record_failure(
        diagnostics_root=tmp_path / "diagnostics", tool_id="mythril", input_id="Vault.sol",
        return_code=1, timeout_seconds=9, staged_root=staged, secrets=[secret],
    )
    saved = (tmp_path / item.directory / "reports/result.log").read_text()
    assert "sk-BOUNDARY" not in saved
    assert len(saved.encode()) <= 128


def test_aggregation_preserves_timeout_reason_and_all_failed_inputs() -> None:
    failures = [
        diagnostics.ToolFailureDiagnostic(input_id="A.sol", failure_code="ANALYZER_ERROR", detail="solver crashed", return_code=1),
        diagnostics.ToolFailureDiagnostic(input_id="B.sol", failure_code="TOOL_TIMEOUT", detail="deadline 10s", return_code=124),
    ]
    status = aggregate_tool_status_history([
        diagnostics.status_from_outcome(item.return_code, 0.1, [item]) for item in failures
    ])
    assert status.status == "FAIL"
    assert status.failure_code == "MULTIPLE_FAILURES"
    assert status.diagnostics == failures
    assert "solver crashed" in status.detail and "deadline 10s" in status.detail
    timeout = aggregate_tool_status_history([diagnostics.status_from_outcome(124, diagnostics=[failures[1]])])
    assert timeout.status == "TIMEOUT"
    assert timeout.return_code == 124
    assert timeout.detail == "deadline 10s"
    assert timeout.diagnostics == [failures[1]]


@pytest.mark.parametrize("jobs", [1, 2])
def test_runner_exceptions_keep_typed_diagnostics_in_serial_and_parallel(tmp_path, monkeypatch, jobs) -> None:
    target = tmp_path / "Vault.sol"
    target.write_text("contract Vault {}")

    def crash(*args, **kwargs):
        raise OSError("adapter executable is unavailable")

    monkeypatch.setattr(runner, "_run_one_tool_for_contract", crash)
    code, statuses = runner._run_one_contract(
        target, target_root=target, results_root=tmp_path / "raw",
        selected_tools=["mythril", "slither"] if jobs == 2 else ["mythril"],
        mapping={}, smartbugs_dir=None, timeout=9, gptscan_timeout=9,
        openai_api_key="", openai_api_base="", jobs=jobs, quarantine_root=tmp_path / "quarantine",
    )
    assert code == 1
    for status in statuses.values():
        assert status.failure_code == "ADAPTER_EXCEPTION"
        assert "adapter executable is unavailable" in status.detail
        assert status.diagnostics[0].input_id == "Vault.sol"


def test_native_adapter_exception_is_a_diagnosable_failure(tmp_path, monkeypatch) -> None:
    target = tmp_path / "Vault.sol"
    target.write_text("pragma solidity ^0.8.20; contract Vault {}")

    def crash(*args, **kwargs):
        raise ValueError("external adapter failed")

    monkeypatch.setattr(runner, "_run_adapter_with_deadline", crash)
    completed = _execute("native", target, tmp_path / "raw", _smartbugs(tmp_path), ["gptscan"])
    assert completed.status == "failed"
    assert completed.tool_statuses["gptscan"].failure_code == "ADAPTER_EXCEPTION"
    assert "external adapter failed" in completed.tool_statuses["gptscan"].detail


@pytest.mark.parametrize("path", ["manual", "native"])
def test_fresh_success_removes_previous_selected_diagnostics(path, tmp_path) -> None:
    target = tmp_path / "B.bin"
    target.write_text("6000")
    smartbugs = _smartbugs(tmp_path)
    root = tmp_path / "raw"
    failed = _execute(path, target, root, smartbugs, ["mythril"])
    assert failed.status == "failed"
    assert (root / "diagnostics/index.json").exists()
    script = smartbugs / "smartbugs"
    script.write_text(script.read_text().replace("failed = tool == 'mythril' and not filename.startswith('A.')", "failed = False"))
    successful = _execute(path, target, root, smartbugs, ["mythril"])
    assert successful.status == "executed"
    assert successful.tool_statuses["mythril"].diagnostics == []
    assert not (root / "diagnostics/mythril").exists()
    assert not (root / "diagnostics/index.json").exists()
