from __future__ import annotations

import importlib.util
import json
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

from toolrank import runner
from toolrank.report_validity import load_valid_report
from toolrank.schemas import ToolExecutionStatus


@pytest.mark.parametrize("jobs", [1, 2])
def test_analyzer_failure_builds_typed_status_without_none_detail(
    jobs: int,
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fail(tool_name, contract_path, **kwargs):
        return runner._map_tool_name(tool_name), ToolExecutionStatus(
            status="FAIL", return_code=2, runtime_minutes=0.25,
        )

    monkeypatch.setattr(runner, "_run_one_tool_for_contract", fail)
    tools = ["slither"] if jobs == 1 else ["slither", "mythril"]
    rc, statuses = runner._run_one_contract(
        tmp_path / "Token.sol",
        target_root=tmp_path,
        results_root=tmp_path / "results",
        selected_tools=tools,
        mapping={},
        smartbugs_dir=None,
        timeout=10,
        gptscan_timeout=10,
        openai_api_key="",
        openai_api_base="",
        jobs=jobs,
        quarantine_root=tmp_path / ".quarantine",
    )

    assert rc == 2
    assert set(statuses) == set(tools)
    assert all(status.status == "FAIL" for status in statuses.values())
    assert all(status.detail == "" for status in statuses.values())


def test_report_semantics_distinguish_valid_empty_from_failure_and_skip(
    tmp_path: Path,
) -> None:
    valid = tmp_path / "valid.json"
    failed = tmp_path / "failed.json"
    skipped = tmp_path / "skipped.json"
    valid.write_text('{"errors": [], "fails": [], "findings": []}', encoding="utf-8")
    failed.write_text(
        '{"errors": ["EXIT_CODE_2"], "fails": ["tool failed"], "findings": []}',
        encoding="utf-8",
    )
    skipped.write_text(
        '{"errors": [], "fails": [], "findings": [], "parser": {"status": "skipped"}}',
        encoding="utf-8",
    )

    assert load_valid_report(valid) is not None
    assert load_valid_report(failed) is None
    assert load_valid_report(skipped) is None


@pytest.mark.parametrize(
    "payload",
    [
        {"findings": [], "errors": {"message": "failed"}},
        {"findings": [], "success": "false"},
        {"findings": [], "status": "FAIL"},
        {"findings": [], "status": "skip"},
        {"analysis": {"findings": [], "error": "compile failed"}},
    ],
)
def test_additional_semantic_failure_shapes_are_rejected(
    payload: dict,
    tmp_path: Path,
) -> None:
    report = tmp_path / "result.json"
    report.write_text(json.dumps(payload), encoding="utf-8")

    assert load_valid_report(report) is None


def test_unsupported_securify2_skip_is_non_success(tmp_path: Path) -> None:
    rc = runner._write_skip_report(tmp_path, "securify2", "unsupported compiler")
    assert rc != 0
    assert load_valid_report(tmp_path / "result.json") is None


def test_failure_and_timeout_without_success_is_not_partial() -> None:
    status = runner._aggregate_tool_status_history(
        [
            ToolExecutionStatus(status="FAIL", return_code=2),
            ToolExecutionStatus(status="TIMEOUT", return_code=124),
        ]
    )
    assert status.status == "FAIL"

    mixed = runner._aggregate_tool_status_history(
        [
            ToolExecutionStatus(status="SUCCESS", return_code=0),
            ToolExecutionStatus(status="TIMEOUT", return_code=124),
        ]
    )
    assert mixed.status == "PARTIAL"


def _load_sailfish_module():
    path = Path(__file__).resolve().parents[1] / "docker" / "runners" / "run_sailfish.py"
    spec = importlib.util.spec_from_file_location("lakes_test_sailfish_runner", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_smartian_module():
    path = Path(__file__).resolve().parents[1] / "docker" / "runners" / "run_smartian.py"
    spec = importlib.util.spec_from_file_location("lakes_test_smartian_runner", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("errors", "expected"),
    [([], 0), (["EXIT_CODE_125"], 2), (["TIMEOUT"], 124)],
)
def test_sailfish_cli_propagates_semantic_outcome(
    errors: list[str],
    expected: int,
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _load_sailfish_module()

    def fake_run(**kwargs):
        out = tmp_path / "sailfish_out"
        out.mkdir()
        (out / "result.json").write_text(
            json.dumps({"errors": errors, "fails": [], "findings": []}),
            encoding="utf-8",
        )
        return str(out)

    monkeypatch.setattr(module, "run_sailfish", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_sailfish.py", str(tmp_path), "Token.sol", "0.8.20"],
    )
    assert module.main() == expected


def test_sailfish_exit_255_is_semantic_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _load_sailfish_module()
    (tmp_path / "Token.sol").write_text("contract Token {}", encoding="utf-8")
    monkeypatch.setattr(module, "_discover_local_solc_bins", lambda: {})
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=255,
            stdout="",
            stderr="analyzer failed",
        ),
    )

    out = module.run_sailfish(
        tmp_path,
        "Token.sol",
        "0.8.20",
        artifacts_root=tmp_path / "artifacts",
    )
    report = json.loads((Path(out) / "result.json").read_text(encoding="utf-8"))

    assert "EXIT_CODE_255" in report["errors"]
    assert report["fails"]


def test_smartian_nonzero_exit_with_findings_remains_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _load_smartian_module()
    contract = tmp_path / "Token.sol"
    contract.write_text("contract Token {}", encoding="utf-8")
    out_dir = tmp_path / "out"
    monkeypatch.setattr(
        module,
        "_compile_source",
        lambda **kwargs: (
            True,
            {"contract_key": "Token"},
            "0.8.20",
            "solc",
            "",
        ),
    )

    def fake_inputs(temp_dir, compiled, bytecode_kind):
        abi = temp_dir / "Token.abi"
        bytecode = temp_dir / "Token.bin"
        abi.write_text("[]", encoding="utf-8")
        bytecode.write_text("6000", encoding="utf-8")
        return abi, bytecode

    def fake_stream(command, cwd=None):
        artifacts = Path(command[command.index("-o") + 1])
        bug_dir = artifacts / "bug"
        bug_dir.mkdir(parents=True)
        (bug_dir / "Reentrancy_case").write_text("finding", encoding="utf-8")
        return 7

    monkeypatch.setattr(module, "_write_compile_inputs", fake_inputs)
    monkeypatch.setattr(module, "_stream_process", fake_stream)

    rc = module._run_one_contract(
        contract,
        tmp_path,
        out_dir,
        tmp_path / "Smartian.dll",
        "dotnet",
        10,
        {},
        "solc",
        "bin",
    )
    report = json.loads((out_dir / "result.json").read_text(encoding="utf-8"))

    assert rc == 7
    assert report["findings"]
    assert "EXIT_CODE_7" in report["errors"]


def test_sailfish_local_compiler_fallback_never_crosses_constraint_patch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _load_sailfish_module()
    candidate = tmp_path / "solc-0.8.30"
    candidate.write_text("binary", encoding="utf-8")
    monkeypatch.setattr(module, "_is_linux_elf", lambda _path: True)

    selected, version, note = module._select_local_solc_bin(
        "0.8.19",
        {"0.8.30": candidate},
    )

    assert selected is None
    assert version is None
    assert note == "local_exact_not_found:0.8.19"
