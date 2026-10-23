from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolrank import execution, runner
from toolrank.compilation import CompilerProcessResult, build_compilation_bundle
from toolrank.process_deadline import DeadlineProcessResult
from toolrank.schemas import ExecutionResult, ExecutionSchedule


def _write_report(path: Path, filename: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "result.json").write_text(
        json.dumps({"findings": [{"name": "tx-origin", "filename": filename}]}),
        encoding="utf-8",
    )


def _bundle(tmp_path: Path, target: Path, tools: list[str] | None = None):
    compiler = tmp_path / "solc-0.8.24"
    compiler.write_bytes(b"fake-solc")
    compiler.chmod(0o755)

    def invoke(_binary, request_bytes, _timeout):
        request = json.loads(request_bytes)
        contracts = {
            name: {
                Path(name).stem: {
                    "abi": [],
                    "evm": {
                        "bytecode": {"object": "6000"},
                        "deployedBytecode": {"object": "6001"},
                    },
                }
            }
            for name in request["sources"]
        }
        return CompilerProcessResult(
            returncode=0,
            stdout=json.dumps({"contracts": contracts}),
            stderr="",
        )

    return build_compilation_bundle(
        target,
        tools if tools is not None else ["smartian", "vandal"],
        installed_compilers={"0.8.24": compiler},
        compiler_invoker=invoke,
    )


def _smartbugs(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "smartbugs"
    path.mkdir()
    monkeypatch.setattr(execution, "DEFAULT_SMARTBUGS_DIR", path)
    return path


@pytest.mark.parametrize("shared_compiler", [False, True])
def test_native_fallback_forwards_project_compiler_constraints(
    tmp_path: Path,
    monkeypatch,
    shared_compiler: bool,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    target = project / "Main.sol"
    target.write_text(
        'pragma solidity ^0.8.0; import "./Lib.sol"; contract Main {}',
        encoding="utf-8",
    )
    (project / "Lib.sol").write_text(
        "pragma solidity <0.8.25; library Lib {}", encoding="utf-8"
    )
    tools = ["smartian", "slither"] if shared_compiler else ["slither"]
    bundle = _bundle(tmp_path, project, tools) if shared_compiler else None
    smartbugs = _smartbugs(tmp_path, monkeypatch)
    (smartbugs / "sb").mkdir()
    for name in ("cli.py", "docker.py"):
        (smartbugs / "sb" / name).write_text("# test sentinel\n", encoding="utf-8")
    # Prepared values must override inherited values as well as fill missing ones.
    monkeypatch.setenv("LAKES_SOLIDITY_CONSTRAINTS", '["0.4.25"]')
    seen: list[dict[str, str]] = []

    def fake_run(command, *, env, **_kwargs):
        seen.append(env)
        _write_report(Path(command[command.index("--results") + 1]), target.name)
        return DeadlineProcessResult(returncode=0, elapsed_seconds=0.1)

    def fake_adapter(_tool_id, contract_path, out_dir, **_kwargs):
        _write_report(Path(out_dir), Path(contract_path).name)
        return 0

    monkeypatch.setattr(execution, "run_process_with_deadline", fake_run)
    monkeypatch.setattr(runner, "_run_adapter_with_deadline", fake_adapter)
    plan = ExecutionResult(
        status="planned",
        target_path=str(project),
        results_root=str(tmp_path / "results"),
        selected_tool_ids=tools,
        primary_tool_id=tools[0],
        execution_schedule=ExecutionSchedule(tool_timeout_seconds=10),
        compilation_bundle=bundle,
    )

    completed = execution._native_smartbugs_execute(plan)

    assert completed.status == "executed", completed.stderr_tail
    assert len(seen) == 1
    assert seen[0]["LAKES_PROJECT_ROOT"] == str(project.resolve())
    assert str(smartbugs) in seen[0]["PYTHONPATH"]
    assert set(json.loads(seen[0]["LAKES_SOLIDITY_CONSTRAINTS"])) == (
        {"0.8.24"} if shared_compiler else {"^0.8.0", "<0.8.25"}
    )
    if shared_compiler:
        assert seen[0]["LAKES_EXECUTION_SOLC_VERSION"] == "0.8.24"


def test_native_fallback_reuses_ready_bundle_without_recompile(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "Main.sol"
    target.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    bundle = _bundle(tmp_path, target)
    _smartbugs(tmp_path, monkeypatch)
    seen: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        execution,
        "build_compilation_bundle",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("native fallback must reuse the ready bundle")
        ),
        raising=False,
    )

    def fake_adapter(tool_id, contract_path, out_dir, **kwargs):
        supplied = kwargs["compilation_bundle"]
        seen.append((tool_id, supplied.manifest.bundle_id))
        _write_report(Path(out_dir), Path(contract_path).name)
        return 0

    monkeypatch.setattr(runner, "_run_adapter_with_deadline", fake_adapter)
    plan = ExecutionResult(
        status="planned",
        target_path=str(target),
        results_root=str(tmp_path / "results"),
        selected_tool_ids=["smartian", "vandal"],
        primary_tool_id="smartian",
        execution_schedule=ExecutionSchedule(tool_timeout_seconds=10),
        compilation=bundle.manifest,
        artifact_consumption=bundle.tool_consumption,
        compilation_bundle=bundle,
    )

    completed = execution._native_smartbugs_execute(plan)

    assert completed.status == "executed"
    assert sorted(seen) == [
        ("smartian", bundle.manifest.bundle_id),
        ("vandal", bundle.manifest.bundle_id),
    ]
    assert completed.compilation.bundle_id == bundle.manifest.bundle_id
    assert completed.tool_statuses["smartian"].artifact_consumption.bundle_id == bundle.manifest.bundle_id
    assert completed.tool_statuses["vandal"].artifact_consumption.mode == "SHARED_ARTIFACT"
    assert completed.artifact_consumption["smartian"].consumed is True
    assert completed.artifact_consumption["vandal"].consumed is True
    assert completed.artifact_consumption == {
        tool: status.artifact_consumption
        for tool, status in completed.tool_statuses.items()
    }


@pytest.mark.parametrize(
    ("return_code", "expected_status"),
    [(1, "FAIL"), (124, "TIMEOUT"), (runner.OUTPUT_CLEANUP_FAILURE_RETURN_CODE, "FAIL")],
)
def test_native_shared_source_failure_is_not_reported_as_consumed(
    tmp_path: Path,
    monkeypatch,
    return_code: int,
    expected_status: str,
) -> None:
    target = tmp_path / "Main.sol"
    target.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    bundle = _bundle(tmp_path, target)
    _smartbugs(tmp_path, monkeypatch)
    monkeypatch.setattr(
        runner,
        "_run_adapter_with_deadline",
        lambda *_args, **_kwargs: return_code,
    )
    plan = ExecutionResult(
        status="planned",
        target_path=str(target),
        results_root=str(tmp_path / "results"),
        selected_tool_ids=["smartian", "vandal"],
        primary_tool_id="smartian",
        execution_schedule=ExecutionSchedule(tool_timeout_seconds=10),
        compilation=bundle.manifest,
        artifact_consumption=bundle.tool_consumption,
        compilation_bundle=bundle,
    )

    completed = execution._native_smartbugs_execute(plan)

    assert completed.status == "failed"
    assert {status.status for status in completed.tool_statuses.values()} == {
        expected_status
    }
    assert all(
        status.artifact_consumption is not None
        and status.artifact_consumption.consumed is False
        for status in completed.tool_statuses.values()
    )
    assert completed.artifact_consumption == {
        tool: status.artifact_consumption
        for tool, status in completed.tool_statuses.items()
    }


def test_native_mixed_shared_source_history_reports_consumption_after_one_success(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    first = project / "First.sol"
    first.write_text("pragma solidity ^0.8.20; contract First {}", encoding="utf-8")
    second = project / "Second.sol"
    second.write_text("pragma solidity ^0.8.20; contract Second {}", encoding="utf-8")
    bundle = _bundle(tmp_path, project)
    _smartbugs(tmp_path, monkeypatch)

    def fake_adapter(_tool_id, contract_path, out_dir, **_kwargs):
        if Path(contract_path).name == "First.sol":
            _write_report(Path(out_dir), Path(contract_path).name)
            return 0
        return 1

    monkeypatch.setattr(runner, "_run_adapter_with_deadline", fake_adapter)
    plan = ExecutionResult(
        status="planned",
        target_path=str(project),
        results_root=str(tmp_path / "results"),
        selected_tool_ids=["smartian", "vandal"],
        primary_tool_id="smartian",
        execution_schedule=ExecutionSchedule(tool_timeout_seconds=10),
        compilation=bundle.manifest,
        artifact_consumption=bundle.tool_consumption,
        compilation_bundle=bundle,
    )

    completed = execution._native_smartbugs_execute(plan)

    assert completed.status == "partial"
    assert {status.status for status in completed.tool_statuses.values()} == {"PARTIAL"}
    assert all(
        completed.per_tool_findings[tool]
        for tool in ("smartian", "vandal")
    )
    assert all(
        status.artifact_consumption is not None
        and status.artifact_consumption.consumed is True
        for status in completed.tool_statuses.values()
    )
    assert completed.artifact_consumption == {
        tool: status.artifact_consumption
        for tool, status in completed.tool_statuses.items()
    }


def test_manual_result_reports_the_runner_consumption_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "Main.sol"
    target.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    bundle = _bundle(tmp_path, target)
    results = tmp_path / "results"

    def fake_stream(*_args, **_kwargs):
        results.mkdir(parents=True, exist_ok=True)
        statuses = {
            tool: {
                "status": "SUCCESS",
                "artifact_consumption": consumption.model_copy(
                    update={"consumed": True}
                ).model_dump(mode="json"),
            }
            for tool, consumption in bundle.tool_consumption.items()
        }
        (results / "tool_run_statuses.json").write_text(
            json.dumps(statuses), encoding="utf-8"
        )
        return 0, None, None

    monkeypatch.setattr(execution, "_stream_runner_output", fake_stream)
    plan = ExecutionResult(
        status="planned",
        target_path=str(target),
        results_root=str(results),
        runner_command=["fixture-runner"],
        selected_tool_ids=["smartian", "vandal"],
        primary_tool_id="smartian",
        execution_schedule=ExecutionSchedule(tool_timeout_seconds=10),
        compilation=bundle.manifest,
        artifact_consumption=bundle.tool_consumption,
        compilation_bundle=bundle,
    )

    completed = execution.execute_plan(plan)

    assert completed.status == "executed"
    assert all(item.consumed for item in completed.artifact_consumption.values())
    assert completed.artifact_consumption == {
        tool: status.artifact_consumption
        for tool, status in completed.tool_statuses.items()
    }


def test_manual_cleanup_failure_preserves_runner_consumption_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "Main.sol"
    target.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    bundle = _bundle(tmp_path, target)
    results = tmp_path / "results"

    def fake_stream(*_args, **_kwargs):
        results.mkdir(parents=True, exist_ok=True)
        statuses = {
            tool: {
                "status": "PARTIAL",
                "return_code": runner.OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
                "artifact_consumption": consumption.model_copy(
                    update={"consumed": True}
                ).model_dump(mode="json"),
            }
            for tool, consumption in bundle.tool_consumption.items()
        }
        (results / "tool_run_statuses.json").write_text(
            json.dumps(statuses), encoding="utf-8"
        )
        return (
            runner.OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
            None,
            "cleanup failed after shared source success",
        )

    monkeypatch.setattr(execution, "_stream_runner_output", fake_stream)
    plan = ExecutionResult(
        status="planned",
        target_path=str(target),
        results_root=str(results),
        runner_command=["fixture-runner"],
        selected_tool_ids=["smartian", "vandal"],
        primary_tool_id="smartian",
        execution_schedule=ExecutionSchedule(tool_timeout_seconds=10),
        compilation=bundle.manifest,
        artifact_consumption=bundle.tool_consumption,
        compilation_bundle=bundle,
    )

    completed = execution.execute_plan(plan)

    assert completed.status == "failed"
    assert completed.return_code == runner.OUTPUT_CLEANUP_FAILURE_RETURN_CODE
    assert completed.per_tool_findings == {}
    assert {status.status for status in completed.tool_statuses.values()} == {
        "PARTIAL"
    }
    assert all(item.consumed for item in completed.artifact_consumption.values())
    assert completed.artifact_consumption == {
        tool: status.artifact_consumption
        for tool, status in completed.tool_statuses.items()
    }


def test_native_direct_invocation_builds_required_bundle_once(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "Main.sol"
    target.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    ready = _bundle(tmp_path, target)
    _smartbugs(tmp_path, monkeypatch)
    calls = 0

    def build(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return ready

    monkeypatch.setattr(execution, "build_compilation_bundle", build, raising=False)

    def fake_adapter(tool_id, contract_path, out_dir, **kwargs):
        assert kwargs["compilation_bundle"].manifest.bundle_id == ready.manifest.bundle_id
        _write_report(Path(out_dir), Path(contract_path).name)
        return 0

    monkeypatch.setattr(runner, "_run_adapter_with_deadline", fake_adapter)
    plan = ExecutionResult(
        status="planned",
        target_path=str(target),
        results_root=str(tmp_path / "results"),
        selected_tool_ids=["smartian", "vandal"],
        primary_tool_id="smartian",
        execution_schedule=ExecutionSchedule(tool_timeout_seconds=10),
    )

    completed = execution._native_smartbugs_execute(plan)

    assert calls == 1
    assert completed.status == "executed"


def test_native_compile_failure_is_predispatch_and_cannot_harvest_stale_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "Main.sol"
    target.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    failed = build_compilation_bundle(
        target,
        ["smartian", "vandal"],
        installed_compilers={},
    )
    _smartbugs(tmp_path, monkeypatch)
    results = tmp_path / "results"
    stale = results / "smartian" / "result.json"
    _write_report(stale.parent, "Old.sol")
    monkeypatch.setattr(execution, "build_compilation_bundle", lambda *_a, **_k: failed, raising=False)
    monkeypatch.setattr(
        runner,
        "_run_adapter_with_deadline",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("compile failure must stop native workers")
        ),
    )
    plan = ExecutionResult(
        status="planned",
        target_path=str(target),
        results_root=str(results),
        selected_tool_ids=["smartian", "vandal"],
        primary_tool_id="smartian",
        execution_schedule=ExecutionSchedule(tool_timeout_seconds=10),
    )

    completed = execution._native_smartbugs_execute(plan)

    assert completed.status == "failed"
    assert completed.return_code == execution.COMPILATION_FAILURE_RETURN_CODE
    assert not stale.exists()
    assert completed.per_tool_findings == {}
    assert {status.status for status in completed.tool_statuses.values()} == {"NOT_RUN"}
    assert all(
        "NO_COMMON_EXECUTION_SOLC" in status.detail
        for status in completed.tool_statuses.values()
    )
    assert all(
        status.artifact_consumption is not None
        and status.artifact_consumption.consumed is False
        for status in completed.tool_statuses.values()
    )
    assert completed.artifact_consumption == {
        tool: status.artifact_consumption
        for tool, status in completed.tool_statuses.items()
    }
