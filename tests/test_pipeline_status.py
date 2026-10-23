from __future__ import annotations

from pathlib import Path

import pytest

import toolrank.contract_profile as contract_profile
import toolrank.engine as engine
import toolrank.scene_pool as scene_pool_module
from toolrank.openai_compat import OpenAICompatClient
from toolrank.schemas import (
    CombinationExplanation,
    ContractFeatures,
    ExecutionResult,
    FusedReport,
    ToolExecutionStatus,
)
from toolrank.schemas_v2 import PipelineStatus, ScorePanel, Stage2Status
from tests.stage1_fixtures import scene_pool, tool_entry


def configure_pipeline(monkeypatch, *, runtime: float | None, with_scene: bool = True) -> None:
    features = ContractFeatures(
        target_path="fake.sol",
        source_kind="sol",
        primary_solidity_version="0.8.20",
        loc_total=10,
    )
    monkeypatch.setattr(contract_profile, "analyze_target", lambda _path: features)
    monkeypatch.setattr(
        scene_pool_module,
        "build_scene_pool",
        lambda *_args, **_kwargs: (
            scene_pool(("d1", 1.0, 1.0)) if with_scene else scene_pool()
        ),
    )
    monkeypatch.setattr(engine, "load_toolcards", lambda _path: [])
    monkeypatch.setattr(
        engine,
        "build_tool_table",
        lambda _cards, _features, _budget, _kb, _scene: [
            tool_entry("a", runtime=runtime)
        ],
    )
    monkeypatch.setattr(
        engine,
        "compute_scene_scores",
        lambda *_args, **_kwargs: ScorePanel(
            nominal_scores=[
                {
                    "tool": "a",
                    "S_scene": 1.0,
                    "rank": 1,
                    "support_mass": 1.0,
                }
            ]
        ),
    )


def run(tmp_path: Path, **kwargs):
    return engine.run_recommendation(
        target_path="fake.sol",
        toolcards_dir=str(tmp_path),
        enable_retrieval=False,
        emit_stderr=False,
        **kwargs,
    )


def test_stage1_terminal_has_no_later_objects(monkeypatch, tmp_path) -> None:
    configure_pipeline(monkeypatch, runtime=2.0, with_scene=False)
    result = run(tmp_path)
    assert result.status == PipelineStatus.PRIMARY_NOT_SELECTED
    assert result.context is result.matrix is result.certificate is None


def test_unknown_primary_runtime_has_typed_terminal(monkeypatch, tmp_path) -> None:
    configure_pipeline(monkeypatch, runtime=None)
    result = run(tmp_path)
    assert result.status == PipelineStatus.NO_EXECUTABLE_PLAN
    assert result.stage2_outcome.status == Stage2Status.NO_EXECUTABLE_PLAN
    assert result.packet.primary_selection.primary_tool == "a"
    assert result.matrix is result.certificate is result.execution is None


def test_primary_only_plan_is_ready_without_llm(monkeypatch, tmp_path) -> None:
    configure_pipeline(monkeypatch, runtime=2.0)
    result = run(tmp_path)
    assert result.status == PipelineStatus.PLAN_READY
    assert result.certificate.selected_action_id == "run_primary"
    assert result.checker_verdict.status == "ACCEPT"


def test_primary_only_execution_still_gets_post_checker_llm_explanation(
    monkeypatch,
    tmp_path,
) -> None:
    configure_pipeline(monkeypatch, runtime=2.0)
    client = OpenAICompatClient(
        base_url="https://example.invalid/v1",
        api_key="secret-sentinel",
        timeout_sec=1.0,
    )
    events: list[str] = []
    generated = CombinationExplanation(
        text="The checked primary-only combination follows the fixed plan.",
        source="LLM",
        model="fake-explainer",
        limitations=[],
    )
    monkeypatch.setattr(engine, "load_openai_client", lambda: client)

    def fake_explanation(**kwargs):
        events.append("explain")
        assert kwargs["client"] is client
        assert kwargs["checker_verdict"].status == "ACCEPT"
        assert kwargs["certificate"].selected_plan[0].tool == "a"
        assert kwargs["certificate"].selected_action_id == "run_primary"
        return generated

    def fake_execute(**kwargs):
        events.append("execute")
        assert kwargs["combination_explanation"] == generated
        assert kwargs["composition"].selected_tool_ids == ["a"]
        execution = ExecutionResult(
            status="executed",
            selected_tool_ids=["a"],
            primary_tool_id="a",
            tool_statuses={"a": ToolExecutionStatus(status="SUCCESS")},
        )
        fused = FusedReport(
            primary_tool_id="a",
            combination_explanation=generated,
        )
        return execution, fused, tmp_path / "LAKES_out" / "fake"

    monkeypatch.setattr(engine, "generate_combination_explanation", fake_explanation)
    monkeypatch.setattr(engine, "_run_execution_pipeline", fake_execute)

    result = run(tmp_path, execute=True, model="fake-explainer")

    assert result.status == PipelineStatus.EXECUTED
    assert result.fused_report.combination_explanation == generated
    assert result.certificate.selected_action_id == "run_primary"
    assert events == ["explain", "execute"]


@pytest.mark.parametrize(
    ("execution_status", "expected"),
    [
        ("executed", PipelineStatus.EXECUTED),
        ("partial", PipelineStatus.EXECUTED_PARTIAL),
        ("failed", PipelineStatus.EXECUTION_FAILED),
    ],
)
def test_execution_sets_overall_status(
    monkeypatch, tmp_path, execution_status: str, expected: PipelineStatus
) -> None:
    configure_pipeline(monkeypatch, runtime=2.0)

    def fake_execute(**kwargs):
        composition = kwargs["composition"]
        execution = ExecutionResult(
            status=execution_status,
            selected_tool_ids=["a"],
            primary_tool_id="a",
            tool_statuses={
                "a": ToolExecutionStatus(
                    status=(
                        "SUCCESS"
                        if execution_status == "executed"
                        else "PARTIAL"
                        if execution_status == "partial"
                        else "FAIL"
                    )
                )
            },
        )
        fused = FusedReport(primary_tool_id="a")
        return execution, fused, tmp_path / "LAKES_out" / "fake"

    monkeypatch.setattr(engine, "_run_execution_pipeline", fake_execute)
    result = run(tmp_path, execute=True)
    assert result.status == expected


def test_project_root_reaches_profile_and_execution_plan(tmp_path, monkeypatch) -> None:
    analyze_target = contract_profile.analyze_target
    configure_pipeline(monkeypatch, runtime=2.0)
    monkeypatch.setattr(contract_profile, "analyze_target", analyze_target)
    monkeypatch.setattr(contract_profile._complexity, "profile_sources", lambda _s: {})
    project = tmp_path / "input"
    (project / "contracts").mkdir(parents=True)
    (project / "lib").mkdir()
    entry = project / "contracts/Main.sol"
    entry.write_text('pragma solidity ^0.8.0; import "../lib/Lib.sol"; contract Main {}')
    (project / "lib/Lib.sol").write_text("pragma solidity >=0.8.10 <0.8.20; library Lib {}")
    (project / "Unrelated.sol").write_text("pragma solidity ^0.4.25; contract Unrelated {}")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(engine, "load_openai_client", lambda: object())
    monkeypatch.setattr(engine, "generate_combination_explanation", lambda **_k: CombinationExplanation(
        text="The checked plan uses the selected contract and its import closure.",
        source="LLM", model="fixture", limitations=[],
    ))
    plans = []

    def execute(plan, **_kwargs):
        plans.append(plan)
        assert plan.target_path == str(entry)
        assert plan.project_root == str(project)
        assert plan.runner_command[plan.runner_command.index("--project-root") + 1] == str(project)
        return plan.model_copy(update={
            "status": "executed", "return_code": 0,
            "tool_statuses": {"a": ToolExecutionStatus(status="SUCCESS", return_code=0)},
            "per_tool_findings": {"a": []},
        })

    monkeypatch.setattr(engine, "execute_plan", execute)
    result = engine.run_recommendation(
        target_path="input/contracts/Main.sol", project_root="input",
        toolcards_dir=str(tmp_path), run_results_root=str(tmp_path / "results"),
        execute=True, enable_retrieval=False, emit_stderr=False,
    )
    assert result.status == PipelineStatus.EXECUTED
    assert result.features.file_count == 2
    assert result.features.execution_input_count == 1
    assert result.features.primary_solidity_version == "0.8.10"
    assert len(plans) == 1
    assert Path(result.lakes_output_dir).name == "Main"
