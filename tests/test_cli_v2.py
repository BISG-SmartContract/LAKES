from __future__ import annotations

import json

import pytest

from typer.testing import CliRunner

import toolrank.cli as cli
from toolrank.cego import build_primary_only_certificate
from toolrank.dace_rag import build_action_evidence_matrix
from toolrank.engine import PipelineResult
from toolrank.schemas import (
    ContractFeatures,
    ExecutionResult,
    FusedReport,
    ToolExecutionStatus,
)
from toolrank.schemas_v2 import CheckerVerdict, PipelineStatus, Stage2Outcome, Stage2Status
from tests.stage2_fixtures import budget, stage2_context


runner = CliRunner()


def plan_result() -> PipelineResult:
    context = stage2_context()
    matrix = build_action_evidence_matrix(context, budget())
    certificate = build_primary_only_certificate(context, matrix, budget())
    return PipelineResult(
        status=PipelineStatus.PLAN_READY,
        features=ContractFeatures(),
        packet=context.stage1,
        context=context,
        stage2_outcome=Stage2Outcome(status=Stage2Status.PLAN_READY),
        matrix=matrix,
        certificate=certificate,
        checker_verdict=CheckerVerdict(status="ACCEPT"),
    )


def test_summary_renders_v2_status_without_certification(monkeypatch) -> None:
    result = plan_result()
    monkeypatch.setattr(cli, "run_recommendation", lambda **_kwargs: result)
    response = runner.invoke(cli.app, ["recommend", "A.sol", "--emit", "summary"])
    assert response.exit_code == 0
    assert "status: PLAN_READY" in response.stdout
    assert "stage1: PRIMARY_SELECTED" in response.stdout
    assert "certification" not in response.stdout


def test_recommend_forwards_explicit_project_root_and_selected_file(tmp_path, monkeypatch) -> None:
    project = tmp_path / "project"
    (project / "contracts").mkdir(parents=True)
    entry = project / "contracts/Main.sol"
    entry.write_text("contract Main {}")
    seen = {}

    def recommend(**kwargs):
        seen.update(kwargs)
        return plan_result()

    monkeypatch.setattr(cli, "run_recommendation", recommend)
    response = runner.invoke(cli.app, [
        "recommend", str(entry), "--project-root", str(project), "--execute",
    ])
    assert response.exit_code == 0, response.stdout
    assert seen["target_path"] == str(entry)
    assert seen["project_root"] == str(project)
    assert seen["execute"] is True


@pytest.mark.parametrize("with_target", [True, False])
def test_recommend_rejects_invalid_project_context_before_loading_tools(
    tmp_path, monkeypatch, with_target,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    entry = tmp_path / "Outside.sol"
    entry.write_text("contract Outside {}")
    monkeypatch.setattr("toolrank.engine.load_toolcards", lambda *_a: pytest.fail("invalid project must fail before loading tools"))
    command = ["recommend", *([str(entry)] if with_target else []), "--project-root", str(project), "--execute"]
    response = runner.invoke(cli.app, command)
    assert response.exit_code == 1
    assert ("inside --project-root" if with_target else "requires a target path") in response.output


def test_json_renders_nullable_v2_boundaries(monkeypatch) -> None:
    result = plan_result()
    monkeypatch.setattr(cli, "run_recommendation", lambda **_kwargs: result)
    response = runner.invoke(cli.app, ["recommend", "A.sol", "--emit", "json"])
    assert response.exit_code == 0
    payload = json.loads(response.stdout)
    assert payload["status"] == "PLAN_READY"
    assert payload["packet"]["schema_version"] == "screc_v2"
    assert payload["stage2_context"]["schema_version"] == "dace_context_v2"
    assert payload["certificate"]["schema_version"] == "dace_orch_v2"


def test_summary_renders_partial_execution_honestly(monkeypatch) -> None:
    planned = plan_result()
    partial = PipelineResult(
        status=PipelineStatus.EXECUTED_PARTIAL,
        features=planned.features,
        packet=planned.packet,
        context=planned.context,
        stage2_outcome=planned.stage2_outcome,
        matrix=planned.matrix,
        certificate=planned.certificate,
        checker_verdict=planned.checker_verdict,
        execution=ExecutionResult(
            status="partial",
            selected_tool_ids=["a"],
            primary_tool_id="a",
            tool_statuses={"a": ToolExecutionStatus(status="PARTIAL")},
        ),
        fused_report=FusedReport(primary_tool_id="a"),
    )
    monkeypatch.setattr(cli, "run_recommendation", lambda **_kwargs: partial)

    response = runner.invoke(cli.app, ["recommend", "A.sol", "--emit", "summary"])

    assert response.exit_code == 0
    assert "status: EXECUTED_PARTIAL" in response.stdout
    assert "execution: partial" in response.stdout
