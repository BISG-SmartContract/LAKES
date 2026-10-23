from __future__ import annotations

import json

import pytest

from toolrank import engine, runner
from toolrank.fusion import compact_fused_report_payload
from toolrank.report_explanation import deterministic_combination_explanation
from toolrank.report_parser import (
    load_per_tool_findings,
    load_per_tool_findings_from_run_dir,
)
from toolrank.schemas import (
    CompositionPlan,
    ExecutionResult,
    FusedReport,
    ToolExecutionStatus,
)


def _smartcheck_finding(severity: int) -> dict:
    return {
        "name": "SOLIDITY_TX_ORIGIN",
        "category": "access_control",
        "filename": "Vault.sol",
        "line": 17,
        "severity": severity,
        "message": "Authorization uses tx.origin",
    }


@pytest.mark.parametrize("severity", [0, 1, 3])
@pytest.mark.parametrize("source", ["raw", "run_dir", "generic"])
def test_smartcheck_integer_severity_survives_report_ingestion(
    severity: int,
    source: str,
    tmp_path,
) -> None:
    original = _smartcheck_finding(severity)
    raw_findings = [original]
    if source != "raw":
        tool_dir = tmp_path / "smartcheck"
        tool_dir.mkdir()
        (tool_dir / "result.json").write_text(
            json.dumps({"findings": [original]}),
            encoding="utf-8",
        )
        loader = (
            load_per_tool_findings_from_run_dir
            if source == "run_dir"
            else load_per_tool_findings
        )
        raw_findings = loader(tmp_path, {"smartcheck"})["smartcheck"]

    finding = engine._normalize_raw_findings("smartcheck", raw_findings)[0]

    assert finding.severity == severity
    assert type(finding.severity) is int
    assert finding.location == "Vault.sol:17"
    assert finding.raw == original


@pytest.mark.parametrize(("severity", "other_severity"), [(0, "high"), (2, "2")])
def test_runner_fusion_preserves_integer_and_string_severity_conflicts(
    severity: int,
    other_severity: str,
    tmp_path,
) -> None:
    original = _smartcheck_finding(severity)
    slither_finding = {**original, "name": "tx-origin", "severity": other_severity}
    for tool, finding in (("smartcheck", original), ("slither", slither_finding)):
        tool_dir = tmp_path / tool
        tool_dir.mkdir()
        (tool_dir / "result.json").write_text(
            json.dumps({"findings": [finding]}),
            encoding="utf-8",
        )
    composition = CompositionPlan(
        selected_tool_ids=["slither", "smartcheck"],
        primary_tool_id="slither",
        complementary_tool_ids=["smartcheck"],
        category_owners={"access_control": ["slither", "smartcheck"]},
    )

    report = runner._build_fused_report_from_run(
        results_root=tmp_path,
        composition=composition,
        tool_statuses={
            tool: ToolExecutionStatus(status="SUCCESS")
            for tool in composition.selected_tool_ids
        },
    )
    restored = FusedReport.model_validate_json(report.model_dump_json())
    payload = compact_fused_report_payload(restored)

    assert len(payload["findings"]) == 1
    finding = payload["findings"][0]
    assert finding["source_tools"] == ["slither", "smartcheck"]
    assert finding["severity_values"] == {
        "slither": [other_severity],
        "smartcheck": [severity],
    }
    assert type(finding["severity_values"]["smartcheck"][0]) is int
    assert type(finding["severity_values"]["slither"][0]) is str
    assert finding["inconsistent_fields"] == ["severity"]
    assert finding["raw_findings"][1]["raw"] == original
    assert payload["category_results"][0]["tools"]["smartcheck"]["findings"] == [original]


@pytest.mark.parametrize("severity", [0, 3])
def test_execution_pipeline_persists_smartcheck_integer_severity(
    severity: int,
    tmp_path,
    monkeypatch,
) -> None:
    original = _smartcheck_finding(severity)
    composition = CompositionPlan(
        selected_tool_ids=["smartcheck"],
        primary_tool_id="smartcheck",
        category_owners={"access_control": ["smartcheck"]},
    )
    execution = ExecutionResult(
        status="executed",
        selected_tool_ids=["smartcheck"],
        primary_tool_id="smartcheck",
        tool_statuses={"smartcheck": ToolExecutionStatus(status="SUCCESS")},
        per_tool_findings={"smartcheck": [original]},
    )
    monkeypatch.setattr(engine, "build_execution_plan", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(engine, "execute_plan", lambda *_args, **_kwargs: execution)

    completed, fused, output_dir = engine._run_execution_pipeline(
        target_path=tmp_path / "Vault.sol",
        composition=composition,
        combination_explanation=deterministic_combination_explanation(composition),
        results_root=tmp_path / "results",
        runner_script=None,
        runner_cwd=None,
        gptscan_timeout_sec=10,
        openai_api_key=None,
        openai_api_base=None,
    )
    payload = json.loads((output_dir / "fused_report.json").read_text(encoding="utf-8"))

    assert completed.status == "executed"
    assert fused.findings[0].severity_values == {"smartcheck": [severity]}
    finding = payload["findings"][0]
    assert finding["severity_values"] == {"smartcheck": [severity]}
    assert type(finding["raw_findings"][0]["severity"]) is int
    assert finding["raw_findings"][0]["severity"] == severity
    assert finding["raw_findings"][0]["raw"] == original
    assert payload["category_results"][0]["tools"]["smartcheck"]["findings"] == [original]
