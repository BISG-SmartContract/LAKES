from __future__ import annotations

import json
import sys

from toolrank.execution import build_execution_plan
from toolrank.schemas import CompositionPlan


def test_execution_plan_runs_additive_owners_in_parallel(tmp_path) -> None:
    target = tmp_path / "A.sol"
    target.write_text("pragma solidity ^0.8.0; contract A {}", encoding="utf-8")
    composition = CompositionPlan(
        selected_tool_ids=["a", "b"],
        primary_tool_id="a",
        complementary_tool_ids=["b"],
        estimated_plan_runtime_minutes=8.0,
        category_owners={"reentrancy": ["a", "b"]},
    )

    result = build_execution_plan(
        target,
        tmp_path / "out",
        composition,
        runner_script=tmp_path / "runner.py",
        selected_tool_solc_ranges={"a": "0.8.x", "b": ">=0.7.0", "unused": "0.4.x"},
    )

    assert result.selected_tool_ids == ["a", "b"]
    assert result.primary_tool_id == "a"
    assert result.category_owners == {"reentrancy": ["a", "b"]}
    assert result.runner_command[0] == sys.executable
    assert {tool: status.status for tool, status in result.tool_statuses.items()} == {
        "a": "NOT_RUN",
        "b": "NOT_RUN",
    }
    assert result.runner_command[result.runner_command.index("--jobs") + 1] == "0"
    category_arg = result.runner_command[result.runner_command.index("--tool_categories") + 1]
    assert category_arg == "b:REENTRANCY"
    assert result.selected_tool_solc_ranges == {"a": "0.8.x", "b": ">=0.7.0"}
    ranges_arg = result.runner_command[result.runner_command.index("--tool-solc-ranges") + 1]
    assert json.loads(ranges_arg) == {"a": "0.8.x", "b": ">=0.7.0"}
