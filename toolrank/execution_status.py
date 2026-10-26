"""Shared aggregation of per-input analyzer execution outcomes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal

from toolrank.report_validity import OUTPUT_CLEANUP_FAILURE_RETURN_CODE
from toolrank.schemas import ToolExecutionStatus


_USABLE_TOOL_STATUSES = frozenset({"SUCCESS", "PARTIAL"})


def aggregate_tool_status_history(
    history: Sequence[ToolExecutionStatus],
) -> ToolExecutionStatus:
    """Aggregate outcomes; ``PARTIAL`` is legal only after a real success."""
    measured = [
        status.runtime_minutes
        for status in history
        if status.runtime_minutes is not None
    ]
    runtime_minutes = sum(measured) if measured else None
    if not history:
        return ToolExecutionStatus()
    diagnostics = [item for status in history for item in status.diagnostics]
    codes = list(dict.fromkeys(status.failure_code for status in history if status.failure_code))
    failure_code = codes[0] if len(codes) == 1 else "MULTIPLE_FAILURES" if codes else ""
    details = [status.detail for status in history if status.status != "SUCCESS" and status.detail]
    detail = "\n".join(dict.fromkeys(details))[:4000]
    evidence = {"diagnostics": diagnostics, "failure_code": failure_code}
    if any(
        status.return_code == OUTPUT_CLEANUP_FAILURE_RETURN_CODE
        for status in history
    ):
        return ToolExecutionStatus(
            status="FAIL",
            runtime_minutes=runtime_minutes,
            return_code=OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
            detail="output cleanup failed",
            **{**evidence, "failure_code": "OUTPUT_CLEANUP_FAILED"},
        )

    values = {status.status for status in history}
    if values == {"SUCCESS"}:
        return ToolExecutionStatus(
            status="SUCCESS", runtime_minutes=runtime_minutes, return_code=0
        )
    if values == {"TIMEOUT"}:
        return ToolExecutionStatus(
            status="TIMEOUT", runtime_minutes=runtime_minutes, return_code=124,
            detail=detail or "all input runs timed out", **evidence,
        )
    if "SUCCESS" in values:
        return ToolExecutionStatus(
            status="PARTIAL",
            runtime_minutes=runtime_minutes,
            detail=detail or "mixed per-input run outcomes",
            **evidence,
        )
    return ToolExecutionStatus(
        status="FAIL",
        runtime_minutes=runtime_minutes,
        return_code=next(
            (
                status.return_code
                for status in reversed(history)
                if status.return_code not in {None, 0}
            ),
            1,
        ),
        detail=detail or (
            "all input runs failed or timed out" if "TIMEOUT" in values
            else "all input runs failed"
        ),
        **evidence,
    )


def overall_execution_status(
    statuses: Mapping[str, ToolExecutionStatus],
    *,
    fatal_cleanup_failure: bool = False,
) -> Literal["executed", "partial", "failed"]:
    """Classify a selected-tool batch without discarding usable current output."""
    if fatal_cleanup_failure or not statuses:
        return "failed"
    values = [status.status for status in statuses.values()]
    if not any(value in _USABLE_TOOL_STATUSES for value in values):
        return "failed"
    if all(value == "SUCCESS" for value in values):
        return "executed"
    return "partial"
