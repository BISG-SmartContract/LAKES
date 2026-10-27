from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from toolrank.cego import CegoError
from toolrank import docker_runtime
from toolrank.engine import run_recommendation
from toolrank.kb_update import app as kb_app

app = typer.Typer(help="LAKES smart-contract analyzer recommendation CLI", no_args_is_help=True)
app.add_typer(kb_app, name="kb")

_DEFAULT_TOOLCARDS_DIR = str((Path(__file__).resolve().parent.parent / "toolcards"))


@app.callback()
def root() -> None:
    """Command group root."""


@app.command("recommend")
def recommend(
    target_path: Optional[str] = typer.Argument(None, help="Target contract file or directory."),
    project_root: Optional[str] = typer.Option(
        None,
        "--project-root",
        help="Project directory for resolving imports of the selected target.",
    ),
    tool_slots: int = typer.Option(5, "--tool-slots", min=0, help="Budget: max concurrent tools."),
    runtime_cap_minutes: float = typer.Option(30.0, "--runtime-cap-minutes", help="Budget: runtime cap in minutes."),
    alert_cap: str = typer.Option("medium", "--alert-cap", help="Budget: alert cap (low|medium|high)."),
    recall: str = typer.Option("Default", "--recall", help="Preference for recall (Best|Prefer|Default)."),
    precision: str = typer.Option("Default", "--precision", help="Preference for precision (Best|Prefer|Default)."),
    focus_categories: str = typer.Option("", "--focus-categories", help="Comma-separated required DASP categories for complement evaluation."),
    model: str = typer.Option("", "--model", help="LLM model name."),
    emit: str = typer.Option("summary", "--emit", help="Output format: json|summary (default: summary)."),
    toolcards_dir: str = typer.Option(_DEFAULT_TOOLCARDS_DIR, "--toolcards-dir", help="ToolCards folder path (default: packaged toolcards/)."),
    kb_root: Optional[str] = typer.Option(
        None,
        "--kb-root",
        help="Dynamic KB root; resolves one kb_current.json generation for all KB readers.",
    ),
    passage_store: Optional[str] = typer.Option(None, "--passage-store", help="Passage store JSON path."),
    vector_index: Optional[str] = typer.Option(None, "--vector-index", help="Vector index JSON path."),
    no_retrieval: bool = typer.Option(False, "--no-retrieval", help="Disable passage retrieval (ablation)."),
    execute: bool = typer.Option(False, "--execute", help="Run selected tools and write LAKES_out/<contract>/fused_report.json."),
    results_root: str = typer.Option("LAKES_out", "--results-root", help="Root for execution outputs; per-contract folders are created under LAKES_out."),
    runner_script: Optional[str] = typer.Option(None, "--runner-script", help="Analyzer runner script path."),
    runner_cwd: Optional[str] = typer.Option(None, "--runner-cwd", help="Working directory for the analyzer runner."),
    tool_timeout_sec: Optional[int] = typer.Option(
        None,
        "--tool-timeout-sec",
        min=1,
        help="Per-tool timeout in seconds (default: runtime budget converted to seconds).",
    ),
    gptscan_timeout_sec: int = typer.Option(600, "--gptscan-timeout-sec", min=1, help="GPTScan LLM timeout in seconds."),
    execution_jobs: int = typer.Option(
        0,
        "--execution-jobs",
        min=0,
        help="Max tools to run in parallel during --execute; 0 means one job per selected tool.",
    ),
    explain: bool = typer.Option(
        True,
        "--explain/--no-explain",
        "-x",
        help="Print per-stage detail (default: on). Use --no-explain to suppress for scripted/parseable output.",
    ),
    use_checker: bool = typer.Option(
        True,
        "--checker/--no-checker",
        help="Run the deterministic Stage 2 checker (default: on).",
    ),
) -> None:
    emit = emit.lower().strip()
    alert_cap = alert_cap.lower().strip()
    if emit not in {"json", "summary"}:
        raise typer.BadParameter("--emit must be json or summary")
    if alert_cap not in {"low", "medium", "high"}:
        raise typer.BadParameter("--alert-cap must be low|medium|high")
    recall = recall.strip()
    precision = precision.strip()
    if recall not in {"Best", "Prefer", "Default"}:
        raise typer.BadParameter("--recall must be Best|Prefer|Default")
    if precision not in {"Best", "Prefer", "Default"}:
        raise typer.BadParameter("--precision must be Best|Prefer|Default")
    focus_list = [c.strip().lower() for c in focus_categories.split(",") if c.strip()]
    if kb_root and (passage_store or vector_index):
        raise typer.BadParameter(
            "--kb-root cannot be combined with --passage-store or --vector-index"
        )

    try:
        docker_runtime.configure(target_path, project_root, results_root)
        result = run_recommendation(
            target_path=target_path,
            project_root=project_root,
            toolcards_dir=toolcards_dir,
            tool_slots=tool_slots,
            runtime_cap_minutes=runtime_cap_minutes,
            alert_cap=alert_cap,
            recall=recall,
            precision=precision,
            focus_categories=focus_list,
            model=model,
            explain=explain,
            use_checker=use_checker,
            enable_retrieval=not no_retrieval,
            kb_root=kb_root,
            passage_store_path=passage_store,
            vector_index_path=vector_index,
            execute=execute,
            run_results_root=results_root,
            runner_script=runner_script,
            runner_cwd=runner_cwd,
            tool_timeout_sec=tool_timeout_sec,
            gptscan_timeout_sec=gptscan_timeout_sec,
            execution_jobs=execution_jobs,
        )
    except (CegoError, RuntimeError, ValueError) as exc:
        typer.echo(f"recommendation failed: {exc}", err=True)
        raise typer.Exit(1) from exc

    if emit == "summary":
        selected_tools = (
            [item.tool for item in result.certificate.selected_plan]
            if result.certificate is not None
            else []
        )
        lines = [
            f"status: {result.status.value}",
            f"stage1: {result.packet.primary_selection.status.value}",
            f"primary_tool: {result.packet.primary_selection.primary_tool or 'none'}",
            f"stage2: {result.stage2_outcome.status.value if result.stage2_outcome else 'not_entered'}",
            f"selected_action: {result.certificate.selected_action_id if result.certificate else 'none'}",
            f"checker: {result.checker_verdict.status if result.checker_verdict else 'not_run'}",
            f"selected_tools: {', '.join(selected_tools) if selected_tools else 'none'}",
        ]
        execution_result = getattr(result, "execution", None)
        lakes_output_dir = getattr(result, "lakes_output_dir", None)
        if execution_result is not None:
            lines.append(f"execution: {execution_result.status}")
        if lakes_output_dir:
            lines.append(f"LAKES_out: {Path(lakes_output_dir) / 'fused_report.json'}")
        typer.echo("\n".join(lines))
    else:
        payload = {
            "status": result.status.value,
            "packet": result.packet.model_dump(),
            "stage2_context": result.context.model_dump() if result.context else None,
            "stage2_outcome": result.stage2_outcome.model_dump() if result.stage2_outcome else None,
            "matrix": result.matrix.model_dump() if result.matrix else None,
            "certificate": result.certificate.model_dump() if result.certificate else None,
            "checker_verdict": result.checker_verdict.model_dump() if result.checker_verdict else None,
            "execution": result.execution.model_dump() if getattr(result, "execution", None) else None,
            "fused_report": result.fused_report.model_dump() if getattr(result, "fused_report", None) else None,
            "lakes_output_dir": getattr(result, "lakes_output_dir", None),
            "warnings": result.warnings,
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
