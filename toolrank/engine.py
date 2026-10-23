"""End-to-end paper-aligned Stage 1, Stage 2, and Stage 3 orchestration."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from toolrank import report_parser
from toolrank.categories import normalize_category
from toolrank.cego import CegoError, build_primary_only_certificate, run_cego
from toolrank.checker import check_decision
from toolrank.composition import composition_from_certificate
from toolrank.dace_rag import build_action_evidence_matrix
from toolrank.dataset_kb import load_performance_db
from toolrank.evidence_packet import build_stage2_context, build_tool_table
from toolrank.execution import build_execution_plan, execute_plan
from toolrank.fusion import compact_fused_report_payload, fuse_reports
from toolrank.openai_compat import load_openai_client
from toolrank.plan_runtime import estimated_budget, plan_constraint_reasons, within_budget
from toolrank.report_explanation import generate_combination_explanation
from toolrank.report_validity import (
    OUTPUT_CLEANUP_FAILURE_RETURN_CODE,
    atomic_write_text,
    canonical_contract_output_dir,
    clear_canonical_final_artifacts,
)
from toolrank.roc import roc_weights
from toolrank.retrieval import load_toolcards
from toolrank.scene_scoring import compute_scene_scores, select_primary
from toolrank.schemas import (
    CombinationExplanation,
    CompositionPlan,
    ContractFeatures,
    ExecutionSchedule,
    ExecutionResult,
    Finding,
    FusedReport,
    PerformanceKnowledgeBase,
)
from toolrank.schemas_v2 import (
    ActionByEvidenceMatrix,
    BudgetProfile,
    CheckerVerdict,
    EvidenceRef,
    PipelineStatus,
    Stage1EvidencePacket,
    Stage1Status,
    Stage2EvidenceContext,
    Stage2Outcome,
    Stage2Status,
    Step2DecisionCertificate,
    UserRequirementProfile,
)
from toolrank.toolcard_snapshot import (
    PRIVATE_SNAPSHOT_WARNING,
    StaticToolcardSnapshot,
    resolve_static_toolcard_snapshot,
)


class PipelineResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: PipelineStatus
    features: ContractFeatures
    packet: Stage1EvidencePacket
    context: Stage2EvidenceContext | None = None
    stage2_outcome: Stage2Outcome | None = None
    matrix: ActionByEvidenceMatrix | None = None
    certificate: Step2DecisionCertificate | None = None
    checker_verdict: CheckerVerdict | None = None
    execution: ExecutionResult | None = None
    fused_report: FusedReport | None = None
    lakes_output_dir: str | None = None
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_status_boundary(self) -> "PipelineResult":
        later = (self.context, self.matrix, self.certificate, self.checker_verdict)
        if self.status == PipelineStatus.PRIMARY_NOT_SELECTED:
            if self.packet.primary_selection.status == Stage1Status.PRIMARY_SELECTED:
                raise ValueError("PRIMARY_NOT_SELECTED cannot carry a selected primary")
            if self.stage2_outcome is not None or any(value is not None for value in later):
                raise ValueError("PRIMARY_NOT_SELECTED cannot carry Stage 2 objects")
        elif self.status == PipelineStatus.NO_EXECUTABLE_PLAN:
            if self.packet.primary_selection.status != Stage1Status.PRIMARY_SELECTED:
                raise ValueError("NO_EXECUTABLE_PLAN requires an analytical primary")
            if (
                self.stage2_outcome is None
                or self.stage2_outcome.status != Stage2Status.NO_EXECUTABLE_PLAN
            ):
                raise ValueError("NO_EXECUTABLE_PLAN requires its typed Stage 2 outcome")
            if any(value is not None for value in later):
                raise ValueError("NO_EXECUTABLE_PLAN cannot carry executable Stage 2 objects")
        elif self.status in {
            PipelineStatus.PLAN_READY,
            PipelineStatus.EXECUTED,
            PipelineStatus.EXECUTED_PARTIAL,
            PipelineStatus.EXECUTION_FAILED,
        }:
            if self.packet.primary_selection.status != Stage1Status.PRIMARY_SELECTED:
                raise ValueError("executable pipeline states require a Stage 1 primary")
            if self.stage2_outcome is None or self.stage2_outcome.status != Stage2Status.PLAN_READY:
                raise ValueError("executable pipeline states require Stage2Status.PLAN_READY")
            if any(value is None for value in later):
                raise ValueError("executable pipeline states require all Stage 2 objects")
        if self.status == PipelineStatus.PLAN_READY:
            if self.execution is not None or self.fused_report is not None:
                raise ValueError("PLAN_READY cannot carry Stage 3 results")
        elif self.status == PipelineStatus.EXECUTED:
            if (
                self.execution is None
                or self.execution.status != "executed"
                or self.fused_report is None
            ):
                raise ValueError(
                    "EXECUTED requires a successful execution and a fused report"
                )
        elif self.status == PipelineStatus.EXECUTED_PARTIAL:
            if (
                self.execution is None
                or self.execution.status != "partial"
                or self.fused_report is None
            ):
                raise ValueError(
                    "EXECUTED_PARTIAL requires usable partial execution and a fused report"
                )
        elif self.status == PipelineStatus.EXECUTION_FAILED:
            if (
                self.execution is None
                or self.execution.status != "failed"
                or self.fused_report is None
            ):
                raise ValueError(
                    "EXECUTION_FAILED requires no usable execution and a fused report"
                )
        return self


def _emit(enabled: bool, title: str, details: str) -> None:
    if enabled:
        sys.stderr.write(f"\n[{title}]\n{details}\n")
        sys.stderr.flush()


def _empty_kb() -> PerformanceKnowledgeBase:
    return PerformanceKnowledgeBase(knowledge_base_type="performance", entries=[])


def _normalize_raw_findings(tool_id: str, raw_findings: list[dict[str, Any]]) -> list[Finding]:
    """Normalize tool output while retaining the complete raw record."""
    findings: list[Finding] = []
    for raw in raw_findings:
        is_parser_projection = (
            raw.get(report_parser.PARSER_PROJECTION_MARKER) is True
            and isinstance(raw.get("raw"), dict)
            and {"source_tool", "category", "location", "explanation"}.issubset(raw)
        )
        original = raw["raw"] if is_parser_projection else raw
        if raw.get("ignored") is True or original.get("ignored") is True:
            continue
        category = (
            raw.get("category")
            or raw.get("vulnerability_type")
            or raw.get("type")
            or raw.get("check")
            or raw.get("name")
            or raw.get("title")
            or "unknown"
        )
        category = normalize_category(category)
        if category.upper() == "IGNORE":
            continue
        location = report_parser.normalize_finding_location(raw)
        severity = report_parser.normalize_finding_severity(raw)
        confidence = report_parser.normalize_finding_confidence(raw.get("confidence"))
        findings.append(
            Finding(
                source_tool=tool_id,
                category=category,
                location=location,
                severity=severity,
                confidence=confidence,
                explanation=str(
                    raw.get("explanation")
                    or raw.get("description")
                    or raw.get("message")
                    or raw.get("info")
                    or ""
                ),
                raw=deepcopy(original),
            )
        )
    return findings


def decide_with_ceiling_fallback(
    *,
    context: Stage2EvidenceContext,
    matrix: ActionByEvidenceMatrix,
    budget: BudgetProfile,
    max_cego_retries: int,
    run_cego_fn: Callable[..., Step2DecisionCertificate],
    check_fn: Callable[
        [Step2DecisionCertificate, Stage2EvidenceContext, ActionByEvidenceMatrix],
        CheckerVerdict,
    ],
) -> tuple[Step2DecisionCertificate, CheckerVerdict]:
    """Repair a model plan at most N times, then use checked primary-only."""
    last_verdict: CheckerVerdict | None = None
    for _attempt in range(max_cego_retries + 1):
        certificate = run_cego_fn(context, matrix, last_verdict)
        verdict = check_fn(certificate, context, matrix)
        if verdict.status == "ACCEPT":
            return certificate, verdict
        last_verdict = verdict

    fallback = build_primary_only_certificate(context, matrix, budget)
    fallback_verdict = check_fn(fallback, context, matrix)
    if fallback_verdict.status != "ACCEPT":
        raise RuntimeError("deterministic primary-only fallback failed the Stage 2 checker")
    return fallback, fallback_verdict


def _load_passage_retriever(
    passage_store_path: Path,
    vector_index_path: Path,
    *,
    enabled: bool,
):
    if not enabled or not passage_store_path.exists():
        return None
    from toolrank.passage_store import PassageRetriever, load_passage_store

    store = load_passage_store(passage_store_path)
    if store is None or not store.passages:
        return None
    if vector_index_path.exists():
        from toolrank.vector_store import VectorIndex

        index = VectorIndex.load(vector_index_path)
    else:
        index = None
    return PassageRetriever(store, index=index)


def _stage1_packet(
    *,
    features: ContractFeatures,
    tool_table,
    scene_pool,
    score_panel,
) -> Stage1EvidencePacket:
    selection = select_primary(scene_pool, score_panel, tool_table, tau=0.2)
    provenance = [
        EvidenceRef(
            evidence_id=f"stage1_benchmark_{neighbor.slice_id}",
            source_type="benchmark_metadata",
            paper_id=neighbor.paper_id,
            field_path="scene_pool.neighbors",
            extraction_confidence="high",
        )
        for neighbor in scene_pool.neighbors
    ]
    return Stage1EvidencePacket(
        target_contract={"features": features.model_dump(mode="json")},
        tool_table=tool_table,
        scene_pool=scene_pool,
        score_panel=score_panel,
        primary_selection=selection,
        provenance_index=provenance,
    )


def _terminal_stage1_result(
    features: ContractFeatures,
    packet: Stage1EvidencePacket,
    warnings: list[str],
) -> PipelineResult:
    return PipelineResult(
        status=PipelineStatus.PRIMARY_NOT_SELECTED,
        features=features,
        packet=packet,
        warnings=warnings,
    )


def _primary_runtime_outcome(
    packet: Stage1EvidencePacket,
    budget: BudgetProfile,
) -> Stage2Outcome:
    primary = packet.primary_selection.primary_tool
    estimate = (
        estimated_budget([primary], packet.tool_table, budget.execution_schedule)
        if primary
        else None
    )
    if estimate is None:
        constraints = (
            plan_constraint_reasons(
                [primary],
                packet.tool_table,
                budget.execution_schedule,
            )
            if primary and budget.execution_schedule is not None
            else []
        )
        if any(reason.startswith("TOOL_TIMEOUT_TOO_SHORT:") for reason in constraints):
            reasons = ["PRIMARY_EXCEEDS_EXPLICIT_TOOL_TIMEOUT"]
        elif "INSUFFICIENT_EXECUTION_JOBS" in constraints:
            reasons = ["PRIMARY_EXECUTION_JOBS_UNAVAILABLE"]
        else:
            reasons = ["PRIMARY_RUNTIME_UNKNOWN"]
        return Stage2Outcome(
            status=Stage2Status.NO_EXECUTABLE_PLAN,
            reason_codes=reasons,
        )
    if not within_budget(estimate, budget):
        return Stage2Outcome(
            status=Stage2Status.NO_EXECUTABLE_PLAN,
            reason_codes=["PRIMARY_EXCEEDS_STAGE2_BUDGET"],
            estimated_plan_runtime_minutes=estimate.runtime_cap_minutes,
        )
    return Stage2Outcome(
        status=Stage2Status.PLAN_READY,
        estimated_plan_runtime_minutes=estimate.runtime_cap_minutes,
    )


def _accepted_without_checker(certificate: Step2DecisionCertificate, reason: str) -> CheckerVerdict:
    return CheckerVerdict(
        status="ACCEPT",
        checked_action_id=certificate.selected_action_id,
        reasons=[reason],
    )


def _run_execution_pipeline(
    *,
    target_path: str | Path,
    composition: CompositionPlan,
    results_root: str | Path,
    runner_script: str | Path | None,
    runner_cwd: str | Path | None,
    gptscan_timeout_sec: int,
    openai_api_key: str | None,
    openai_api_base: str | None,
    combination_explanation: CombinationExplanation | None = None,
    selected_tool_solc_ranges: dict[str, str] | None = None,
    project_root: str | Path | None = None,
) -> tuple[ExecutionResult, FusedReport, Path]:
    output_dir = canonical_contract_output_dir(results_root, target_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    if not clear_canonical_final_artifacts(output_dir):
        raise RuntimeError(
            f"cannot invalidate previous LAKES result before execution: {output_dir}"
        )
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    planned = build_execution_plan(
        target_path,
        raw_dir,
        composition,
        runner_script=runner_script,
        runner_cwd=runner_cwd,
        gptscan_timeout_sec=gptscan_timeout_sec,
        write_lakes_output=False,
        selected_tool_solc_ranges=selected_tool_solc_ranges,
        project_root=project_root,
    )
    runner_env: dict[str, str] = {}
    if openai_api_key:
        runner_env["OPENAI_API_KEY"] = openai_api_key
    if openai_api_base:
        runner_env["OPENAI_API_BASE"] = openai_api_base
        runner_env["OPENAI_BASE_URL"] = openai_api_base
    execution = execute_plan(planned, runner_env=runner_env or None)
    raw_by_tool = dict(execution.per_tool_findings)
    if (
        not raw_by_tool
        and execution.return_code != OUTPUT_CLEANUP_FAILURE_RETURN_CODE
    ):
        raw_by_tool = report_parser.load_per_tool_findings_from_run_dir(
            raw_dir, set(composition.selected_tool_ids)
        )
    findings_by_tool = {
        tool: _normalize_raw_findings(tool, raw_by_tool.get(tool, []))
        for tool in composition.selected_tool_ids
    }
    fused = fuse_reports(
        findings_by_tool,
        composition,
        tool_statuses=execution.tool_statuses,
        findings_source="execution",
        combination_explanation=combination_explanation,
    )
    execution = execution.model_copy(update={"fusion_summary": fused.summary})
    output_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        output_dir / "fusion_plan.json",
        composition.model_dump_json(indent=2) + "\n",
    )
    atomic_write_text(
        output_dir / "execution.json",
        execution.model_dump_json(indent=2) + "\n",
    )
    atomic_write_text(
        output_dir / "tool_run_statuses.json",
        json.dumps(
            {
                tool: status.model_dump(mode="json")
                for tool, status in execution.tool_statuses.items()
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    atomic_write_text(
        output_dir / "fused_report.json",
        json.dumps(compact_fused_report_payload(fused), ensure_ascii=False, indent=2)
        + "\n",
    )
    return execution, fused, output_dir


def run_recommendation(
    *,
    target_path: str | None,
    project_root: str | Path | None = None,
    toolcards_dir: str,
    tool_slots: int = 1,
    runtime_cap_minutes: float = 30.0,
    alert_cap: str = "medium",
    recall: str = "Default",
    precision: str = "Default",
    focus_categories: list[str] | None = None,
    model: str = "",
    max_cego_retries: int = 2,
    use_checker: bool = True,
    emit_stderr: bool = True,
    explain: bool = False,
    enable_retrieval: bool = True,
    kb_root: str | None = None,
    passage_store_path: str | None = None,
    vector_index_path: str | None = None,
    execute: bool = False,
    run_results_root: str | None = None,
    runner_script: str | None = None,
    runner_cwd: str | None = None,
    tool_timeout_sec: int | None = None,
    gptscan_timeout_sec: int = 600,
    execution_jobs: int = 0,
    openai_api_key: str | None = None,
    openai_api_base: str | None = None,
) -> PipelineResult:
    """Run the paper flow without allowing Stage 2 evidence to change ``t*``."""
    _ = explain  # concise stage summaries are emitted through ``emit_stderr``.
    from toolrank.contract_profile import analyze_target
    from toolrank.scene_pool import build_scene_pool
    from toolrank.source_project import resolve_project_root

    if project_root is not None:
        project_root = resolve_project_root(target_path, project_root)

    cards = load_toolcards(toolcards_dir)
    toolcards_path = Path(toolcards_dir)
    db_path = toolcards_path / "performance_db.json"
    generation = None
    static_snapshot: StaticToolcardSnapshot | None = None
    if kb_root is not None:
        if passage_store_path is not None or vector_index_path is not None:
            raise ValueError(
                "kb_root cannot be combined with independent passage/vector paths"
            )
        from toolrank.kb_generation import load_current_generation

        generation = load_current_generation(kb_root)
        kb = generation.performance_kb
    else:
        static_snapshot = resolve_static_toolcard_snapshot(toolcards_path)
        db_path = static_snapshot.performance_db_path
        kb = load_performance_db(db_path) if db_path.exists() else _empty_kb()
    features = (
        analyze_target(target_path, project_root=project_root)
        if project_root is not None
        else analyze_target(target_path)
    )
    execution_schedule = ExecutionSchedule(
        contract_count=max(
            1,
            features.execution_input_count or features.file_count,
        ),
        execution_jobs=execution_jobs,
        tool_timeout_seconds=(
            float(tool_timeout_sec)
            if tool_timeout_sec is not None
            else runtime_cap_minutes * 60.0
        ),
        timeout_source="explicit" if tool_timeout_sec is not None else "budget_default",
    )
    budget = BudgetProfile(
        tool_slots=tool_slots,
        runtime_cap_minutes=runtime_cap_minutes,
        alert_cap=alert_cap,
        execution_schedule=execution_schedule,
    )
    requirements = UserRequirementProfile(
        recall=recall,
        precision=precision,
        focus_categories=focus_categories or [],
        runtime_budget_minutes=runtime_cap_minutes,
    )
    w_recall, w_precision = roc_weights(requirements.recall, requirements.precision)
    warnings: list[str] = []
    if static_snapshot is not None and static_snapshot.private_active:
        warnings.append(PRIVATE_SNAPSHOT_WARNING)
        _emit(emit_stderr, "Warning", PRIVATE_SNAPSHOT_WARNING)
    if generation is None and not db_path.exists():
        warnings.append("performance_db.json not found; Stage 1 has no benchmark evidence")

    profiles_path = (
        toolcards_path / "contract_profiles.json"
        if generation is not None
        else static_snapshot.contract_profiles_path
    )
    scene_pool = build_scene_pool(
        features,
        kb,
        profiles_path=profiles_path,
    )
    tool_table = build_tool_table(cards, features, budget, kb, scene_pool)
    feasible_ids = [entry.tool for entry in tool_table if entry.feasible]
    score_panel = compute_scene_scores(
        scene_pool,
        kb,
        feasible_ids,
        w_recall,
        w_precision,
    )
    packet = _stage1_packet(
        features=features,
        tool_table=tool_table,
        scene_pool=scene_pool,
        score_panel=score_panel,
    )
    selection = packet.primary_selection
    _emit(
        emit_stderr,
        "Stage 1",
        f"status={selection.status.value} primary={selection.primary_tool or 'none'} tau={selection.tau}",
    )
    if selection.status != Stage1Status.PRIMARY_SELECTED:
        return _terminal_stage1_result(features, packet, warnings)

    runtime_outcome = _primary_runtime_outcome(packet, budget)
    if runtime_outcome.status == Stage2Status.NO_EXECUTABLE_PLAN:
        _emit(
            emit_stderr,
            "Stage 2",
            f"status={runtime_outcome.status.value} reasons={runtime_outcome.reason_codes}",
        )
        return PipelineResult(
            status=PipelineStatus.NO_EXECUTABLE_PLAN,
            features=features,
            packet=packet,
            stage2_outcome=runtime_outcome,
            warnings=warnings,
        )

    context = build_stage2_context(packet, kb, requirements.focus_categories)
    try:
        if generation is not None:
            if enable_retrieval and generation.passage_store.passages:
                from toolrank.passage_store import PassageRetriever

                retriever = PassageRetriever(
                    generation.passage_store,
                    index=generation.vector_index,
                )
            else:
                retriever = None
        else:
            passage_path = (
                Path(passage_store_path)
                if passage_store_path
                else static_snapshot.passage_store_path
            )
            index_path = (
                Path(vector_index_path)
                if vector_index_path
                else static_snapshot.vector_index_path
            )
            retriever = _load_passage_retriever(
                passage_path,
                index_path,
                enabled=enable_retrieval,
            )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        retriever = None
        warnings.append(f"RAG retrieval disabled: {exc}")
    if enable_retrieval and retriever is None:
        warnings.append("RAG retrieval unavailable; Stage 2 uses structured evidence only")
    matrix = build_action_evidence_matrix(context, budget, retriever=retriever)
    has_complement = any(
        panel.eligible_candidates for panel in matrix.ownership_panel.values()
    )

    def checked(certificate: Step2DecisionCertificate) -> CheckerVerdict:
        return check_decision(certificate, context, matrix)

    certificate: Step2DecisionCertificate
    verdict: CheckerVerdict
    llm_client = None
    if not context.required_categories or not has_complement:
        certificate = build_primary_only_certificate(context, matrix, budget)
        verdict = checked(certificate) if use_checker else _accepted_without_checker(
            certificate, "checker disabled; deterministic primary-only plan"
        )
    else:
        llm_client = load_openai_client()
        if llm_client is None:
            warnings.append("LLM endpoint unavailable; retained checked primary-only plan")
            certificate = build_primary_only_certificate(context, matrix, budget)
            verdict = checked(certificate) if use_checker else _accepted_without_checker(
                certificate, "checker disabled; LLM-unavailable primary-only plan"
            )
        else:
            def run_model(
                current_context: Stage2EvidenceContext,
                current_matrix: ActionByEvidenceMatrix,
                previous: CheckerVerdict | None,
            ) -> Step2DecisionCertificate:
                return run_cego(
                    llm_client,
                    model,
                    current_context,
                    current_matrix,
                    previous,
                    w_recall=w_recall,
                    w_precision=w_precision,
                )

            if use_checker:
                try:
                    certificate, verdict = decide_with_ceiling_fallback(
                        context=context,
                        matrix=matrix,
                        budget=budget,
                        max_cego_retries=max_cego_retries,
                        run_cego_fn=run_model,
                        check_fn=lambda cert, ctx, mtx: check_decision(cert, ctx, mtx),
                    )
                except CegoError as exc:
                    warnings.append(f"CEGO unavailable; retained primary only: {exc}")
                    certificate = build_primary_only_certificate(context, matrix, budget)
                    verdict = checked(certificate)
            else:
                try:
                    certificate = run_model(context, matrix, None)
                except CegoError as exc:
                    warnings.append(f"CEGO unavailable; retained primary only: {exc}")
                    certificate = build_primary_only_certificate(context, matrix, budget)
                verdict = _accepted_without_checker(certificate, "checker disabled")

    stage2_outcome = Stage2Outcome(
        status=Stage2Status.PLAN_READY,
        estimated_plan_runtime_minutes=(
            certificate.budget.estimated_use.runtime_cap_minutes
        ),
    )
    _emit(
        emit_stderr,
        "Stage 2",
        f"status={stage2_outcome.status.value} action={certificate.selected_action_id} "
        f"checker={verdict.status}",
    )

    execution: ExecutionResult | None = None
    fused: FusedReport | None = None
    output_dir: Path | None = None
    if execute:
        if not target_path:
            raise RuntimeError("--execute requires a target path")
        if llm_client is None:
            llm_client = load_openai_client()
        combination_explanation = generate_combination_explanation(
            client=llm_client,
            model=model,
            certificate=certificate,
            checker_verdict=verdict,
            matrix=matrix,
            checker_enabled=use_checker,
        )
        composition = composition_from_certificate(certificate)
        card_by_tool = {card.tool_id: card for card in cards}
        selected_tool_solc_ranges = {
            tool_id: card_by_tool[tool_id].d2_solidity_versions
            for tool_id in composition.selected_tool_ids
            if tool_id in card_by_tool
            and card_by_tool[tool_id].d2_solidity_versions
        }
        execution, fused, output_dir = _run_execution_pipeline(
            target_path=target_path,
            project_root=project_root,
            composition=composition,
            results_root=run_results_root or "LAKES_out",
            runner_script=runner_script,
            runner_cwd=runner_cwd,
            gptscan_timeout_sec=gptscan_timeout_sec,
            openai_api_key=openai_api_key,
            openai_api_base=openai_api_base,
            combination_explanation=combination_explanation,
            selected_tool_solc_ranges=selected_tool_solc_ranges,
        )
        _emit(
            emit_stderr,
            "Stage 3",
            f"execution={execution.status} fused_findings={len(fused.findings)}",
        )

    if execution is None:
        pipeline_status = PipelineStatus.PLAN_READY
    elif execution.status == "executed":
        pipeline_status = PipelineStatus.EXECUTED
    elif execution.status == "partial":
        pipeline_status = PipelineStatus.EXECUTED_PARTIAL
    else:
        pipeline_status = PipelineStatus.EXECUTION_FAILED
    return PipelineResult(
        status=pipeline_status,
        features=features,
        packet=packet,
        context=context,
        stage2_outcome=stage2_outcome,
        matrix=matrix,
        certificate=certificate,
        checker_verdict=verdict,
        execution=execution,
        fused_report=fused,
        lakes_output_dir=str(output_dir) if output_dir else None,
        warnings=warnings,
    )
