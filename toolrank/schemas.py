from __future__ import annotations

from enum import Enum
import hashlib
import math
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from toolrank.compilation import (
    CompilationManifest,
    Stage3CompilationBundle,
    ToolArtifactConsumption,
)
from toolrank.categories import DASP10_CATEGORIES, normalize_category
from toolrank.target_inputs import TargetInputKind


class TriState(str, Enum):
    no = "no"
    partial = "partial"
    yes = "yes"


class DetectionMode(str, Enum):
    static = "static"
    symbolic = "symbolic"
    fuzz = "fuzz"
    ml = "ml"
    llm = "llm"


class D7InputSupport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sol: bool = False
    bytecode: bool = False
    runtime: bool = False


class D1Metric(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    precision: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    recall: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    f1: Optional[float] = Field(default=None, ge=0.0, le=1.0, alias="f1_score")
    accuracy: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    time_sec: Optional[float] = Field(default=None, gt=0.0)
    execution_time_avg: Optional[float] = Field(default=None, gt=0.0)
    execution_time_avg_average_s: Optional[float] = Field(default=None, gt=0.0)
    failure_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    runtime_unit: Optional[str] = None
    runtime_basis: Optional[str] = None
    sample_count: Optional[int] = Field(default=None, ge=0)
    success_count: Optional[int] = Field(default=None, ge=0)
    timeout_count: Optional[int] = Field(default=None, ge=0)
    compilation_failure_count: Optional[int] = Field(default=None, ge=0)
    failure_count: Optional[int] = Field(default=None, ge=0)

    @property
    def resolved_time_sec(self) -> Optional[float]:
        for value in (
            self.time_sec,
            self.execution_time_avg,
            self.execution_time_avg_average_s,
        ):
            if value is not None:
                return value
        return None


class VulnerabilityScoreCount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected: int = Field(ge=0)
    total: int = Field(ge=0)

    @model_validator(mode="after")
    def _detected_not_above_total(self) -> "VulnerabilityScoreCount":
        if self.detected > self.total:
            raise ValueError("detected cannot exceed total")
        return self


class ToolCard(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_id: str
    tool_name: str
    d7_input_support: D7InputSupport
    d8_mode: DetectionMode
    d2_solidity_versions: str
    d3_multifile_support: TriState
    d3_multicontract_support: TriState = TriState.partial
    d1_metrics: Optional[Dict[str, D1Metric]] = None


class FeasibilityResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feasible: bool
    reasons: List[str] = Field(default_factory=list)


class ContractFeatures(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_path: Optional[str] = None
    source_kind: Literal["sol", "bytecode", "runtime", "mixed", "unknown"] = "unknown"
    present_input_kinds: List[TargetInputKind] = Field(default_factory=list)
    solidity_versions: List[str] = Field(default_factory=list)
    solidity_version_constraints: List[str] = Field(default_factory=list)
    primary_solidity_version: Optional[str] = None
    gower_solc_bucket: str = "unknown"
    gower_ast_available: bool = False
    loc_total: int = 0
    function_count: int = 0
    file_count: int = 0
    execution_input_count: int = 0
    contract_count: int = 0
    is_multifile: bool = False
    cyclomatic_avg: float = 0.0
    cyclomatic_max: int = 0
    cyclomatic_sum: int = 0
    max_nesting: int = 0
    contract_coupling: int = 0


class DatasetComplexityStats(BaseModel):
    """Contract complexity summary statistics per dataset.

    Follows the Table-1 convention in SliSE (Wang et al., FSE 2024):
    avg Loc, avg functions, avg sub-contracts.
    """

    model_config = ConfigDict(extra="allow")

    avg_loc: Optional[float] = None
    median_loc: Optional[float] = None
    avg_functions: Optional[float] = None
    avg_subcontracts: Optional[float] = None
    vulnerability_categories: List[str] = Field(default_factory=list)


class DatasetProfile(BaseModel):
    model_config = ConfigDict(extra="allow")

    dataset_name: str
    solc: List[str] = Field(default_factory=list)
    contract_count_total: Optional[int] = None
    realism_level: Optional[str] = None
    domain_tags: List[str] = Field(default_factory=list)
    loc_profile: Dict[str, Any] = Field(default_factory=dict)
    complexity_stats: Optional[DatasetComplexityStats] = None
    what_contracts: Optional[str] = None
    how_collected: Optional[str] = None
    scale: Optional[str] = None
    labeling: Optional[str] = None
    target_vulnerabilities: List[str] = Field(default_factory=list)
    label_granularity: Optional[str] = None
    label_count: Optional[int] = None
    label_count_basis: Optional[str] = None


class KnowledgeSourceLocator(BaseModel):
    """Resolvable source location shared by dynamic metrics and passages."""

    model_config = ConfigDict(extra="forbid")

    block_id: str = Field(min_length=1, max_length=96)
    page_number: Optional[int] = Field(default=None, ge=1)
    block_type: Optional[str] = Field(default=None, max_length=32)
    table_id: Optional[str] = Field(default=None, max_length=96)
    row: Optional[int] = Field(default=None, ge=0)
    column: Optional[int] = Field(default=None, ge=0)
    excerpt: str = Field(min_length=1, max_length=1000)
    excerpt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _excerpt_digest_matches(self) -> "KnowledgeSourceLocator":
        expected = hashlib.sha256(self.excerpt.encode("utf-8")).hexdigest()
        if self.excerpt_sha256 != expected:
            raise ValueError("source locator excerpt digest mismatch")
        return self

    @property
    def locator_key(self) -> str:
        parts = [
            self.block_id,
            str(self.page_number or ""),
            self.block_type or "",
            self.table_id or "",
            str(self.row if self.row is not None else ""),
            str(self.column if self.column is not None else ""),
            self.excerpt_sha256,
        ]
        return "|".join(parts)


class PerformanceObservationRef(BaseModel):
    """Persistent, non-run-derived link to one performance observation."""

    model_config = ConfigDict(extra="forbid")

    observation_id: str = Field(pattern=r"^perf_[0-9a-f]{32}$")
    source_id: str = Field(min_length=1, max_length=160)
    canonical_dataset_id: str = Field(min_length=1, max_length=160)
    dataset_name: str = Field(min_length=1, max_length=180)
    tool: str = Field(min_length=1, max_length=96)
    category: Optional[str] = Field(default=None, max_length=96)
    paper_id: str = Field(pattern=r"^paper_[0-9a-f]{32}$")


class PerformanceObservation(BaseModel):
    """Atomic metric/count/runtime observation with paper-level provenance."""

    model_config = ConfigDict(extra="forbid")

    observation_id: str = Field(pattern=r"^perf_[0-9a-f]{32}$")
    paper_id: str = Field(pattern=r"^paper_[0-9a-f]{32}$")
    publication_date: Optional[str] = Field(default=None, max_length=32)
    source_id: str = Field(min_length=1, max_length=160)
    canonical_dataset_id: str = Field(min_length=1, max_length=160)
    dataset_name: str = Field(min_length=1, max_length=180)
    tool: str = Field(min_length=1, max_length=96)
    metric_kind: Literal[
        "precision",
        "recall",
        "f1",
        "accuracy",
        "runtime",
        "category_rate",
        "category_count",
    ]
    category: Optional[str] = Field(default=None, max_length=96)
    value: Optional[float] = None
    detected: Optional[int] = Field(default=None, ge=0)
    total: Optional[int] = Field(default=None, ge=0)
    normalized_unit: Literal["fraction", "seconds", "count"]
    original_value: Optional[float] = None
    original_unit: str = Field(min_length=1, max_length=48)
    runtime_basis: Optional[
        Literal[
            "per_contract",
            "per_file",
            "per_project",
            "total_benchmark",
            "per_kloc",
            "campaign_cap",
        ]
    ] = None
    source_locator: KnowledgeSourceLocator
    stage1_eligible: bool
    stage1_ineligible_reason: Optional[str] = Field(default=None, max_length=96)

    @field_validator("category")
    @classmethod
    def _canonical_category(cls, value: Optional[str]) -> Optional[str]:
        return normalize_category(value) if value is not None else None

    @model_validator(mode="after")
    def _metric_shape(self) -> "PerformanceObservation":
        if self.value is not None and not math.isfinite(self.value):
            raise ValueError("performance observation value must be finite")
        if self.original_value is not None and not math.isfinite(self.original_value):
            raise ValueError("performance observation original value must be finite")
        if self.metric_kind == "category_count":
            if self.category is None or self.detected is None or self.total is None:
                raise ValueError("category_count requires category, detected, and total")
            if self.detected > self.total:
                raise ValueError("detected cannot exceed total")
            if self.normalized_unit != "count":
                raise ValueError("category_count must use count units")
        else:
            if self.value is None:
                raise ValueError(f"{self.metric_kind} requires value")
            if self.metric_kind == "runtime":
                if self.normalized_unit != "seconds" or not self.runtime_basis:
                    raise ValueError("runtime requires seconds and an explicit basis")
                if self.value <= 0:
                    raise ValueError("runtime must be positive")
            elif self.normalized_unit != "fraction" or not (0.0 <= self.value <= 1.0):
                raise ValueError("rate observations must be fractions in [0, 1]")
        if self.stage1_eligible and self.stage1_ineligible_reason is not None:
            raise ValueError("Stage 1 eligible rows cannot carry an ineligible reason")
        if not self.stage1_eligible and not self.stage1_ineligible_reason:
            raise ValueError("Stage 1 ineligible rows require a reason")
        return self

    def to_ref(self) -> PerformanceObservationRef:
        return PerformanceObservationRef(
            observation_id=self.observation_id,
            source_id=self.source_id,
            canonical_dataset_id=self.canonical_dataset_id,
            dataset_name=self.dataset_name,
            tool=self.tool,
            category=self.category,
            paper_id=self.paper_id,
        )


LiteratureRuntimeBasis = Literal["per_contract", "per_kloc"]


class RuntimeLiteratureObservation(BaseModel):
    """One independently verified paper-level completion-time mean."""

    model_config = ConfigDict(extra="forbid")

    observation_id: str = Field(pattern=r"^lit_[a-z0-9][a-z0-9_]*$")
    tool: str = Field(min_length=1, max_length=96)
    paper_id: str = Field(pattern=r"^paper_[a-z0-9][a-z0-9_]*$")
    title: str = Field(min_length=1, max_length=300)
    authors: List[str] = Field(min_length=1)
    year: int = Field(ge=1900, le=2100)
    venue: str = Field(min_length=1, max_length=240)
    doi: Optional[str] = Field(default=None, max_length=160)
    source_url: str = Field(min_length=1, max_length=500)
    evidence_locator: str = Field(min_length=1, max_length=500)
    tool_identity: str = Field(min_length=1, max_length=500)
    dataset: str = Field(min_length=1, max_length=1000)
    input_profile: Optional[str] = Field(default=None, max_length=500)
    hardware: Optional[str] = Field(default=None, max_length=1000)
    reported_value: float = Field(gt=0.0)
    reported_unit: str = Field(min_length=1, max_length=64)
    reported_basis: str = Field(min_length=1, max_length=64)
    runtime_seconds: float = Field(gt=0.0)
    runtime_unit: Literal["seconds"] = "seconds"
    runtime_basis: LiteratureRuntimeBasis
    normalization_formula: str = Field(min_length=1, max_length=1000)
    attempted_count: Optional[int] = Field(default=None, ge=0)
    success_count: Optional[int] = Field(default=None, ge=0)
    timeout_count: Optional[int] = Field(default=None, ge=0)
    compilation_failure_count: Optional[int] = Field(default=None, ge=0)
    failure_count: Optional[int] = Field(default=None, ge=0)
    denominator_unit: Optional[str] = Field(default=None, max_length=64)
    timeout_policy: Optional[str] = Field(default=None, max_length=1000)
    independent: Literal[True] = True
    admitted_to_summary: Literal[True] = True
    scheduling_eligible: Literal[False] = False
    limitations: List[str] = Field(min_length=1)

    @field_validator(
        "tool",
        "title",
        "venue",
        "source_url",
        "evidence_locator",
        "tool_identity",
        "dataset",
        "reported_unit",
        "reported_basis",
        "normalization_formula",
    )
    @classmethod
    def _non_empty_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("runtime literature text fields cannot be empty")
        return normalized

    @field_validator("authors", "limitations")
    @classmethod
    def _non_empty_unique_values(cls, values: List[str]) -> List[str]:
        normalized = [value.strip() for value in values]
        if any(not value for value in normalized):
            raise ValueError("runtime literature lists cannot contain blank values")
        if len(set(normalized)) != len(normalized):
            raise ValueError("runtime literature lists must be unique")
        return normalized

    @field_validator("source_url")
    @classmethod
    def _http_source_url(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            raise ValueError("runtime literature source_url must be HTTP(S)")
        return value

    @field_validator("reported_value", "runtime_seconds")
    @classmethod
    def _finite_positive_value(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("runtime literature values must be finite")
        return value

    @model_validator(mode="after")
    def _counts_are_consistent(self) -> "RuntimeLiteratureObservation":
        counts = [
            count
            for count in (
                self.success_count,
                self.timeout_count,
                self.compilation_failure_count,
                self.failure_count,
            )
            if count is not None
        ]
        if self.attempted_count is not None:
            if any(count > self.attempted_count for count in counts):
                raise ValueError("literature outcome counts cannot exceed attempts")
            if counts and sum(counts) > self.attempted_count:
                raise ValueError("known literature outcome counts cannot exceed attempts")
        return self


class RuntimeLiteratureSummary(BaseModel):
    """Replayable descriptive mean that is never scheduler input."""

    model_config = ConfigDict(extra="forbid")

    summary_id: str = Field(pattern=r"^summary_[a-z0-9][a-z0-9_]*$")
    tool: str = Field(min_length=1, max_length=96)
    aggregation: Literal["unweighted_arithmetic_mean_of_paper_level_means"]
    runtime_basis: Optional[LiteratureRuntimeBasis] = None
    runtime_unit: Literal["seconds"] = "seconds"
    constituent_observation_ids: List[str] = Field(default_factory=list)
    n: int = Field(ge=0)
    formula: str = Field(min_length=1, max_length=1000)
    precision_decimal_places: Optional[int] = Field(default=None, ge=0, le=12)
    mean_seconds: Optional[float] = Field(default=None, gt=0.0)
    cross_paper_mean: bool
    inclusion_policy: str = Field(min_length=1, max_length=1000)
    exclusions: List[str] = Field(default_factory=list)
    scheduling_eligible: Literal[False] = False
    limitations: List[str] = Field(min_length=1)

    @field_validator("tool", "formula", "inclusion_policy")
    @classmethod
    def _non_empty_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("runtime literature summary text cannot be empty")
        return normalized

    @field_validator("constituent_observation_ids", "exclusions", "limitations")
    @classmethod
    def _non_empty_unique_values(cls, values: List[str]) -> List[str]:
        normalized = [value.strip() for value in values]
        if any(not value for value in normalized):
            raise ValueError("runtime literature summary lists cannot contain blanks")
        if len(set(normalized)) != len(normalized):
            raise ValueError("runtime literature summary lists must be unique")
        return normalized

    @field_validator("mean_seconds")
    @classmethod
    def _finite_mean(cls, value: Optional[float]) -> Optional[float]:
        if value is not None and not math.isfinite(value):
            raise ValueError("runtime literature mean must be finite")
        return value

    @model_validator(mode="after")
    def _truthful_empty_or_identity_shape(self) -> "RuntimeLiteratureSummary":
        if self.n != len(self.constituent_observation_ids):
            raise ValueError("literature summary n must equal constituent membership")
        if self.n == 0:
            if self.runtime_basis is not None:
                raise ValueError("null literature summaries cannot claim a runtime basis")
            if self.mean_seconds is not None:
                raise ValueError("null literature summaries require mean_seconds=null")
            if self.precision_decimal_places is not None:
                raise ValueError("null literature summaries cannot claim numeric precision")
            if self.cross_paper_mean:
                raise ValueError("null literature summaries are not cross-paper means")
            return self
        if self.runtime_basis is None:
            raise ValueError("numeric literature summaries require a runtime basis")
        if self.mean_seconds is None or self.precision_decimal_places is None:
            raise ValueError("numeric literature summaries require a mean and precision")
        if self.cross_paper_mean != (self.n > 1):
            raise ValueError("cross_paper_mean must reflect the independent paper count")
        return self


class ToolPerformanceObservation(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool_name: str
    metrics: D1Metric
    vulnerability_scores: Optional[Dict[str, float]] = None
    vulnerability_score_counts: Optional[Dict[str, VulnerabilityScoreCount]] = None
    observation_ids: List[str] = Field(default_factory=list)
    evidence_source: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_tp_over_gt_scores(cls, data):
        if not isinstance(data, dict):
            return data
        raw_scores = data.get("vulnerability_scores")
        normalized_scores: Dict[str, float] = {}
        raw_counts = data.get("vulnerability_score_counts")
        normalized_counts = {
            normalize_category(category): value
            for category, value in raw_counts.items()
        } if isinstance(raw_counts, dict) else {}
        if isinstance(raw_scores, dict):
            for category, value in raw_scores.items():
                key = normalize_category(category)
                if isinstance(value, str) and "/" in value:
                    detected_text, total_text = value.split("/", 1)
                    detected = int(detected_text.strip())
                    total = int(total_text.strip())
                    normalized_counts[key] = {"detected": detected, "total": total}
                    if total > 0:
                        normalized_scores[key] = detected / total
                else:
                    normalized_scores[key] = float(value)

        return {
            **data,
            "vulnerability_scores": (
                normalized_scores or None
                if isinstance(raw_scores, dict)
                else raw_scores
            ),
            "vulnerability_score_counts": normalized_counts or None,
        }


class PerformanceEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_id: str
    publication_date: Optional[str] = None
    canonical_dataset_id: Optional[str] = None
    stage1_eligible: Optional[bool] = None
    stage1_ineligible_reason: Optional[str] = None
    dataset_profile: DatasetProfile
    tool_performance_data: List[ToolPerformanceObservation] = Field(default_factory=list)
    performance_observations: List[PerformanceObservation] = Field(default_factory=list)


class PerformanceKnowledgeBase(BaseModel):
    model_config = ConfigDict(extra="allow")

    knowledge_base_type: str
    criteria: Dict[str, Any] = Field(default_factory=dict)
    runtime_literature_observations: List[RuntimeLiteratureObservation] = Field(
        default_factory=list
    )
    runtime_literature_summaries: List[RuntimeLiteratureSummary] = Field(
        default_factory=list
    )
    entries: List[PerformanceEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_runtime_literature(self) -> "PerformanceKnowledgeBase":
        observations: Dict[str, RuntimeLiteratureObservation] = {}
        for observation in self.runtime_literature_observations:
            if observation.observation_id in observations:
                raise ValueError(
                    f"duplicate runtime literature observation ID: {observation.observation_id}"
                )
            observations[observation.observation_id] = observation

        summary_ids: set[str] = set()
        summary_keys: set[tuple[str, Optional[LiteratureRuntimeBasis]]] = set()
        referenced_ids: set[str] = set()
        for summary in self.runtime_literature_summaries:
            if summary.summary_id in summary_ids:
                raise ValueError(
                    f"duplicate runtime literature summary ID: {summary.summary_id}"
                )
            summary_ids.add(summary.summary_id)
            key = (summary.tool, summary.runtime_basis)
            if key in summary_keys:
                raise ValueError("duplicate runtime literature summary tool/basis")
            summary_keys.add(key)

            if summary.n == 0:
                if summary.formula != "null (no admissible observations)":
                    raise ValueError(
                        "null literature summary formula must state that no observations exist"
                    )
                if any(
                    observation.tool == summary.tool
                    for observation in self.runtime_literature_observations
                ):
                    raise ValueError(
                        "null literature summary cannot coexist with admitted observations"
                    )
                continue

            try:
                constituents = [
                    observations[observation_id]
                    for observation_id in summary.constituent_observation_ids
                ]
            except KeyError as exc:
                raise ValueError(
                    f"unknown runtime literature constituent: {exc.args[0]}"
                ) from exc
            if any(observation.tool != summary.tool for observation in constituents):
                raise ValueError("literature summary constituents must match the tool")
            if any(
                observation.runtime_basis != summary.runtime_basis
                for observation in constituents
            ):
                raise ValueError(
                    "literature summary constituents must use one homogeneous runtime basis"
                )
            paper_ids = [observation.paper_id for observation in constituents]
            if len(set(paper_ids)) != len(paper_ids):
                raise ValueError(
                    "literature summary constituents require unique independent paper identities"
                )
            exact_members = {
                observation.observation_id
                for observation in self.runtime_literature_observations
                if observation.tool == summary.tool
                and observation.runtime_basis == summary.runtime_basis
            }
            if set(summary.constituent_observation_ids) != exact_members:
                raise ValueError(
                    "literature summary constituent membership must be exact"
                )
            values = [observation.runtime_seconds for observation in constituents]
            terms = " + ".join(format(value, ".15g") for value in values)
            expected_formula = (
                f"({terms}) / {summary.n}"
                if summary.n > 1
                else f"{terms} / 1"
            )
            if summary.formula != expected_formula:
                raise ValueError(
                    "literature summary formula does not match its constituents"
                )
            expected = round(
                math.fsum(values) / summary.n,
                summary.precision_decimal_places,
            )
            if summary.mean_seconds != expected:
                raise ValueError(
                    "literature summary mean does not replay from its constituents"
                )
            referenced_ids.update(summary.constituent_observation_ids)

        if referenced_ids != set(observations):
            raise ValueError(
                "every runtime literature observation must belong to exactly one summary"
            )
        return self


class ExecutionSchedule(BaseModel):
    """Execution constraints shared by planning and both runner paths."""

    model_config = ConfigDict(extra="forbid")

    contract_count: int = Field(default=1, ge=1)
    execution_jobs: int = Field(default=0, ge=0)
    tool_timeout_seconds: float = Field(default=1800.0, gt=0.0)
    timeout_source: Literal["budget_default", "explicit"] = "budget_default"


class CompositionPlan(BaseModel):
    """Executable additive owner plan produced from a checked Stage 2 certificate."""

    model_config = ConfigDict(extra="forbid")

    selected_tool_ids: List[str] = Field(default_factory=list)
    primary_tool_id: str
    complementary_tool_ids: List[str] = Field(default_factory=list)
    estimated_plan_runtime_minutes: float = Field(default=0.0, ge=0.0)
    execution_schedule: ExecutionSchedule = Field(default_factory=ExecutionSchedule)
    category_owners: Dict[str, List[str]] = Field(default_factory=dict)
    rationale: str = ""

    @model_validator(mode="before")
    @classmethod
    def _normalize_category_owner_keys(cls, data):
        if not isinstance(data, dict) or not isinstance(data.get("category_owners"), dict):
            return data
        owners: Dict[str, List[str]] = {}
        for raw_category, raw_owners in data["category_owners"].items():
            category = normalize_category(raw_category)
            if not category:
                continue
            bucket = owners.setdefault(category, [])
            for tool in raw_owners if isinstance(raw_owners, list) else []:
                if tool not in bucket:
                    bucket.append(tool)
        return {**data, "category_owners": owners}

    @model_validator(mode="after")
    def _validate_additive_owners(self) -> "CompositionPlan":
        if not self.selected_tool_ids or self.selected_tool_ids[0] != self.primary_tool_id:
            raise ValueError("selected_tool_ids must begin with primary_tool_id")
        if len(set(self.selected_tool_ids)) != len(self.selected_tool_ids):
            raise ValueError("selected_tool_ids cannot contain duplicates")
        expected_complements = [
            tool for tool in self.selected_tool_ids if tool != self.primary_tool_id
        ]
        if self.complementary_tool_ids != expected_complements:
            raise ValueError("complementary_tool_ids must match selected_tool_ids")
        for category, owners in self.category_owners.items():
            if not category or not owners or owners[0] != self.primary_tool_id:
                raise ValueError("every category owner set must begin with primary_tool_id")
            if len(owners) > 2 or len(set(owners)) != len(owners):
                raise ValueError("category owner sets contain one primary and at most one complement")
            if any(tool not in self.selected_tool_ids for tool in owners):
                raise ValueError("category owners must be selected tools")
        return self


class ToolExecutionStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["NOT_RUN", "SUCCESS", "FAIL", "PARTIAL", "TIMEOUT"] = "NOT_RUN"
    runtime_minutes: Optional[float] = Field(default=None, ge=0.0)
    return_code: Optional[int] = None
    detail: str = ""
    artifact_consumption: ToolArtifactConsumption | None = None


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["not_requested", "planned", "executed", "partial", "failed"] = (
        "not_requested"
    )
    execution_mode: str = "none"
    target_path: Optional[str] = None
    results_root: Optional[str] = None
    runner_script: Optional[str] = None
    runner_cwd: Optional[str] = None
    runner_command: List[str] = Field(default_factory=list)
    native_commands: List[str] = Field(default_factory=list)
    selected_tool_ids: List[str] = Field(default_factory=list)
    primary_tool_id: Optional[str] = None
    category_owners: Dict[str, List[str]] = Field(default_factory=dict)
    estimated_plan_runtime_minutes: float = Field(default=0.0, ge=0.0)
    execution_schedule: ExecutionSchedule = Field(default_factory=ExecutionSchedule)
    selected_tool_solc_ranges: Dict[str, str] = Field(default_factory=dict)
    compilation: CompilationManifest | None = None
    artifact_consumption: Dict[str, ToolArtifactConsumption] = Field(default_factory=dict)
    compilation_bundle: Stage3CompilationBundle | None = Field(
        default=None,
        exclude=True,
        repr=False,
    )
    tool_statuses: Dict[str, ToolExecutionStatus] = Field(default_factory=dict)
    return_code: Optional[int] = None
    stdout_tail: Optional[str] = None
    stderr_tail: Optional[str] = None
    fusion_summary: str = ""
    per_tool_findings: Dict[str, List[Dict[str, Any]]] = Field(
        default_factory=dict,
        description="Per-tool raw findings: {tool_id: [finding_dicts]}. "
        "Populated by the execution runner or injected externally.",
    )


class Finding(BaseModel):
    """Normalized finding representation per paper Eq. 7: r = (t, ν, λ, γ, η).

    t = source_tool, ν = category, λ = location, γ = severity, η = explanation.
    Severity retains the tool's string label or integer code.
    The ``raw`` dict preserves all original fields from the tool's output report.
    """
    model_config = ConfigDict(extra="forbid")

    source_tool: str
    category: str
    location: str = ""
    severity: str | StrictInt | None = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    explanation: str = ""
    raw: Dict[str, Any] = Field(default_factory=dict, description="Original tool report fields, preserved verbatim.")

    @model_validator(mode="before")
    @classmethod
    def _normalize_category(cls, data):
        if isinstance(data, dict) and "category" in data:
            return {**data, "category": normalize_category(data["category"])}
        return data


class FusedFinding(BaseModel):
    """Findings sharing a non-empty ``(category, location)`` with full provenance."""

    model_config = ConfigDict(extra="forbid")

    category: str
    location: str = ""
    source_tools: List[str] = Field(default_factory=list)
    severity_values: Dict[str, List[str | StrictInt]] = Field(default_factory=dict)
    confidence_values: Dict[str, List[float]] = Field(default_factory=dict)
    explanation_variants: Dict[str, List[str]] = Field(default_factory=dict)
    inconsistent_fields: List[Literal["severity", "confidence", "explanation"]] = Field(
        default_factory=list
    )
    raw_findings: List[Finding] = Field(default_factory=list)


class CombinationExplanation(BaseModel):
    """Provenance-labelled prose about an already-fixed checked composition."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1)
    source: Literal["LLM", "DETERMINISTIC_FALLBACK"]
    model: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)

    @field_validator("text")
    @classmethod
    def _non_empty_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("combination explanation text cannot be blank")
        if "\n" in stripped or "\r" in stripped:
            raise ValueError("combination explanation text must be exactly one paragraph")
        return stripped

    @field_validator("model")
    @classmethod
    def _normalize_model(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return value.strip()

    @field_validator("limitations")
    @classmethod
    def _non_empty_limitations(cls, values: List[str]) -> List[str]:
        normalized = [value.strip() for value in values if value.strip()]
        if len(normalized) != len(values):
            raise ValueError("combination explanation limitations cannot be blank")
        return normalized

    @model_validator(mode="after")
    def _provenance_matches_source(self) -> "CombinationExplanation":
        if self.source == "LLM":
            if not self.model:
                raise ValueError("LLM explanations require a model")
        else:
            if self.model is not None:
                raise ValueError("deterministic explanations cannot name an LLM model")
            if not self.limitations:
                raise ValueError("deterministic explanations require a limitation or reason")
        return self


class CategoryToolResult(BaseModel):
    """One checked category owner's current-run status and verbatim findings."""

    model_config = ConfigDict(extra="forbid")

    status: ToolExecutionStatus
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class CategoryResult(BaseModel):
    """User-facing category view derived from checked owners and accepted findings."""

    model_config = ConfigDict(extra="forbid")

    category: str
    owner_tools: List[str]
    tools: Dict[str, CategoryToolResult]

    @field_validator("category")
    @classmethod
    def _canonical_category(cls, value: str) -> str:
        category = normalize_category(value)
        if category not in DASP10_CATEGORIES:
            raise ValueError("category results require a canonical DASP identifier")
        return category

    @model_validator(mode="after")
    def _tools_match_checked_owner_order(self) -> "CategoryResult":
        if not self.owner_tools or len(set(self.owner_tools)) != len(self.owner_tools):
            raise ValueError("category results require unique checked owners")
        if list(self.tools) != self.owner_tools:
            raise ValueError("category result tools must match checked owner order")
        return self


def _default_combination_explanation() -> CombinationExplanation:
    return CombinationExplanation(
        text="No checked plan explanation was supplied for this report.",
        source="DETERMINISTIC_FALLBACK",
        model=None,
        limitations=["CHECKED_PLANNING_CONTEXT_UNAVAILABLE"],
    )


class FusedReport(BaseModel):
    """Additive finding fusion with provenance, conflicts, and run availability."""
    model_config = ConfigDict(extra="forbid")

    primary_tool_id: str
    category_owners: Dict[str, List[str]] = Field(default_factory=dict)
    tool_statuses: Dict[str, ToolExecutionStatus] = Field(default_factory=dict)
    combination_explanation: CombinationExplanation = Field(
        default_factory=_default_combination_explanation
    )
    category_results: List[CategoryResult] = Field(default_factory=list)
    findings: List[FusedFinding] = Field(default_factory=list)
    deduplicated_count: int = 0
    unavailable_categories: List[str] = Field(default_factory=list)
    partial_categories: List[str] = Field(default_factory=list)
    findings_source: str = Field(
        default="synthesized",
        description="'execution' if fused from real runner findings, "
        "'synthesized' if built from toolcard fallback.",
    )
    summary: str = ""

    @model_validator(mode="after")
    def _category_view_matches_top_level_status(self) -> "FusedReport":
        categories = [result.category for result in self.category_results]
        if len(set(categories)) != len(categories):
            raise ValueError("category results cannot contain duplicate categories")

        checked_categories = [normalize_category(category) for category in self.category_owners]
        if categories[: len(checked_categories)] != checked_categories:
            raise ValueError(
                "category results must begin with every checked owner category in order"
            )

        checked_owners = {
            normalize_category(category): owners
            for category, owners in self.category_owners.items()
        }
        for result in self.category_results:
            expected_owners = checked_owners.get(
                result.category,
                [self.primary_tool_id],
            )
            if result.owner_tools != expected_owners:
                raise ValueError(
                    "category result owners must match the checked owner order"
                )
            for tool, per_category in result.tools.items():
                top_level = self.tool_statuses.get(tool)
                if top_level is None or per_category.status != top_level:
                    raise ValueError(
                        "per-category tool status must match the top-level tool status"
                    )

        expected_unavailable: List[str] = []
        expected_partial: List[str] = []
        for category in checked_categories:
            result = next(
                item for item in self.category_results if item.category == category
            )
            statuses = [result.tools[tool].status for tool in result.owner_tools]
            usable = [
                status for status in statuses if status.status in {"SUCCESS", "PARTIAL"}
            ]
            if not usable:
                expected_unavailable.append(category)
            elif len(usable) < len(statuses) or any(
                status.status == "PARTIAL" for status in usable
            ):
                expected_partial.append(category)
        if self.unavailable_categories != expected_unavailable:
            raise ValueError(
                "unavailable categories contradict per-category tool statuses"
            )
        if self.partial_categories != expected_partial:
            raise ValueError("partial categories contradict per-category tool statuses")
        return self
