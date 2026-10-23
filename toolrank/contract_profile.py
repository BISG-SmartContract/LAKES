from __future__ import annotations

import re
from pathlib import Path
from typing import List

from toolrank import _complexity
from toolrank.schemas import ContractFeatures
from toolrank.solc_range import (
    representative_solidity_version,
    version_satisfies_solidity_constraint,
)
from toolrank.source_project import (
    dependency_closure,
    mask_solidity_noncode_for_pragmas,
    resolve_project_root,
    source_entrypoints,
)
from toolrank.target_inputs import classify_target_input

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_VERSION_RE = re.compile(r"0\.[4-8](?:\.\d+|\.x)?")
_CONTRACT_RE = re.compile(r"\b(contract|library|interface)\s+[A-Za-z_][A-Za-z0-9_]*")
_FUNCTION_RE = re.compile(r"\bfunction\s+[A-Za-z_][A-Za-z0-9_]*")


class SolidityConstraintError(RuntimeError):
    """Raised when source-unit Solidity pragmas have no supported intersection."""


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _semver_key(version: str) -> tuple:
    """Parse a version string like '0.8.20' into a tuple of ints for correct comparison."""
    parts = []
    for part in version.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def analyze_target(
    target_path: str | None,
    *,
    project_root: str | Path | None = None,
) -> ContractFeatures:
    explicit_root = (
        resolve_project_root(target_path, project_root)
        if project_root is not None
        else None
    )
    if not target_path:
        return ContractFeatures()

    path = Path(target_path).expanduser().resolve()
    if not path.exists():
        return ContractFeatures(target_path=str(path))

    sol_files: List[Path] = []
    bytecode_files: List[Path] = []
    runtime_files: List[Path] = []
    source_root = explicit_root or (path if path.is_dir() else path.parent)
    source_inputs: list[Path] = []

    if path.is_file():
        input_kind = classify_target_input(path)
        if input_kind == "sol":
            source_inputs = [path]
            sol_files = dependency_closure(path, source_root)
        elif input_kind == "bytecode":
            bytecode_files = [path]
        elif input_kind == "runtime":
            runtime_files = [path]
    else:
        target_inputs = [
            (candidate, classify_target_input(candidate))
            for candidate in sorted(path.rglob("*"))
            if candidate.is_file() and not candidate.is_symlink()
        ]
        sol_files = [candidate for candidate, kind in target_inputs if kind == "sol"]
        if explicit_root is not None and sol_files:
            source_inputs = source_entrypoints(
                sol_files, source_root, follow_imports=True
            )
            sol_files = sorted({
                dependency
                for entrypoint in source_inputs
                for dependency in dependency_closure(entrypoint, source_root)
            })
        bytecode_files = [
            candidate for candidate, kind in target_inputs if kind == "bytecode"
        ]
        runtime_files = [
            candidate for candidate, kind in target_inputs if kind == "runtime"
        ]

    version_literals: List[str] = []
    version_constraints: List[str] = []
    contract_count = 0
    function_count = 0
    sol_sources: dict[str, str] = {}
    if sol_files:
        for sol_file in sol_files:
            text = _read_text(sol_file)
            profile_text = mask_solidity_noncode_for_pragmas(
                _complexity.normalize_profile_source(text)
            )
            try:
                source_name = sol_file.relative_to(source_root).as_posix()
            except ValueError:
                source_name = sol_file.name
            sol_sources[source_name] = text
            constraints = [match.strip() for match in _PRAGMA_RE.findall(profile_text)]
            version_constraints.extend(constraints)
            version_literals.extend(_VERSION_RE.findall(" ".join(constraints)))
            contract_count += len(_CONTRACT_RE.findall(profile_text))
            function_count += len(_FUNCTION_RE.findall(profile_text))

    primary_version = representative_solidity_version(version_constraints)
    if version_constraints and primary_version is None:
        joined = "; ".join(version_constraints)
        raise SolidityConstraintError(
            f"No supported Solidity version satisfies target pragmas: {joined}"
        )
    satisfying_literals = [
        version
        for version in version_literals
        if not version.endswith(".x")
        and all(
            version_satisfies_solidity_constraint(version, constraint)
            for constraint in version_constraints
        )
    ]
    if primary_version is not None:
        satisfying_literals.append(primary_version)

    gower_ast_available = False
    try:
        gower_profile = _complexity.profile_sources(sol_sources) if sol_sources else {}
        gower_ast_available = bool(gower_profile) and all(
            key in gower_profile for key in _complexity.NUM_DIMS
        )
    except _complexity.AstExtractionError:
        gower_profile = _complexity.source_profile_facts(sol_sources)
    if sol_sources and not gower_ast_available:
        gower_profile = _complexity.source_profile_facts(sol_sources)

    input_kind_count = sum(
        bool(files) for files in (sol_files, bytecode_files, runtime_files)
    )
    present_input_kinds = [
        kind
        for kind, files in (
            ("sol", sol_files),
            ("bytecode", bytecode_files),
            ("runtime", runtime_files),
        )
        if files
    ]
    if input_kind_count > 1:
        source_kind = "mixed"
    elif sol_files:
        source_kind = "sol"
    elif bytecode_files:
        source_kind = "bytecode"
    elif runtime_files:
        source_kind = "runtime"
    else:
        source_kind = "unknown"

    file_count = len(sol_files) + len(bytecode_files) + len(runtime_files)
    source_execution_count = (
        len(source_inputs)
        if explicit_root is not None
        else len(source_entrypoints(sol_files, source_root)) if sol_files else 0
    )
    features = ContractFeatures(
        target_path=str(path),
        source_kind=source_kind,
        present_input_kinds=present_input_kinds,
        solidity_versions=sorted(set(satisfying_literals), key=_semver_key),
        solidity_version_constraints=version_constraints,
        primary_solidity_version=primary_version,
        gower_solc_bucket=str(gower_profile.get("solc", "unknown")),
        gower_ast_available=gower_ast_available,
        loc_total=int(gower_profile.get("loc", 0)),
        function_count=function_count,
        file_count=file_count,
        execution_input_count=(
            source_execution_count + len(bytecode_files) + len(runtime_files)
        ),
        contract_count=contract_count,
        is_multifile=len(sol_files) > 1,
        cyclomatic_avg=gower_profile.get("avg_cyc", 0.0),
        cyclomatic_max=gower_profile.get("max_cyc", 0),
        cyclomatic_sum=gower_profile.get("sum_cyc", 0),
        max_nesting=gower_profile.get("max_nest", 0),
        contract_coupling=gower_profile.get("coupling", 0),
    )
    return features
