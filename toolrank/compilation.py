"""One run-scoped Solidity compilation shared by artifact-aware adapters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from toolrank.adapter_capabilities import (
    SharedArtifactComponent,
    adapter_supports_input,
    shared_artifact_components,
)
from toolrank.solc_range import (
    parse_solc_range,
    version_in_range,
    version_satisfies_solidity_constraint,
)
from toolrank.source_project import (
    dependency_closure,
    mask_solidity_noncode_for_pragmas,
    resolve_project_root,
    source_entrypoints,
)


COMPILATION_SCHEMA_VERSION = "stage3_compile_v1"
DEFAULT_COMPILATION_TIMEOUT_SECONDS = 120.0
COMPONENT_ORDER: tuple[SharedArtifactComponent, ...] = (
    "abi",
    "creation_bytecode",
    "runtime_bytecode",
)
_OUTPUT_COMPONENTS: Mapping[SharedArtifactComponent, str] = {
    "abi": "abi",
    "creation_bytecode": "evm.bytecode.object",
    "runtime_bytecode": "evm.deployedBytecode.object",
}
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_VERSION_RE = re.compile(r"(?<![0-9.])(0\.[4-8]\.[0-9]+)(?![0-9.])")


class CompilationStatus(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    READY = "READY"
    FAILED = "FAILED"


class ArtifactConsumptionMode(str, Enum):
    SHARED_ARTIFACT = "SHARED_ARTIFACT"
    SOURCE_ONLY = "SOURCE_ONLY"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class CompilationFailure(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    detail: str = ""


class CompilationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    optimizer_enabled: bool = False
    optimizer_runs: int | None = Field(default=None, ge=0)
    via_ir: bool = False
    evm_version: str | None = None
    remappings: list[str] = Field(default_factory=list)


class CompilationSourceUnit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    relative_path: str
    sha256: str
    size_bytes: int = Field(ge=0)


class CompilationContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fully_qualified_name: str
    source_unit: str
    contract_name: str
    abi: list[dict[str, Any]] | None = None
    creation_bytecode: str | None = None
    runtime_bytecode: str | None = None


class CompilationConsumerRoute(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    logical_input_id: str
    fully_qualified_contract: str
    components: list[SharedArtifactComponent]
    bundle_id: str


class ToolArtifactConsumption(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    mode: ArtifactConsumptionMode
    components: list[SharedArtifactComponent] = Field(default_factory=list)
    bundle_id: str | None = None
    route_count: int = Field(default=0, ge=0)
    consumed: bool = False
    detail: str = ""


class CompilationManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = COMPILATION_SCHEMA_VERSION
    status: CompilationStatus
    bundle_id: str | None = None
    compiler_version: str | None = None
    compiler_binary: str | None = None
    compiler_binary_sha256: str | None = None
    source_root: str | None = None
    entrypoints: list[str] = Field(default_factory=list)
    source_units: list[CompilationSourceUnit] = Field(default_factory=list)
    sources_sha256: str | None = None
    settings: CompilationSettings = Field(default_factory=CompilationSettings)
    settings_sha256: str | None = None
    standard_json_input_sha256: str | None = None
    standard_json_output_sha256: str | None = None
    requested_components: list[SharedArtifactComponent] = Field(default_factory=list)
    consumer_routes: list[CompilationConsumerRoute] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    failure_reason: CompilationFailure | None = None
    duration_seconds: float = Field(default=0.0, ge=0.0)


class Stage3CompilationBundle(BaseModel):
    """Validated standard-JSON provenance plus minimal consumer projections."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest: CompilationManifest
    contracts: dict[str, CompilationContract] = Field(default_factory=dict)
    tool_consumption: dict[str, ToolArtifactConsumption] = Field(default_factory=dict)
    standard_json_input: str = ""
    standard_json_output: str = ""

    def route_for(
        self,
        tool_id: str,
        logical_input_id: str,
    ) -> CompilationConsumerRoute | None:
        normalized_tool = tool_id.strip().lower()
        return next(
            (
                route
                for route in self.manifest.consumer_routes
                if route.tool_id == normalized_tool
                and route.logical_input_id == logical_input_id
            ),
            None,
        )


@dataclass(frozen=True)
class CompilerProcessResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


CompilerInvoker = Callable[[Path, bytes, float], CompilerProcessResult]


class CompilationBundleError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class _SourceProject:
    root: Path
    entrypoints: tuple[Path, ...]
    sources: tuple[Path, ...]
    contents: Mapping[str, bytes]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _ordered_components(values: Iterable[str]) -> list[SharedArtifactComponent]:
    requested = set(values)
    return [component for component in COMPONENT_ORDER if component in requested]


def _relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _discover_source_project(
    target_path: str | Path,
    *,
    project_root: str | Path | None = None,
) -> _SourceProject | None:
    try:
        explicit_root = (
            resolve_project_root(target_path, project_root)
            if project_root is not None
            else None
        )
    except ValueError as exc:
        raise CompilationBundleError("INVALID_PROJECT_ROOT", str(exc)) from exc
    target = (
        Path(target_path).expanduser()
        if explicit_root is not None
        else Path(target_path)
    ).resolve()
    if target.is_file():
        if target.is_symlink() or target.suffix.lower() != ".sol":
            return None
        root = explicit_root or target.parent
        entrypoints = [target]
    elif target.is_dir():
        root = explicit_root or target
        source_files = [
            path
            for path in sorted(target.rglob("*.sol"))
            if path.is_file() and not path.is_symlink()
        ]
        if not source_files:
            return None
        entrypoints = source_entrypoints(
            source_files, root, follow_imports=explicit_root is not None
        )
    else:
        return None

    closure: set[Path] = set()
    for entrypoint in entrypoints:
        closure.update(dependency_closure(entrypoint, root))
    ordered_sources = tuple(sorted(closure, key=lambda path: _relative(path, root)))
    contents: dict[str, bytes] = {}
    for source in ordered_sources:
        try:
            raw = source.read_bytes()
            raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise CompilationBundleError(
                "SOURCE_READ_FAILED",
                f"{_relative(source, root)}: {exc}",
            ) from exc
        contents[_relative(source, root)] = raw
    return _SourceProject(
        root=root,
        entrypoints=tuple(entrypoints),
        sources=ordered_sources,
        contents=contents,
    )


def _source_units(project: _SourceProject) -> list[CompilationSourceUnit]:
    return [
        CompilationSourceUnit(
            relative_path=name,
            sha256=_sha256_bytes(raw),
            size_bytes=len(raw),
        )
        for name, raw in project.contents.items()
    ]


def _sources_digest(units: Sequence[CompilationSourceUnit]) -> str:
    return _sha256_bytes(
        _canonical_json_bytes(
            [unit.model_dump(mode="json") for unit in units]
        )
    )


def _tool_consumption(
    selected_tools: Sequence[str],
    *,
    has_source: bool,
    bundle_id: str | None = None,
    route_counts: Mapping[str, int] | None = None,
    consumed: bool = False,
    detail: str = "",
) -> dict[str, ToolArtifactConsumption]:
    result: dict[str, ToolArtifactConsumption] = {}
    for raw_tool in selected_tools:
        tool = raw_tool.strip().lower()
        if not tool or tool in result:
            continue
        components = _ordered_components(shared_artifact_components(tool, "sol"))
        if has_source and components:
            mode = ArtifactConsumptionMode.SHARED_ARTIFACT
        elif has_source and adapter_supports_input(tool, "sol"):
            mode = ArtifactConsumptionMode.SOURCE_ONLY
        else:
            mode = ArtifactConsumptionMode.NOT_APPLICABLE
        count = int((route_counts or {}).get(tool, 0))
        result[tool] = ToolArtifactConsumption(
            tool_id=tool,
            mode=mode,
            components=components if mode == ArtifactConsumptionMode.SHARED_ARTIFACT else [],
            bundle_id=(
                bundle_id
                if mode == ArtifactConsumptionMode.SHARED_ARTIFACT
                else None
            ),
            route_count=count,
            consumed=consumed and mode == ArtifactConsumptionMode.SHARED_ARTIFACT,
            detail=detail,
        )
    return result


def _required_components(selected_tools: Sequence[str]) -> list[SharedArtifactComponent]:
    return _ordered_components(
        component
        for tool in selected_tools
        for component in shared_artifact_components(tool, "sol")
    )


def _failure_bundle(
    selected_tools: Sequence[str],
    *,
    code: str,
    detail: str,
    status: CompilationStatus = CompilationStatus.FAILED,
    duration_seconds: float = 0.0,
    project: _SourceProject | None = None,
    compiler_version: str | None = None,
    compiler_binary: Path | None = None,
    compiler_binary_sha256: str | None = None,
    settings: CompilationSettings | None = None,
    requested_components: Sequence[SharedArtifactComponent] = (),
    standard_json_input: str = "",
    standard_json_output: str = "",
    warnings: Sequence[str] = (),
) -> Stage3CompilationBundle:
    units = _source_units(project) if project is not None else []
    chosen_settings = settings or CompilationSettings()
    manifest = CompilationManifest(
        status=status,
        compiler_version=compiler_version,
        compiler_binary=str(compiler_binary) if compiler_binary is not None else None,
        compiler_binary_sha256=compiler_binary_sha256,
        source_root=str(project.root) if project is not None else None,
        entrypoints=(
            [_relative(path, project.root) for path in project.entrypoints]
            if project is not None
            else []
        ),
        source_units=units,
        sources_sha256=_sources_digest(units) if units else None,
        settings=chosen_settings,
        settings_sha256=_sha256_bytes(
            _canonical_json_bytes(chosen_settings.model_dump(mode="json"))
        ),
        standard_json_input_sha256=(
            _sha256_bytes(standard_json_input.encode("utf-8"))
            if standard_json_input
            else None
        ),
        standard_json_output_sha256=(
            _sha256_bytes(standard_json_output.encode("utf-8"))
            if standard_json_output
            else None
        ),
        requested_components=list(requested_components),
        warnings=list(warnings),
        failure_reason=(
            CompilationFailure(code=code, detail=detail)
            if status == CompilationStatus.FAILED
            else None
        ),
        duration_seconds=max(0.0, duration_seconds),
    )
    return Stage3CompilationBundle(
        manifest=manifest,
        tool_consumption=_tool_consumption(
            selected_tools,
            has_source=project is not None,
            detail=detail,
        ),
        standard_json_input=standard_json_input,
        standard_json_output=standard_json_output,
    )


def _not_applicable_bundle(
    selected_tools: Sequence[str],
    project: _SourceProject | None,
) -> Stage3CompilationBundle:
    return _failure_bundle(
        selected_tools,
        code="NOT_APPLICABLE",
        detail=(
            "no selected Solidity route consumes a shared artifact"
            if project is not None
            else "target has no Solidity source input"
        ),
        status=CompilationStatus.NOT_APPLICABLE,
        project=project,
    )


def _discover_installed_compilers() -> dict[str, Path]:
    candidates: dict[str, Path] = {}
    home = Path.home()
    for path in sorted((home / ".solc-select" / "artifacts").glob("solc-*/solc-*")):
        match = _VERSION_RE.search(path.name)
        if match and path.is_file():
            candidates[match.group(1)] = path.resolve()
    for path in sorted((home / ".solcx").glob("solc-v*")):
        match = _VERSION_RE.search(path.name)
        if match and path.is_file():
            candidates.setdefault(match.group(1), path.resolve())
    current = shutil.which("solc")
    if current:
        resolved = Path(current).resolve()
        match = _VERSION_RE.search(resolved.name)
        if match and resolved.is_file():
            candidates.setdefault(match.group(1), resolved)
    return candidates


def _project_constraints(project: _SourceProject) -> list[str]:
    constraints: list[str] = []
    for raw in project.contents.values():
        text = raw.decode("utf-8")
        masked = mask_solidity_noncode_for_pragmas(text)
        constraints.extend(match.group(1).strip() for match in _PRAGMA_RE.finditer(masked))
    return constraints


def _version_tuple(value: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in value.split("."))
    return major, minor, patch


def _select_compiler(
    project: _SourceProject,
    selected_tools: Sequence[str],
    selected_tool_solc_ranges: Mapping[str, str] | None,
    installed_compilers: Mapping[str, Path],
) -> tuple[str, Path] | None:
    constraints = _project_constraints(project)
    ranges = {
        tool.strip().lower(): value
        for tool, value in (selected_tool_solc_ranges or {}).items()
        if value and parse_solc_range(value) is not None
    }
    compatible = []
    for version, binary in installed_compilers.items():
        if not _VERSION_RE.fullmatch(version):
            continue
        if constraints and not all(
            version_satisfies_solidity_constraint(version, constraint)
            for constraint in constraints
        ):
            continue
        if any(
            tool.strip().lower() in ranges
            and not version_in_range(version, ranges[tool.strip().lower()])
            for tool in selected_tools
        ):
            continue
        compatible.append((version, Path(binary).resolve()))
    return max(compatible, key=lambda item: _version_tuple(item[0])) if compatible else None


def _standard_json_input(
    project: _SourceProject,
    components: Sequence[SharedArtifactComponent],
    settings: CompilationSettings,
) -> str:
    compiler_settings: dict[str, Any] = {
        "optimizer": {"enabled": settings.optimizer_enabled},
        "outputSelection": {
            "*": {"*": [_OUTPUT_COMPONENTS[component] for component in components]}
        },
    }
    if settings.optimizer_runs is not None:
        compiler_settings["optimizer"]["runs"] = settings.optimizer_runs
    if settings.evm_version is not None:
        compiler_settings["evmVersion"] = settings.evm_version
    if settings.remappings:
        compiler_settings["remappings"] = list(settings.remappings)
    # Omitting viaIR is the cross-version spelling of the canonical false value.
    request = {
        "language": "Solidity",
        "sources": {
            name: {"content": raw.decode("utf-8")}
            for name, raw in project.contents.items()
        },
        "settings": compiler_settings,
    }
    return _canonical_json_bytes(request).decode("utf-8")


def _invoke_compiler(
    binary: Path,
    request_bytes: bytes,
    timeout_seconds: float,
) -> CompilerProcessResult:
    try:
        completed = subprocess.run(
            [str(binary), "--standard-json"],
            input=request_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return CompilerProcessResult(
            returncode=None,
            stdout=(exc.stdout or b"").decode("utf-8", errors="replace"),
            stderr=(exc.stderr or b"").decode("utf-8", errors="replace"),
            timed_out=True,
        )
    except OSError as exc:
        return CompilerProcessResult(returncode=None, stdout="", stderr=str(exc))
    return CompilerProcessResult(
        returncode=completed.returncode,
        stdout=completed.stdout.decode("utf-8", errors="replace"),
        stderr=completed.stderr.decode("utf-8", errors="replace"),
    )


def _bytecode(data: Any, *path: str) -> str | None:
    current = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    if not isinstance(current, str):
        return None
    normalized = "".join(current.split()).removeprefix("0x")
    return normalized or None


def _project_contract(
    source_name: str,
    contract_name: str,
    raw: Any,
) -> CompilationContract:
    abi = raw.get("abi") if isinstance(raw, dict) else None
    return CompilationContract(
        fully_qualified_name=f"{source_name}:{contract_name}",
        source_unit=source_name,
        contract_name=contract_name,
        abi=abi if isinstance(abi, list) else None,
        creation_bytecode=_bytecode(raw, "evm", "bytecode", "object"),
        runtime_bytecode=_bytecode(raw, "evm", "deployedBytecode", "object"),
    )


def _has_components(
    contract: CompilationContract,
    components: Sequence[SharedArtifactComponent],
) -> bool:
    return all(
        contract.abi is not None
        if component == "abi"
        else contract.creation_bytecode is not None
        if component == "creation_bytecode"
        else contract.runtime_bytecode is not None
        for component in components
    )


def _select_entrypoint_contract(
    output_contracts: Any,
    entrypoint: str,
    components: Sequence[SharedArtifactComponent],
) -> CompilationContract:
    source_contracts = (
        output_contracts.get(entrypoint)
        if isinstance(output_contracts, dict)
        else None
    )
    projected = [
        _project_contract(entrypoint, name, raw)
        for name, raw in sorted((source_contracts or {}).items())
        if isinstance(name, str)
    ] if isinstance(source_contracts, dict) else []
    deployable = [contract for contract in projected if _has_components(contract, components)]
    stem = Path(entrypoint).stem
    stem_matches = [contract for contract in deployable if contract.contract_name == stem]
    if len(stem_matches) == 1:
        return stem_matches[0]
    if len(stem_matches) > 1 or len(deployable) > 1:
        raise CompilationBundleError(
            "AMBIGUOUS_TARGET_CONTRACT",
            f"{entrypoint} has multiple deployable contract outputs",
        )
    if len(deployable) == 1:
        return deployable[0]
    raise CompilationBundleError(
        "MISSING_REQUESTED_ARTIFACT",
        f"{entrypoint} has no deployable output with {','.join(components)}",
    )


def _diagnostics(payload: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    warnings: list[str] = []
    errors: list[str] = []
    raw_diagnostics = payload.get("errors")
    if not isinstance(raw_diagnostics, list):
        return warnings, errors
    for item in raw_diagnostics:
        if not isinstance(item, dict):
            continue
        message = str(item.get("formattedMessage") or item.get("message") or "").strip()
        severity = str(item.get("severity") or "").strip().lower()
        if severity == "error":
            errors.append(message or "compiler error")
        elif message:
            warnings.append(message)
    return warnings, errors


def _ensure_sources_unchanged(project: _SourceProject) -> None:
    for source in project.sources:
        relative = _relative(source, project.root)
        try:
            current = source.read_bytes()
        except OSError as exc:
            raise CompilationBundleError(
                "SOURCE_DIGEST_MISMATCH", f"{relative}: {exc}"
            ) from exc
        if current != project.contents[relative]:
            raise CompilationBundleError(
                "SOURCE_DIGEST_MISMATCH",
                f"source changed during compilation: {relative}",
            )


def compute_bundle_id(bundle: Stage3CompilationBundle) -> str:
    """Return the content identity, excluding paths, timing, and existing IDs."""

    manifest = bundle.manifest
    payload = {
        "schema_version": manifest.schema_version,
        "compiler_version": manifest.compiler_version,
        "compiler_binary_sha256": manifest.compiler_binary_sha256,
        "sources_sha256": manifest.sources_sha256,
        "settings": manifest.settings.model_dump(mode="json"),
        "settings_sha256": manifest.settings_sha256,
        "standard_json_input_sha256": manifest.standard_json_input_sha256,
        "standard_json_output_sha256": manifest.standard_json_output_sha256,
        "requested_components": manifest.requested_components,
        "contracts": {
            name: contract.model_dump(mode="json")
            for name, contract in sorted(bundle.contracts.items())
        },
        "consumer_routes": [
            {
                "tool_id": route.tool_id,
                "logical_input_id": route.logical_input_id,
                "fully_qualified_contract": route.fully_qualified_contract,
                "components": route.components,
            }
            for route in manifest.consumer_routes
        ],
    }
    return _sha256_bytes(_canonical_json_bytes(payload))


def _verify_internal(bundle: Stage3CompilationBundle) -> None:
    manifest = bundle.manifest
    if manifest.status != CompilationStatus.READY:
        return
    if not manifest.bundle_id or manifest.bundle_id != compute_bundle_id(bundle):
        raise CompilationBundleError("BUNDLE_DIGEST_MISMATCH")
    if manifest.standard_json_input_sha256 != _sha256_bytes(
        bundle.standard_json_input.encode("utf-8")
    ):
        raise CompilationBundleError("STANDARD_JSON_INPUT_DIGEST_MISMATCH")
    if manifest.standard_json_output_sha256 != _sha256_bytes(
        bundle.standard_json_output.encode("utf-8")
    ):
        raise CompilationBundleError("STANDARD_JSON_OUTPUT_DIGEST_MISMATCH")
    if manifest.settings_sha256 != _sha256_bytes(
        _canonical_json_bytes(manifest.settings.model_dump(mode="json"))
    ):
        raise CompilationBundleError("SETTINGS_DIGEST_MISMATCH")
    if manifest.sources_sha256 != _sources_digest(manifest.source_units):
        raise CompilationBundleError("SOURCE_MANIFEST_DIGEST_MISMATCH")
    if any(route.bundle_id != manifest.bundle_id for route in manifest.consumer_routes):
        raise CompilationBundleError("ROUTE_BUNDLE_ID_MISMATCH")


def validate_compilation_bundle(
    bundle: Stage3CompilationBundle,
    target_path: str | Path,
    selected_tools: Sequence[str],
    *,
    project_root: str | Path | None = None,
) -> Stage3CompilationBundle:
    """Validate bundle identity, current source bytes, and declared consumers."""

    _verify_internal(bundle)
    project = _discover_source_project(target_path, project_root=project_root)
    required = _required_components(selected_tools) if project is not None else []
    if not required:
        if bundle.manifest.status != CompilationStatus.NOT_APPLICABLE:
            raise CompilationBundleError("UNEXPECTED_COMPILATION_BUNDLE")
        return bundle
    if bundle.manifest.status != CompilationStatus.READY or project is None:
        raise CompilationBundleError("COMPILATION_BUNDLE_NOT_READY")
    current_units = _source_units(project)
    if current_units != bundle.manifest.source_units:
        raise CompilationBundleError("SOURCE_DIGEST_MISMATCH")
    if bundle.manifest.requested_components != required:
        raise CompilationBundleError("REQUESTED_COMPONENTS_MISMATCH")
    expected_entrypoints = [_relative(path, project.root) for path in project.entrypoints]
    if bundle.manifest.entrypoints != expected_entrypoints:
        raise CompilationBundleError("ENTRYPOINT_SET_MISMATCH")
    for tool in dict.fromkeys(value.strip().lower() for value in selected_tools if value):
        components = _ordered_components(shared_artifact_components(tool, "sol"))
        for entrypoint in expected_entrypoints if components else []:
            route = bundle.route_for(tool, entrypoint)
            if route is None or route.components != components:
                raise CompilationBundleError("CONSUMER_ROUTE_MISMATCH")
    return bundle


def build_compilation_bundle(
    target_path: str | Path,
    selected_tools: Sequence[str],
    *,
    project_root: str | Path | None = None,
    selected_tool_solc_ranges: Mapping[str, str] | None = None,
    compiler_timeout_seconds: float = DEFAULT_COMPILATION_TIMEOUT_SECONDS,
    installed_compilers: Mapping[str, Path] | None = None,
    compiler_invoker: CompilerInvoker | None = None,
    settings: CompilationSettings | None = None,
) -> Stage3CompilationBundle:
    """Compile the safe source-project union once when a selected route consumes it."""

    tools = list(dict.fromkeys(tool.strip().lower() for tool in selected_tools if tool.strip()))
    try:
        project = _discover_source_project(target_path, project_root=project_root)
    except CompilationBundleError as exc:
        return _failure_bundle(
            tools,
            code=exc.code,
            detail=exc.detail,
        )
    components = _required_components(tools) if project is not None else []
    if project is None or not components:
        return _not_applicable_bundle(tools, project)
    started = time.monotonic()
    if compiler_timeout_seconds <= 0:
        return _failure_bundle(
            tools,
            code="INVALID_COMPILATION_TIMEOUT",
            detail="compiler timeout must be positive",
            project=project,
            requested_components=components,
        )
    canonical_settings = settings or CompilationSettings()
    available = dict(
        _discover_installed_compilers()
        if installed_compilers is None
        else installed_compilers
    )
    selected = _select_compiler(
        project,
        tools,
        selected_tool_solc_ranges,
        available,
    )
    if selected is None:
        return _failure_bundle(
            tools,
            code="NO_COMMON_EXECUTION_SOLC",
            detail="no installed compiler satisfies project and selected-tool constraints",
            duration_seconds=time.monotonic() - started,
            project=project,
            settings=canonical_settings,
            requested_components=components,
        )
    compiler_version, compiler_binary = selected
    try:
        compiler_digest = _sha256_bytes(compiler_binary.read_bytes())
    except OSError as exc:
        return _failure_bundle(
            tools,
            code="COMPILER_BINARY_UNREADABLE",
            detail=str(exc),
            duration_seconds=time.monotonic() - started,
            project=project,
            compiler_version=compiler_version,
            compiler_binary=compiler_binary,
            settings=canonical_settings,
            requested_components=components,
        )
    standard_input = _standard_json_input(project, components, canonical_settings)
    process = (compiler_invoker or _invoke_compiler)(
        compiler_binary,
        standard_input.encode("utf-8"),
        compiler_timeout_seconds,
    )
    duration = time.monotonic() - started
    if process.timed_out:
        return _failure_bundle(
            tools,
            code="COMPILATION_TIMEOUT",
            detail=process.stderr[-4000:],
            duration_seconds=duration,
            project=project,
            compiler_version=compiler_version,
            compiler_binary=compiler_binary,
            compiler_binary_sha256=compiler_digest,
            settings=canonical_settings,
            requested_components=components,
            standard_json_input=standard_input,
            standard_json_output=process.stdout,
        )
    if process.returncode != 0:
        return _failure_bundle(
            tools,
            code="COMPILER_PROCESS_FAILED",
            detail=process.stderr[-4000:],
            duration_seconds=duration,
            project=project,
            compiler_version=compiler_version,
            compiler_binary=compiler_binary,
            compiler_binary_sha256=compiler_digest,
            settings=canonical_settings,
            requested_components=components,
            standard_json_input=standard_input,
            standard_json_output=process.stdout,
        )
    try:
        output = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        return _failure_bundle(
            tools,
            code="MALFORMED_COMPILER_OUTPUT",
            detail=str(exc),
            duration_seconds=duration,
            project=project,
            compiler_version=compiler_version,
            compiler_binary=compiler_binary,
            compiler_binary_sha256=compiler_digest,
            settings=canonical_settings,
            requested_components=components,
            standard_json_input=standard_input,
            standard_json_output=process.stdout,
        )
    if not isinstance(output, dict):
        return _failure_bundle(
            tools,
            code="MALFORMED_COMPILER_OUTPUT",
            detail="standard-JSON output is not an object",
            duration_seconds=duration,
            project=project,
            compiler_version=compiler_version,
            compiler_binary=compiler_binary,
            compiler_binary_sha256=compiler_digest,
            settings=canonical_settings,
            requested_components=components,
            standard_json_input=standard_input,
            standard_json_output=process.stdout,
        )
    warnings, errors = _diagnostics(output)
    if errors:
        return _failure_bundle(
            tools,
            code="COMPILER_DIAGNOSTIC_ERROR",
            detail="\n".join(errors)[-4000:],
            duration_seconds=duration,
            project=project,
            compiler_version=compiler_version,
            compiler_binary=compiler_binary,
            compiler_binary_sha256=compiler_digest,
            settings=canonical_settings,
            requested_components=components,
            standard_json_input=standard_input,
            standard_json_output=process.stdout,
            warnings=warnings,
        )
    try:
        _ensure_sources_unchanged(project)
        selected_contracts = {
            entrypoint: _select_entrypoint_contract(
                output.get("contracts"), entrypoint, components
            )
            for entrypoint in (
                _relative(path, project.root) for path in project.entrypoints
            )
        }
    except CompilationBundleError as exc:
        return _failure_bundle(
            tools,
            code=exc.code,
            detail=exc.detail,
            duration_seconds=duration,
            project=project,
            compiler_version=compiler_version,
            compiler_binary=compiler_binary,
            compiler_binary_sha256=compiler_digest,
            settings=canonical_settings,
            requested_components=components,
            standard_json_input=standard_input,
            standard_json_output=process.stdout,
            warnings=warnings,
        )

    contracts = {
        contract.fully_qualified_name: contract
        for contract in selected_contracts.values()
    }
    provisional_routes = [
        CompilationConsumerRoute(
            tool_id=tool,
            logical_input_id=entrypoint,
            fully_qualified_contract=contract.fully_qualified_name,
            components=_ordered_components(shared_artifact_components(tool, "sol")),
            bundle_id="pending",
        )
        for entrypoint, contract in selected_contracts.items()
        for tool in tools
        if shared_artifact_components(tool, "sol")
    ]
    units = _source_units(project)
    settings_digest = _sha256_bytes(
        _canonical_json_bytes(canonical_settings.model_dump(mode="json"))
    )
    manifest = CompilationManifest(
        status=CompilationStatus.READY,
        bundle_id="pending",
        compiler_version=compiler_version,
        compiler_binary=str(compiler_binary),
        compiler_binary_sha256=compiler_digest,
        source_root=str(project.root),
        entrypoints=list(selected_contracts),
        source_units=units,
        sources_sha256=_sources_digest(units),
        settings=canonical_settings,
        settings_sha256=settings_digest,
        standard_json_input_sha256=_sha256_bytes(standard_input.encode("utf-8")),
        standard_json_output_sha256=_sha256_bytes(process.stdout.encode("utf-8")),
        requested_components=components,
        consumer_routes=provisional_routes,
        warnings=warnings,
        duration_seconds=duration,
    )
    provisional = Stage3CompilationBundle(
        manifest=manifest,
        contracts=contracts,
        tool_consumption=_tool_consumption(
            tools,
            has_source=True,
            route_counts={
                tool: sum(route.tool_id == tool for route in provisional_routes)
                for tool in tools
            },
        ),
        standard_json_input=standard_input,
        standard_json_output=process.stdout,
    )
    bundle_id = compute_bundle_id(provisional)
    routes = [route.model_copy(update={"bundle_id": bundle_id}) for route in provisional_routes]
    ready = provisional.model_copy(
        update={
            "manifest": manifest.model_copy(
                update={"bundle_id": bundle_id, "consumer_routes": routes}
            ),
            "tool_consumption": _tool_consumption(
                tools,
                has_source=True,
                bundle_id=bundle_id,
                route_counts={
                    tool: sum(route.tool_id == tool for route in routes)
                    for tool in tools
                },
            ),
        }
    )
    _verify_internal(ready)
    return ready


def failed_compilation_bundle(
    target_path: str | Path,
    selected_tools: Sequence[str],
    *,
    project_root: str | Path | None = None,
    code: str,
    detail: str,
) -> Stage3CompilationBundle:
    """Create typed failed preflight provenance for a rejected supplied bundle."""

    try:
        project = _discover_source_project(target_path, project_root=project_root)
    except CompilationBundleError:
        project = None
    tools = list(dict.fromkeys(tool.strip().lower() for tool in selected_tools if tool.strip()))
    return _failure_bundle(
        tools,
        code=code,
        detail=detail,
        project=project,
        requested_components=(
            _required_components(tools) if project is not None else []
        ),
    )


def write_compilation_bundle(bundle: Stage3CompilationBundle, path: str | Path) -> Path:
    """Atomically serialize one bundle outside analyzer report directories."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(bundle.model_dump_json(indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def load_compilation_bundle(path: str | Path) -> Stage3CompilationBundle:
    try:
        bundle = Stage3CompilationBundle.model_validate_json(
            Path(path).read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as exc:
        raise CompilationBundleError("MALFORMED_COMPILATION_BUNDLE", str(exc)) from exc
    _verify_internal(bundle)
    return bundle


def write_compilation_manifest(
    bundle: Stage3CompilationBundle,
    results_root: str | Path,
) -> Path:
    """Write provenance beside status artifacts, never inside a tool scan tree."""

    path = Path(results_root) / "compilation_manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(bundle.manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path
