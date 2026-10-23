from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from toolrank import compilation, contract_profile, engine, execution, runner
from toolrank.schemas import CompositionPlan, ExecutionResult, ExecutionSchedule
from toolrank.source_project import resolve_project_root


ROOT = Path(__file__).resolve().parents[1]
SMARTBUGS = Path(__file__).resolve().parent / "fixtures" / "smartbugs_spawn"
SOURCE_NAMES = {"contracts/Main.sol", "lib/Lib.sol", "utils/Math.sol"}


@pytest.fixture
def nested_project(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "project"
    for folder in ("contracts", "lib", "utils"):
        (root / folder).mkdir(parents=True)
    entry = root / "contracts/Main.sol"
    entry.write_text(
        'pragma solidity ^0.8.0; import "../lib/Lib.sol"; contract Main {}',
        encoding="utf-8",
    )
    (root / "lib/Lib.sol").write_text(
        'pragma solidity >=0.8.10 <0.8.20; import "../utils/Math.sol"; library Lib {}',
        encoding="utf-8",
    )
    (root / "utils/Math.sol").write_text(
        "pragma solidity ^0.8.0; library Math {}", encoding="utf-8"
    )
    (root / "Unrelated.sol").write_text(
        "pragma solidity ^0.4.25; contract Unrelated {}", encoding="utf-8"
    )
    return root, entry


@pytest.fixture
def returning_project(nested_project) -> tuple[Path, Path]:
    root, entry = nested_project
    entry.write_text(
        'pragma solidity ^0.8.0; import "../lib/Lib.sol"; '
        "contract Main { function value(uint x) external pure returns (uint) { return Lib.value(x); } }",
        encoding="utf-8",
    )
    (root / "lib/Lib.sol").write_text(
        'pragma solidity >=0.8.10 <0.8.20; import "../contracts/Dep.sol"; '
        "library Lib { function value(uint x) internal pure returns (uint) { return x + 1; } }",
        encoding="utf-8",
    )
    (root / "contracts/Dep.sol").write_text(
        "pragma solidity >=0.8.12; interface Dep { function value(uint x) external returns (uint); }",
        encoding="utf-8",
    )
    return root, entry


def _bundle(
    tmp_path: Path, entry: Path, root: Path,
    *, empty_artifact_sources: set[str] | None = None,
):
    compilers = {}
    for version in ("0.8.19", "0.8.24"):
        binary = tmp_path / f"solc-{version}"
        binary.write_bytes(f"fake-solc-{version}".encode())
        compilers[version] = binary
    requests = []

    def compile_once(binary, request_bytes, _timeout):
        request = json.loads(request_bytes)
        requests.append((binary, request))
        return compilation.CompilerProcessResult(
            returncode=0,
            stdout=json.dumps({"contracts": {
                name: {Path(name).stem: {
                    "abi": [],
                    "evm": {
                        "bytecode": {"object": "" if name in (empty_artifact_sources or ()) else "6000"},
                        "deployedBytecode": {"object": "" if name in (empty_artifact_sources or ()) else "6001"},
                    },
                }}
                for name in request["sources"]
            }}),
            stderr="",
        )

    bundle = compilation.build_compilation_bundle(
        entry, ["smartian", "vandal"], project_root=root,
        installed_compilers=compilers, compiler_invoker=compile_once,
    )
    assert bundle.manifest.status == "READY"
    assert len(requests) == 1
    return bundle, requests[0]


def test_profile_uses_selected_import_closure_and_preserves_default(
    nested_project, monkeypatch,
) -> None:
    root, entry = nested_project
    source_inputs = []
    monkeypatch.setattr(
        contract_profile._complexity, "profile_sources",
        lambda sources: source_inputs.append(set(sources)) or {},
    )

    legacy = contract_profile.analyze_target(str(entry))
    scoped = contract_profile.analyze_target(str(entry), project_root=root)

    assert legacy.file_count == 1 and not legacy.is_multifile
    assert legacy.solidity_version_constraints == ["^0.8.0"]
    assert legacy.primary_solidity_version == "0.8.0"
    assert scoped.file_count == 3 and scoped.is_multifile
    assert scoped.execution_input_count == 1
    assert scoped.primary_solidity_version == "0.8.10"
    assert set(scoped.solidity_version_constraints) == {
        "^0.8.0", ">=0.8.10 <0.8.20",
    }
    assert source_inputs == [{"Main.sol"}, SOURCE_NAMES]


def test_directory_selection_can_resolve_dependencies_outside_its_subtree(
    nested_project, monkeypatch,
) -> None:
    root, entry = nested_project
    monkeypatch.setattr(contract_profile._complexity, "profile_sources", lambda _s: {})

    features = contract_profile.analyze_target(str(entry.parent), project_root=root)
    inputs = runner._discover_target_inputs(entry.parent, project_root=root)

    assert features.file_count == 3 and features.execution_input_count == 1
    assert [item.path for item in inputs] == [entry]
    assert features.primary_solidity_version == "0.8.10"


def test_returning_dependency_is_not_a_profile_or_shared_compilation_entrypoint(
    returning_project, tmp_path, monkeypatch,
) -> None:
    root, entry = returning_project
    monkeypatch.setattr(contract_profile._complexity, "profile_sources", lambda _s: {})
    legacy = contract_profile.analyze_target(str(entry.parent))
    scoped = contract_profile.analyze_target(str(entry.parent), project_root=root)
    assert legacy.file_count == 2 and legacy.execution_input_count == 2
    assert [item.path.name for item in runner._discover_target_inputs(entry.parent)] == [
        "Dep.sol", "Main.sol",
    ]
    assert scoped.file_count == 3 and scoped.execution_input_count == 1
    assert scoped.primary_solidity_version == "0.8.12"
    assert [item.path for item in runner._discover_target_inputs(entry.parent, project_root=root)] == [entry]
    bundle, (_binary, request) = _bundle(
        tmp_path, entry.parent, root, empty_artifact_sources={"contracts/Dep.sol"},
    )
    assert set(request["sources"]) == {"contracts/Main.sol", "lib/Lib.sol", "contracts/Dep.sol"}
    assert bundle.manifest.entrypoints == ["contracts/Main.sol"]
    for tool in ("smartian", "vandal"):
        assert bundle.route_for(tool, "contracts/Main.sol") is not None
        assert bundle.route_for(tool, "contracts/Dep.sol") is None


def test_dependency_pragma_conflict_fails_before_compiler_launch(
    nested_project, tmp_path, monkeypatch,
) -> None:
    root, entry = nested_project
    (root / "lib/Lib.sol").write_text("pragma solidity ^0.7.0; library Lib {}")
    monkeypatch.setattr(contract_profile._complexity, "profile_sources", lambda _s: {})
    with pytest.raises(contract_profile.SolidityConstraintError):
        contract_profile.analyze_target(str(entry), project_root=root)
    bundle = compilation.build_compilation_bundle(
        entry, ["smartian"], project_root=root,
        installed_compilers={"0.8.19": tmp_path / "solc-0.8.19"},
        compiler_invoker=lambda *_a: pytest.fail("incompatible pragmas must fail before compilation"),
    )
    assert bundle.manifest.failure_reason.code == "NO_COMMON_EXECUTION_SOLC"


@pytest.mark.parametrize("case", [
    "missing_root", "root_file", "outside", "prefix_sibling",
    "symlink_file", "symlink_parent", "missing_entry", "no_entry",
])
def test_invalid_project_context_is_rejected_before_analysis(
    nested_project, tmp_path, monkeypatch, case,
) -> None:
    root, entry = nested_project
    selected_root = root
    if case == "missing_root":
        selected_root = tmp_path / "missing"
    elif case == "root_file":
        selected_root = entry
    elif case in {"outside", "prefix_sibling", "symlink_file", "symlink_parent"}:
        outside = tmp_path / ("project-other" if case == "prefix_sibling" else "outside")
        outside.mkdir()
        outside_entry = outside / "Other.sol"
        outside_entry.write_text("pragma solidity ^0.8.0; contract Other {}")
        if case == "symlink_file":
            entry = root / "Linked.sol"
            entry.symlink_to(outside_entry)
        elif case == "symlink_parent":
            (root / "linked").symlink_to(outside, target_is_directory=True)
            entry = root / "linked/Other.sol"
        else:
            entry = outside_entry
    elif case == "missing_entry":
        entry = root / "Missing.sol"
    else:
        entry = None
    with pytest.raises(ValueError):
        resolve_project_root(entry, selected_root)
    with pytest.raises(ValueError):
        contract_profile.analyze_target(str(entry) if entry else None, project_root=selected_root)
    monkeypatch.setattr(engine, "load_toolcards", lambda *_a: pytest.fail("invalid input must fail before recommendation"))
    with pytest.raises(ValueError):
        engine.run_recommendation(
            target_path=str(entry) if entry else None,
            project_root=selected_root, toolcards_dir=str(tmp_path),
        )
    if entry is not None:
        bundle = compilation.build_compilation_bundle(entry, ["smartian"], project_root=selected_root)
        assert bundle.manifest.failure_reason.code == "INVALID_PROJECT_ROOT"
        monkeypatch.setattr(runner, "_discover_target_inputs", lambda *_a, **_k: pytest.fail("invalid input must fail before dispatch"))
        with pytest.raises(SystemExit) as rejected:
            runner.run_targets(entry, tmp_path / "results", ["slither"], project_root=selected_root)
        assert rejected.value.code == 2


def test_shared_compilation_preserves_project_names_and_consumer_identity(
    nested_project, tmp_path,
) -> None:
    root, entry = nested_project
    bundle, (binary, request) = _bundle(tmp_path, entry, root)

    assert binary.name == "solc-0.8.19"
    assert set(request["sources"]) == SOURCE_NAMES
    for name in SOURCE_NAMES:
        assert request["sources"][name]["content"] == (root / name).read_text()
    assert bundle.manifest.source_root == str(root)
    assert bundle.manifest.entrypoints == ["contracts/Main.sol"]
    assert bundle.manifest.compiler_version == "0.8.19"
    assert runner._logical_input_id(entry, entry, project_root=root) == "contracts/Main.sol"
    assert runner._logical_input_id(entry, entry) == "Main.sol"
    for tool in ("smartian", "vandal"):
        route = bundle.route_for(tool, "contracts/Main.sol")
        assert route is not None
        assert route.fully_qualified_contract == "contracts/Main.sol:Main"
        assert bundle.route_for(tool, "Main.sol") is None
    restored = compilation.Stage3CompilationBundle.model_validate_json(bundle.model_dump_json())
    compilation.validate_compilation_bundle(restored, entry, ["smartian", "vandal"], project_root=root)
    with pytest.raises(compilation.CompilationBundleError, match="SOURCE_DIGEST_MISMATCH"):
        compilation.validate_compilation_bundle(restored, entry, ["smartian", "vandal"])


@pytest.mark.parametrize("path", ["runner", "native"])
def test_ready_shared_bundle_is_reused_with_explicit_project_context(
    nested_project, tmp_path, monkeypatch, path,
) -> None:
    root, entry = nested_project
    bundle, _request = _bundle(tmp_path, entry, root)
    seen = []

    def adapter(tool, contract, out_dir, **kwargs):
        assert contract == entry and kwargs["target_root"] == entry
        assert kwargs["project_root"] == root
        assert kwargs["logical_input_id"] == "contracts/Main.sol"
        assert kwargs["compilation_bundle"].route_for(tool, "contracts/Main.sol") is not None
        seen.append(tool)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "result.json").write_text(json.dumps({"findings": []}))
        return 0

    def unexpected_compile(*_a, **_k):
        pytest.fail("ready bundles must be reused across the project-root boundary")

    monkeypatch.setattr(runner, "_run_adapter_with_deadline", adapter)
    monkeypatch.setattr(runner, "build_compilation_bundle", unexpected_compile)
    monkeypatch.setattr(execution, "build_compilation_bundle", unexpected_compile)
    results = tmp_path / "results"
    if path == "runner":
        bundle_file = compilation.write_compilation_bundle(bundle, tmp_path / "bundle.json")
        assert runner.run_targets(
            entry, results, ["smartian", "vandal"], project_root=root,
            compilation_bundle=bundle_file, write_lakes_output=False,
        ) == 0
    else:
        monkeypatch.setattr(execution, "DEFAULT_SMARTBUGS_DIR", SMARTBUGS)
        plan = ExecutionResult(
            status="planned", target_path=str(entry), project_root=str(root),
            results_root=str(results), selected_tool_ids=["smartian", "vandal"],
            primary_tool_id="smartian", compilation_bundle=bundle,
        )
        assert execution._native_smartbugs_execute(plan).status == "executed"
    assert sorted(seen) == ["smartian", "vandal"]
    manifest = json.loads((results / "compilation_manifest.json").read_text())
    assert manifest["source_root"] == str(root)
    assert manifest["entrypoints"] == ["contracts/Main.sol"]


@pytest.mark.parametrize("path", ["runner", "native"])
def test_nested_file_project_context_reaches_real_spawn_worker(
    nested_project, tmp_path, monkeypatch, path,
) -> None:
    root, entry = nested_project
    results = tmp_path / "results"
    composition = CompositionPlan(
        selected_tool_ids=["slither"], primary_tool_id="slither",
        execution_schedule=ExecutionSchedule(tool_timeout_seconds=20),
    )
    plan = execution.build_execution_plan(
        entry, results, composition, project_root=root, write_lakes_output=False,
    )
    assert plan.runner_command[plan.runner_command.index("--project-root") + 1] == str(root)
    # Deserialization must retain the context used by native fallback too.
    plan = ExecutionResult.model_validate_json(plan.model_dump_json())
    assert plan.project_root == str(root)
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    monkeypatch.setenv("LAKES_SOLIDITY_CONSTRAINTS", '["0.8.30"]')
    env = {"LAKES_SMARTBUGS_DIR": str(SMARTBUGS)}
    if path == "runner":
        completed = execution.execute_plan(plan, runner_env=env)
        assert completed.execution_mode == "manual_runner"
    else:
        completed = execution._native_smartbugs_execute(plan, runner_env=env)
        assert completed.execution_mode == "native_smartbugs"
    assert completed.status == "executed", completed.stderr_tail
    assert completed.tool_statuses["slither"].status == "SUCCESS"
    reports = list(results.rglob("result.json"))
    assert len(reports) == 1
    probe = json.loads(reports[0].read_text())["probe"]
    assert probe["start_method"] == "spawn" and probe["main_module"] == "__mp_main__"
    assert probe["compiler"] == "0.8.19"
    assert probe["files"] == {f"project/{name}": (root / name).read_text() for name in SOURCE_NAMES}
    assert probe["docker_args"]["command"] == ["analyze", "/sb/project/contracts/Main.sol", "20", "/sb/bin", "0"]
    manifest = json.loads((results / "compilation_manifest.json").read_text())
    assert manifest["entrypoints"] == ["contracts/Main.sol"]
    assert {source["relative_path"] for source in manifest["source_units"]} == SOURCE_NAMES


@pytest.mark.parametrize("path", ["runner", "native"])
def test_returning_dependency_is_not_dispatched_to_a_spawn_worker(
    returning_project, tmp_path, monkeypatch, path,
) -> None:
    root, entry = returning_project
    results = tmp_path / "results"
    plan = execution.build_execution_plan(
        entry.parent, results,
        CompositionPlan(
            selected_tool_ids=["slither"], primary_tool_id="slither",
            execution_schedule=ExecutionSchedule(tool_timeout_seconds=20),
        ),
        project_root=root, write_lakes_output=False,
    )
    monkeypatch.setenv("PYTHONPATH", str(ROOT))
    env = {"LAKES_SMARTBUGS_DIR": str(SMARTBUGS)}
    completed = (
        execution.execute_plan(plan, runner_env=env)
        if path == "runner"
        else execution._native_smartbugs_execute(plan, runner_env=env)
    )
    assert completed.status == "executed", completed.stderr_tail
    report, = results.rglob("result.json")
    probe = json.loads(report.read_text())["probe"]
    assert probe["start_method"] == "spawn"
    assert probe["compiler"] == "0.8.19"
    assert set(probe["files"]) == {
        "project/contracts/Main.sol", "project/lib/Lib.sol", "project/contracts/Dep.sol",
    }
    assert probe["docker_args"]["command"][1] == "/sb/project/contracts/Main.sol"
    manifest = json.loads((results / "compilation_manifest.json").read_text())
    assert manifest["entrypoints"] == ["contracts/Main.sol"]


def test_legacy_execution_plan_does_not_add_a_project_root(nested_project, tmp_path) -> None:
    _root, entry = nested_project
    plan = execution.build_execution_plan(
        entry, tmp_path / "results",
        CompositionPlan(selected_tool_ids=["slither"], primary_tool_id="slither"),
    )
    assert plan.project_root is None
    assert "--project-root" not in plan.runner_command
    legacy_json = plan.model_dump()
    legacy_json.pop("project_root")
    assert ExecutionResult.model_validate(legacy_json).project_root is None


def test_relative_project_context_is_serialized_as_absolute_paths(
    nested_project, tmp_path, monkeypatch,
) -> None:
    root, entry = nested_project
    monkeypatch.chdir(tmp_path)
    plan = execution.build_execution_plan(
        Path("project/contracts/Main.sol"), tmp_path / "results",
        CompositionPlan(selected_tool_ids=["slither"], primary_tool_id="slither"),
        project_root=Path("project"),
    )
    assert plan.target_path == str(entry)
    assert plan.project_root == str(root)
    assert plan.runner_command[2] == str(entry)
    assert plan.runner_command[plan.runner_command.index("--project-root") + 1] == str(root)


@pytest.mark.parametrize("kind", ["bytecode", "runtime", "vandal_source"])
def test_project_root_validation_keeps_temporary_bytecode_projections_working(
    nested_project, tmp_path, kind,
) -> None:
    root, entry = nested_project
    bundle = None
    tool = "mythril"
    input_kind = kind
    if kind == "vandal_source":
        bundle, _request = _bundle(tmp_path, entry, root)
        tool, input_kind = "vandal", "sol"
    else:
        entry = root / "contracts/Code.hex"
        entry.write_text("0x60 00\n")
    with runner.prepare_smartbugs_invocation(
        tool, entry, tmp_path / "result", target_root=entry,
        project_root=root, smartbugs_dir=SMARTBUGS, timeout=10,
        input_kind=input_kind, compilation_bundle=bundle,
        logical_input_id="contracts/Main.sol",
    ) as invocation:
        staged = Path(invocation.command[invocation.command.index("-f") + 1])
        assert staged.is_file() and root not in staged.parents
        assert staged.read_text() == ("6001" if kind == "vandal_source" else "6000")
        assert invocation.command[0] == "./smartbugs"
        assert ("--runtime" in invocation.command) == (kind != "bytecode")
    assert not staged.exists()


def test_gptscan_stages_only_selected_entry_with_the_wider_dependency_root(
    nested_project, tmp_path, monkeypatch,
) -> None:
    root, entry = nested_project
    main = tmp_path / "gptscan/main.py"
    main.parent.mkdir()
    main.write_text("# test sentinel")
    monkeypatch.setattr(runner, "GPTSCAN_MAIN", main)

    def select_compiler(contract, _label, *, target_root, entrypoints):
        assert contract == entry and target_root == root
        assert entrypoints == [entry]
        assert ">=0.8.10 <0.8.20" in runner._collect_pragma_specs(contract, target_root=target_root)
        return True

    def run_process(_command, *, env, **_kwargs):
        staged = Path(env["LAKES_GPTSCAN_SOURCE"])
        assert json.loads(env["LAKES_GPTSCAN_ENTRYPOINTS"]) == ["contracts/Main.sol"]
        assert {p.relative_to(staged).as_posix() for p in staged.rglob("*.sol")} == SOURCE_NAMES
        Path(env["LAKES_GPTSCAN_OUTPUT"]).write_text(json.dumps({
            "success": True,
            "results": [{
                "code": "nested_issue",
                "affectedFiles": [
                    {"filePath": str(staged / "contracts/Main.sol")},
                    {"filePath": "lib/Lib.sol"},
                ],
            }],
        }))
        return 0

    monkeypatch.setattr(runner, "_run_solc_select", select_compiler)
    monkeypatch.setattr(runner, "_stream_process", run_process)
    assert runner._run_smartbugs_tool(
        "gptscan", entry, tmp_path / "result", target_root=entry,
        project_root=root, smartbugs_dir=None, timeout=10,
        gptscan_timeout=5, openai_api_key="", openai_api_base="",
    ) == 0
    report = json.loads((tmp_path / "result/result.json").read_text())
    assert [finding["filename"] for finding in report["findings"]] == [
        str(entry), str(root / "lib/Lib.sol"),
    ]


def test_gptscan_keeps_the_legacy_compiler_without_project_root(
    nested_project, tmp_path, monkeypatch,
) -> None:
    _root, entry = nested_project
    main = tmp_path / "gptscan/main.py"
    main.parent.mkdir()
    main.write_text("# test sentinel")
    monkeypatch.setattr(runner, "GPTSCAN_MAIN", main)
    monkeypatch.setenv("LAKES_GPTSCAN_ENTRYPOINTS", '["stale.sol"]')

    def select_compiler(contract, _label, *, target_root):
        assert contract == entry and target_root == entry.parent
        return True

    def run_process(_command, *, env, **_kwargs):
        assert "LAKES_GPTSCAN_ENTRYPOINTS" not in env
        staged = Path(env["LAKES_GPTSCAN_SOURCE"])
        assert (staged / "Main.sol").is_file()
        Path(env["LAKES_GPTSCAN_OUTPUT"]).write_text('{"success": true, "results": []}')
        return 0

    monkeypatch.setattr(runner, "_run_solc_select", select_compiler)
    monkeypatch.setattr(runner, "_stream_process", run_process)
    assert runner._run_gptscan(entry, tmp_path / "result", "", 5, "", target_root=entry) == 0


@pytest.mark.parametrize("mode", ["file", "directory", "multiple_entries", "legacy"])
def test_gptscan_and_shared_compilation_use_real_solc_and_falcon(
    returning_project, tmp_path, mode,
) -> None:
    image = os.environ.get("LAKES_TEST_RUNTIME_IMAGE")
    if not image:
        pytest.skip("set LAKES_TEST_RUNTIME_IMAGE to a built LAKES image for real compiler tests")
    root, entry = returning_project
    names = {"contracts/Main.sol", "lib/Lib.sol", "contracts/Dep.sol"}
    entrypoints = ["contracts/Main.sol"]
    version = "0.8.19"
    if mode == "file":
        entry.write_text(entry.read_text().replace("../lib/Lib.sol", "lib/Lib.sol"))
        library = root / "lib/Lib.sol"
        library.write_text(library.read_text().replace("../contracts/Dep.sol", "contracts/Dep.sol"))
    elif mode == "multiple_entries":
        library = root / "lib/Lib.sol"
        library.write_text(library.read_text().replace(" <0.8.20", ""))
        (entry.parent / "Other.sol").write_text(
            "pragma solidity >=0.8.30; contract Other {}", encoding="utf-8"
        )
        names.add("contracts/Other.sol")
        entrypoints.append("contracts/Other.sol")
        version = "0.8.30"
    elif mode == "legacy":
        entry.write_text(
            "pragma solidity ^0.8.0; contract Main { "
            "function value(uint x) external pure returns (uint) { return x + 1; } }",
            encoding="utf-8",
        )
        names = {"Main.sol"}
        entrypoints = None
    completed = subprocess.run(
        [
            "docker", "run", "--rm", "--pull=never", "--network", "none",
            "--mount", f"type=bind,src={ROOT},dst=/lakes-code,readonly",
            "--mount", f"type=bind,src={tmp_path},dst=/case",
            "--env", "PYTHONPATH=/lakes-code:/work/docker/vendor/gptscan/src",
            "--entrypoint", "python3", image,
            "/lakes-code/tests/fixtures/gptscan_project/run_compile_case.py", "/case", mode,
        ],
        capture_output=True, text=True, timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    raw_path, = (tmp_path / "result").rglob("gptscan_output.json")
    raw = json.loads(raw_path.read_text())
    assert set(raw["probe"]["sources"]) == names
    assert raw["probe"]["entrypoints"] == entrypoints
    assert raw["probe"]["compilers"] == [version]
    assert raw["probe"]["main_ir_operations"] > 0
    report = json.loads(raw_path.with_name("result.json").read_text())
    original_root = Path("/case/project/contracts") if mode == "legacy" else Path("/case/project")
    assert {finding["filename"] for finding in report["findings"]} == {
        str(original_root / name) for name in names
    }
    if mode != "legacy":
        manifest = json.loads((tmp_path / "result/compilation_manifest.json").read_text())
        assert manifest["entrypoints"] == entrypoints
        assert {source["relative_path"] for source in manifest["source_units"]} == names
    if mode in {"file", "directory"}:
        executed = json.loads((tmp_path / "result/execution.json").read_text())
        assert executed["project_root"] == "/case/project"
        assert executed["execution_mode"] == (
            "manual_runner" if mode == "file" else "native_smartbugs"
        )


@pytest.mark.parametrize("tool", ["securify2", "sailfish"])
def test_special_source_adapter_receives_project_paths_and_dependency_pragmas(
    nested_project, tmp_path, monkeypatch, tool,
) -> None:
    root, entry = nested_project
    adapter = tmp_path / "adapter.py"
    adapter.write_text("# test sentinel")
    monkeypatch.setattr(runner, "SECURIFY2_RUNNER", adapter)
    monkeypatch.setattr(runner, "SAILFISH_RUNNER", adapter)
    monkeypatch.setattr(runner, "_SECURIFY2_IMAGE_CACHE", set())
    monkeypatch.setattr(runner, "_inspect_docker_image", lambda _image: "exists")
    commands = []

    def run_process(command, **_kwargs):
        commands.append(command)
        return 0

    monkeypatch.setattr(runner, "_stream_process", run_process)
    assert runner._run_smartbugs_tool(
        tool, entry, tmp_path / "result", target_root=entry,
        project_root=root, smartbugs_dir=None, timeout=10,
        gptscan_timeout=5, openai_api_key="", openai_api_base="",
    ) == 0
    command, = commands
    if tool == "securify2":
        assert command[2] == str(entry)
        assert command[command.index("--project-root") + 1] == str(root)
        assert command[command.index("--image") + 1] == runner.SECURIFY2_IMAGE_TEMPLATE.format(version="0.8.10")
    else:
        assert command[2:5] == [str(root), "contracts/Main.sol", "0.8.10"]
