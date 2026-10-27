from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from toolrank import runner
from toolrank.compilation import (
    CompilerProcessResult,
    Stage3CompilationBundle,
    build_compilation_bundle,
)


def _write_report(path: Path, filename: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "result.json").write_text(
        json.dumps({"findings": [{"name": "tx-origin", "filename": filename}]}),
        encoding="utf-8",
    )


def _bundle(tmp_path: Path, tools: list[str], target: Path) -> Stage3CompilationBundle:
    compiler = tmp_path / "solc-0.8.24"
    compiler.write_bytes(b"fake-solc")
    compiler.chmod(0o755)

    def compile_once(_binary, request_bytes, _timeout):
        request = json.loads(request_bytes)
        contracts = {}
        for source_name in request["sources"]:
            stem = Path(source_name).stem
            contracts[source_name] = {
                stem: {
                    "abi": [{"type": "constructor"}],
                    "evm": {
                        "bytecode": {"object": "6000"},
                        "deployedBytecode": {"object": "6001"},
                    },
                }
            }
        return CompilerProcessResult(
            returncode=0,
            stdout=json.dumps({"contracts": contracts}),
            stderr="",
        )

    return build_compilation_bundle(
        target,
        tools,
        installed_compilers={"0.8.24": compiler},
        compiler_invoker=compile_once,
    )


def test_runner_reuses_ready_bundle_for_smartian_and_vandal(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "Main.sol"
    target.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    bundle = _bundle(tmp_path, ["smartian", "vandal"], target)
    seen: list[tuple[str, str | None]] = []

    monkeypatch.setattr(
        runner,
        "build_compilation_bundle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("ready bundle must not be recompiled")
        ),
        raising=False,
    )

    def fake_adapter(tool_id, contract_path, out_dir, **kwargs):
        supplied = kwargs["compilation_bundle"]
        seen.append((tool_id, supplied.manifest.bundle_id))
        _write_report(Path(out_dir), Path(contract_path).name)
        return 0

    monkeypatch.setattr(runner, "_run_adapter_with_deadline", fake_adapter)
    results = tmp_path / "results"

    rc = runner.run_targets(
        target,
        results,
        ["smartian", "vandal"],
        primary_tool="smartian",
        compilation_bundle=bundle,
        write_lakes_output=False,
    )

    assert rc == 0
    assert sorted(seen) == [
        ("smartian", bundle.manifest.bundle_id),
        ("vandal", bundle.manifest.bundle_id),
    ]
    manifest = json.loads(
        (results / "compilation_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["bundle_id"] == bundle.manifest.bundle_id
    statuses = json.loads(
        (results / "tool_run_statuses.json").read_text(encoding="utf-8")
    )
    assert statuses["smartian"]["artifact_consumption"]["mode"] == "SHARED_ARTIFACT"
    assert statuses["vandal"]["artifact_consumption"]["bundle_id"] == bundle.manifest.bundle_id
    assert statuses["smartian"]["artifact_consumption"]["consumed"] is True
    assert statuses["vandal"]["artifact_consumption"]["consumed"] is True


@pytest.mark.parametrize(
    ("return_code", "expected_status"),
    [(1, "FAIL"), (124, "TIMEOUT"), (runner.OUTPUT_CLEANUP_FAILURE_RETURN_CODE, "FAIL")],
)
def test_runner_does_not_report_failed_shared_source_as_consumed(
    tmp_path: Path,
    monkeypatch,
    return_code: int,
    expected_status: str,
) -> None:
    target = tmp_path / "Main.sol"
    target.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    bundle = _bundle(tmp_path, ["vandal"], target)
    monkeypatch.setattr(
        runner,
        "_run_adapter_with_deadline",
        lambda *_args, **_kwargs: return_code,
    )
    results = tmp_path / "results"

    rc = runner.run_targets(
        target,
        results,
        ["vandal"],
        primary_tool="vandal",
        compilation_bundle=bundle,
        write_lakes_output=False,
    )

    assert rc == return_code
    status = json.loads(
        (results / "tool_run_statuses.json").read_text(encoding="utf-8")
    )["vandal"]
    assert status["status"] == expected_status
    assert status["artifact_consumption"]["consumed"] is False


@pytest.mark.parametrize(
    ("source_return_code", "runtime_return_code", "expected_consumed"),
    [(1, 0, False), (0, 1, True)],
)
def test_runner_mixed_history_consumption_depends_on_shared_source_success(
    tmp_path: Path,
    monkeypatch,
    source_return_code: int,
    runtime_return_code: int,
    expected_consumed: bool,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "Main.sol"
    source.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    (project / "Explicit.runtime").write_text("0x6002\n", encoding="utf-8")
    bundle = _bundle(tmp_path, ["vandal"], project)

    def fake_adapter(_tool_id, contract_path, out_dir, **kwargs):
        return_code = (
            source_return_code if kwargs["input_kind"] == "sol" else runtime_return_code
        )
        if return_code == 0:
            _write_report(Path(out_dir), Path(contract_path).name)
        return return_code

    monkeypatch.setattr(runner, "_run_adapter_with_deadline", fake_adapter)
    results = tmp_path / "results"

    rc = runner.run_targets(
        project,
        results,
        ["vandal"],
        primary_tool="vandal",
        compilation_bundle=bundle,
        write_lakes_output=False,
    )

    assert rc == 1
    status = json.loads(
        (results / "tool_run_statuses.json").read_text(encoding="utf-8")
    )["vandal"]
    assert status["status"] == "PARTIAL"
    assert status["artifact_consumption"]["consumed"] is expected_consumed


def test_compile_failure_stops_runner_workers_and_clears_stale_reports(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "Main.sol"
    target.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    failed = build_compilation_bundle(
        target,
        ["smartian", "vandal"],
        installed_compilers={},
    )
    results = tmp_path / "results"
    stale = results / "smartian" / "result.json"
    _write_report(stale.parent, "Old.sol")
    (results / "compilation_manifest.json").write_text(
        '{"status":"READY","bundle_id":"stale"}', encoding="utf-8"
    )
    monkeypatch.setattr(runner, "build_compilation_bundle", lambda *_a, **_k: failed, raising=False)
    monkeypatch.setattr(
        runner,
        "_run_adapter_with_deadline",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("compiler failure must precede every worker")
        ),
    )

    rc = runner.run_targets(
        target,
        results,
        ["smartian", "vandal"],
        primary_tool="smartian",
        write_lakes_output=False,
    )

    assert rc == runner.COMPILATION_FAILURE_RETURN_CODE
    assert not stale.exists()
    statuses = json.loads(
        (results / "tool_run_statuses.json").read_text(encoding="utf-8")
    )
    assert {value["status"] for value in statuses.values()} == {"NOT_RUN"}
    assert all("NO_COMMON_EXECUTION_SOLC" in value["detail"] for value in statuses.values())
    assert all(
        value["artifact_consumption"]["consumed"] is False
        for value in statuses.values()
    )
    manifest = json.loads(
        (results / "compilation_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["status"] == "FAILED"
    assert manifest["bundle_id"] is None


def test_source_native_tool_receives_shared_exact_compiler_version(
    tmp_path: Path,
) -> None:
    target = tmp_path / "Main.sol"
    target.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    bundle = _bundle(tmp_path, ["smartian", "slither"], target)
    smartbugs = tmp_path / "smartbugs"
    (smartbugs / "sb").mkdir(parents=True)
    for name in ("cli.py", "docker.py"):
        (smartbugs / "sb" / name).write_text("", encoding="utf-8")

    with runner.prepare_smartbugs_invocation(
        "slither",
        target,
        tmp_path / "out",
        target_root=target,
        smartbugs_dir=smartbugs,
        timeout=10,
        input_kind="sol",
        compilation_bundle=bundle,
        logical_input_id="Main.sol",
    ) as invocation:
        assert invocation.env is not None
        assert invocation.env["LAKES_EXECUTION_SOLC_VERSION"] == "0.8.24"
        assert json.loads(invocation.env["LAKES_SOLIDITY_CONSTRAINTS"]) == ["0.8.24"]

    assert bundle.tool_consumption["slither"].mode == "SOURCE_ONLY"
    assert {route.tool_id for route in bundle.manifest.consumer_routes} == {"smartian"}


def test_mixed_source_runtime_routes_each_logical_input_once(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "Main.sol"
    source.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    explicit_runtime = project / "Explicit.runtime"
    explicit_runtime.write_text("0x6002\n", encoding="utf-8")
    bundle = _bundle(tmp_path, ["vandal", "mythril"], project)
    calls: list[tuple[str, str, str, bool]] = []

    def fake_adapter(tool_id, contract_path, out_dir, **kwargs):
        supplied = kwargs["compilation_bundle"]
        logical_id = kwargs["logical_input_id"]
        calls.append(
            (
                tool_id,
                Path(contract_path).name,
                kwargs["input_kind"],
                supplied.route_for(tool_id, logical_id) is not None,
            )
        )
        _write_report(Path(out_dir), Path(contract_path).name)
        return 0

    monkeypatch.setattr(runner, "_run_adapter_with_deadline", fake_adapter)

    rc = runner.run_targets(
        project,
        tmp_path / "results",
        ["vandal", "mythril"],
        primary_tool="vandal",
        compilation_bundle=bundle,
        write_lakes_output=False,
    )

    assert rc == 0
    assert sorted(calls) == sorted([
        ("vandal", "Main.sol", "sol", True),
        ("mythril", "Main.sol", "sol", False),
        ("vandal", "Explicit.runtime", "runtime", False),
        ("mythril", "Explicit.runtime", "runtime", False),
    ])
    assert explicit_runtime.read_text(encoding="utf-8") == "0x6002\n"


def test_vandal_bundle_route_preserves_runtime_mode_shape(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "Main.sol"
    target.write_text("pragma solidity ^0.8.20; contract Main {}", encoding="utf-8")
    bundle = _bundle(tmp_path, ["vandal"], target)
    smartbugs = tmp_path / "smartbugs"
    smartbugs.mkdir()
    monkeypatch.setattr(
        runner,
        "_compile_runtime_hex_for_vandal",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("Vandal private compiler must not run")
        ),
    )

    with runner.prepare_smartbugs_invocation(
        "vandal",
        target,
        tmp_path / "out",
        target_root=target,
        smartbugs_dir=smartbugs,
        timeout=10,
        input_kind="sol",
        compilation_bundle=bundle,
        logical_input_id="Main.sol",
    ) as invocation:
        runtime_path = Path(invocation.command[invocation.command.index("-f") + 1])
        assert runtime_path.name.endswith(".rt.hex")
        assert runtime_path.read_text(encoding="utf-8") == "6001"
        assert "--runtime" in invocation.command


def _load_smartian_module():
    path = Path(__file__).resolve().parents[1] / "docker" / "runners" / "run_smartian.py"
    spec = importlib.util.spec_from_file_location("lakes_shared_smartian_runner", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_smartian_bundle_route_preserves_engine_command_shape(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _load_smartian_module()
    target = tmp_path / "Main.sol"
    target.write_text("contract Main {}", encoding="utf-8")
    abi = tmp_path / "Main.abi.json"
    creation = tmp_path / "Main.bin"
    abi.write_text("[]", encoding="utf-8")
    creation.write_text("6000", encoding="utf-8")
    commands: list[list[str]] = []
    monkeypatch.setattr(
        module,
        "_compile_source",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("Smartian private compiler must not run")
        ),
    )

    def fake_stream(command, cwd=None):
        commands.append(command)
        return 0

    monkeypatch.setattr(module, "_stream_process", fake_stream)

    rc = module._run_one_contract(
        target,
        tmp_path,
        tmp_path / "out",
        tmp_path / "Smartian.dll",
        "dotnet",
        10,
        {},
        "solc",
        "bin",
        shared_abi=abi,
        shared_bytecode=creation,
        shared_contract_key="Main.sol:Main",
        shared_bundle_id="bundle-1",
        shared_compiler_version="0.8.24",
        shared_compiler_binary="/exact/solc-0.8.24",
    )

    assert rc == 0
    command = commands[0]
    assert command[:3] == ["dotnet", str(tmp_path / "Smartian.dll"), "fuzz"]
    assert command[command.index("-p") + 1] == str(creation)
    assert command[command.index("-a") + 1] == str(abi)
    report = json.loads((tmp_path / "out" / "result.json").read_text(encoding="utf-8"))
    assert report["parser"]["bundle_id"] == "bundle-1"



def test_smartian_preflight_accepts_a_dotnet_runtime_without_sdk(tmp_path, monkeypatch) -> None:
    module = _load_smartian_module()
    source = tmp_path / "Main.sol"
    source.write_text("contract Main {}")
    dll = tmp_path / "Smartian.dll"
    dll.write_bytes(b"fixture")
    abi = tmp_path / "Main.abi.json"
    abi.write_text("[]")
    bytecode = tmp_path / "Main.bin"
    bytecode.write_text("6000")
    probes = tmp_path / "runtime-probes.jsonl"
    runtime = tmp_path / "dotnet"
    runtime.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\nfrom pathlib import Path\n"
        f"with Path({str(probes)!r}).open('a') as output:\n"
        "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "supported = [['--info'], ['--list-runtimes'], ['--help']]\n"
        "raise SystemExit(0 if sys.argv[1:] in supported else 145)\n"
    )
    runtime.chmod(0o755)
    executions = []
    monkeypatch.setattr(module, "_run_one_contract", lambda **kwargs: executions.append(kwargs) or 0)
    monkeypatch.setattr(sys, "argv", [
        "run_smartian.py", str(source), str(tmp_path / "out"),
        "--smartian_dll", str(dll), "--dotnet", str(runtime),
        "--shared-abi", str(abi), "--shared-bytecode", str(bytecode),
    ])
    assert module.main() == 0
    assert probes.read_text().splitlines()
    assert len(executions) == 1
