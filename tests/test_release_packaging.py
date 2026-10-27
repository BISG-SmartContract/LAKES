from __future__ import annotations

import configparser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shlex
import shutil
import subprocess
import sys
import zipfile
import xml.etree.ElementTree as ET

import pytest
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

from tests.release_helpers import (
    bind_mounts,
    docker_copy,
    docker_instructions,
    documented_docker_runs,
    host_path,
    option_value,
)
from toolrank.report_validity import atomic_write_text, canonical_contract_output_dir


ROOT = Path(__file__).resolve().parents[1]


def _python_with_wheel_backend() -> str:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import setuptools.build_meta, wheel",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "wheel regression requires setuptools and wheel in the test environment: "
        + result.stderr
    )
    return sys.executable


def test_fresh_wheel_contains_default_toolcards_and_cli_resolves_them(
    tmp_path: Path,
) -> None:
    build_python = _python_with_wheel_backend()
    source_root = tmp_path / "source"
    source_root.mkdir()
    for filename in ("pyproject.toml", "README.md"):
        shutil.copy2(ROOT / filename, source_root / filename)
    for package in ("toolrank", "toolcards"):
        shutil.copytree(
            ROOT / package,
            source_root / package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".private"),
        )
    private_payloads = {
        "performance_db.json": "PRIVATE_PERFORMANCE_SENTINEL",
        "contract_profiles.json": "PRIVATE_PROFILE_SENTINEL",
        "passage_store.json": "PRIVATE_PASSAGE_SENTINEL",
        "vector_index/index.json": "PRIVATE_VECTOR_SENTINEL",
        "recovery_source.json": "PRIVATE_RECOVERY_SENTINEL",
        "credentials.json": "PRIVATE_CREDENTIAL_SENTINEL",
    }
    for relative_path, sentinel in private_payloads.items():
        private_path = source_root / "toolcards" / ".private" / relative_path
        private_path.parent.mkdir(parents=True, exist_ok=True)
        private_path.write_text(sentinel, encoding="utf-8")
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    build = subprocess.run(
        [
            build_python,
            "-c",
            (
                "import pathlib, setuptools.build_meta as backend, sys; "
                "print(backend.build_wheel(str(pathlib.Path(sys.argv[1]).resolve())))"
            ),
            str(wheel_dir),
        ],
        cwd=source_root,
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, build.stdout + build.stderr

    wheels = list(wheel_dir.glob("lakes-*.whl"))
    assert len(wheels) == 1
    expected_toolcard_files = {
        "toolcards/__init__.py",
        "toolcards/vector_index/index.json",
    } | {
        f"toolcards/{path.name}" for path in (ROOT / "toolcards").glob("*.json")
    }
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        entry_points = configparser.ConfigParser()
        entry_points_path = next(name for name in names if name.endswith(".dist-info/entry_points.txt"))
        entry_points.read_string(archive.read(entry_points_path).decode())
        assert "lakes-profile-builder" in entry_points["console_scripts"]
        packaged_toolcard_files = {
            name
            for name in names
            if name.startswith("toolcards/") and not name.endswith("/")
        }
        assert packaged_toolcard_files == expected_toolcard_files
        archive_payload = b"".join(
            archive.read(name) for name in sorted(names) if not name.endswith("/")
        )
        for sentinel in private_payloads.values():
            assert sentinel.encode("utf-8") not in archive_payload

        installed = tmp_path / "installed"
        archive.extractall(installed)

    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                "from toolrank.cli import _DEFAULT_TOOLCARDS_DIR; "
                "root=Path(_DEFAULT_TOOLCARDS_DIR); "
                "assert root.resolve() == Path(__import__('toolcards').__file__).parent.resolve(); "
                "assert (root/'performance_db.json').is_file(); "
                "assert (root/'contract_profiles.json').is_file(); "
                "assert (root/'contract_profile_manifest.json').is_file(); "
                "assert (root/'passage_store.json').is_file(); "
                "assert (root/'vector_index'/'index.json').is_file(); "
                "import importlib.metadata as metadata; import sys; "
                "distribution = next(dist for dist in metadata.distributions(path=[str(root.parent)]) "
                "if dist.metadata['Name'] == 'lakes'); "
                "entry_point = next(ep for ep in distribution.entry_points "
                "if ep.group == 'console_scripts' and ep.name == 'lakes-profile-builder'); "
                "sys.argv = [entry_point.name, '--help']; entry_point.load()()"
            ),
        ],
        cwd=tmp_path,
        env={
            **os.environ,
            "PYTHONPATH": str(installed),
        },
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    for option in ("--corpus-root", "--manifest", "--output"):
        assert option in probe.stdout


def test_fresh_tracked_checkout_execute_publishes_one_canonical_tree(
    tmp_path: Path,
) -> None:
    fresh = tmp_path / "fresh-checkout"
    fresh.mkdir()
    tracked = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode().split("\0")
    target_relative = Path(
        "docker/vendor/securify2/securify/staticanalysis/testContract.sol"
    )
    for raw_relative in tracked:
        if not raw_relative:
            continue
        relative = Path(raw_relative)
        if not (
            relative.parts[0] in {"toolrank", "toolcards"}
            or relative == target_relative
        ):
            continue
        source = ROOT / relative
        if not source.is_file():
            continue
        destination = fresh / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            r'''
import json
import os
import sys
from pathlib import Path

from typer.testing import CliRunner

import toolcards
import toolrank
from toolrank import contract_profile, engine, execution
from toolrank.cli import _DEFAULT_TOOLCARDS_DIR, app
from toolrank.schemas import ContractFeatures, ToolExecutionStatus

fresh = Path.cwd()
target = fresh / "docker/vendor/securify2/securify/staticanalysis/testContract.sol"
results_root = fresh / "demo-output"
run_dir = results_root / "LAKES_out" / "testContract"
run_dir.mkdir(parents=True)
for filename in (
    "fusion_plan.json",
    "execution.json",
    "tool_run_statuses.json",
    "fused_report.json",
):
    (run_dir / filename).write_text(
        json.dumps({"stale_sentinel": filename}),
        encoding="utf-8",
    )

assert not (fresh / "toolcards/.private").exists()
assert target.is_file()
assert Path(toolrank.__file__).resolve().is_relative_to(fresh.resolve())
assert Path(toolcards.__file__).resolve().is_relative_to(fresh.resolve())
assert Path(_DEFAULT_TOOLCARDS_DIR).resolve() == (fresh / "toolcards").resolve()

raw_root = run_dir / "raw"
for card_path in (fresh / "toolcards").glob("*.json"):
    try:
        card = json.loads(card_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        continue
    tool_id = str(card.get("tool_id") or "").strip().lower()
    if not tool_id:
        continue
    stale = raw_root / tool_id / "result.json"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "name": "stale-sentinel",
                        "filename": "Old.sol",
                        "line": 99,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

contract_profile.analyze_target = lambda _path: ContractFeatures(
    target_path=str(target),
    source_kind="sol",
    present_input_kinds=["sol"],
    solidity_versions=["0.5.4"],
    solidity_version_constraints=["^0.5.4"],
    primary_solidity_version="0.5.4",
    gower_solc_bucket="0.5.x",
    gower_ast_available=True,
    loc_total=19,
    function_count=2,
    file_count=1,
    execution_input_count=1,
    contract_count=1,
    cyclomatic_avg=1.0,
    cyclomatic_max=1,
    cyclomatic_sum=3,
)
engine.load_openai_client = lambda: None

def fake_stream(command, **_kwargs):
    assert command[0] == sys.executable
    assert Path(command[1]).resolve().is_relative_to(fresh.resolve())
    current_raw = Path(command[3])
    assert current_raw.resolve() == raw_root.resolve()
    selected = command[command.index("--tools") + 1].split(",")
    statuses = {}
    for tool in selected:
        report = current_raw / tool / "result.json"
        assert not report.exists(), f"stale report survived: {report}"
        finding = {
            "name": "tx-origin",
            "category": "access_control",
            "filename": target.name,
            "line": 7,
        }
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
        statuses[tool] = ToolExecutionStatus(
            status="SUCCESS",
            return_code=0,
            runtime_minutes=0.01,
        ).model_dump(mode="json")
    (current_raw / "tool_run_statuses.json").write_text(
        json.dumps(statuses),
        encoding="utf-8",
    )
    return 0, "fresh isolated runner\n", None

execution._stream_runner_output = fake_stream

response = CliRunner().invoke(
    app,
    [
        "recommend",
        str(target),
        "--execute",
        "--emit",
        "summary",
        "--no-retrieval",
        "--no-checker",
        "--results-root",
        str(results_root),
    ],
)
assert response.exit_code == 0, (response.stdout, response.exception)
assert "status: EXECUTED" in response.stdout
assert f"LAKES_out: {run_dir / 'fused_report.json'}" in response.stdout
expected = {
    "fusion_plan.json",
    "execution.json",
    "tool_run_statuses.json",
    "fused_report.json",
}
assert {path.name for path in run_dir.iterdir() if path.is_file()} == expected
for filename in expected:
    payload = json.loads((run_dir / filename).read_text(encoding="utf-8"))
    assert "stale_sentinel" not in payload
    visible = [
        path.resolve()
        for path in fresh.rglob(filename)
        if "raw" not in path.relative_to(fresh).parts
    ]
    assert visible == [(run_dir / filename).resolve()]
assert [path.resolve() for path in fresh.rglob("LAKES_out") if path.is_dir()] == [
    (results_root / "LAKES_out").resolve()
]
fused = (run_dir / "fused_report.json").read_text(encoding="utf-8")
assert "tx-origin" in fused
assert "stale_sentinel" not in fused
assert "Old.sol" not in fused
''',
        ],
        cwd=fresh,
        env={
            **{
                key: value
                for key, value in os.environ.items()
                if key
                not in {
                    "DEEPSEEK_API_KEY",
                    "OPENAI_API_KEY",
                    "OPENAI_API_TOKEN",
                    "LAKES_TOOLCARDS_PRIVATE_DIR",
                }
            },
            "PYTHONPATH": str(fresh),
        },
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr


def test_readme_execution_publishes_to_writable_canonical_host_directory(tmp_path) -> None:
    workspace = tmp_path / "checkout with spaces"
    workspace.mkdir()
    runs = documented_docker_runs((ROOT / "README.md").read_text(), workspace)
    executions = [argv for argv in runs if "recommend" in argv and "--execute" in argv]
    assert executions, "README should demonstrate analyzer execution"
    for argv in executions:
        target = argv[argv.index("recommend") + 1]
        results_root = option_value(argv, "--results-root") or "/work/LAKES_out"
        mounts = bind_mounts(argv)
        container_output = canonical_contract_output_dir(results_root, target)
        output = host_path(container_output, mounts)
        expected = canonical_contract_output_dir(host_path(results_root, mounts), target)
        assert output == expected
        assert output.resolve().is_relative_to(workspace.resolve())
        assert output.resolve().relative_to(workspace.resolve()).parts.count("LAKES_out") == 1
        atomic_write_text(output / "fused_report.json", '{"findings": []}\n')
        assert json.loads((expected / "fused_report.json").read_text()) == {"findings": []}


def test_public_profile_artifacts_are_manifest_and_audit_digest_bound() -> None:
    manifest_path = ROOT / "toolcards" / "contract_profile_manifest.json"
    profile_path = ROOT / "toolcards" / "contract_profiles.json"
    audit_path = ROOT / "toolcards" / "contract_profiles_migration_audit.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))

    included_names = [
        row["name"] for row in manifest["datasets"] if row["include"]
    ]
    excluded_rows = [row for row in manifest["datasets"] if not row["include"]]
    assert all(row.get("duplicate_of") in included_names for row in excluded_rows)
    assert profile["_meta"]["dataset_names"] == included_names
    assert profile["_meta"]["manifest_digest"] == hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    assert audit["replay_provenance"]["rebuilt_artifact_sha256"] == (
        hashlib.sha256(profile_path.read_bytes()).hexdigest()
    )


def test_release_build_uses_immutable_dependency_revisions() -> None:
    instructions = docker_instructions((ROOT / "Dockerfile").read_text())
    defaults = dict(value.split("=", 1) for kind, value in instructions if kind == "ARG" and "=" in value)
    for name in ("SMARTIAN_REF", "SMARTBUGS_REF", "FALCON_REF"):
        values = shlex.split(defaults[name])
        assert len(values) == 1 and re.fullmatch(r"[0-9a-fA-F]{40}", values[0]), name


def test_release_smartian_artifacts_come_from_a_build_stage() -> None:
    instructions = docker_instructions((ROOT / "Dockerfile").read_text())
    stages = {}
    for kind, value in instructions:
        if kind == "FROM":
            words = shlex.split(value)
            if "AS" in [word.upper() for word in words]:
                index = next(i for i, word in enumerate(words) if word.upper() == "AS")
                stages[words[index + 1]] = words[:index]
    artifact_copies = []
    for kind, value in instructions:
        if kind != "COPY":
            continue
        options, paths = docker_copy(value)
        if "from" not in options:
            assert all(not PurePosixPath(source).is_absolute() for source in paths[:-1])
            assert not any(
                PurePosixPath(source).as_posix().rstrip("/").endswith("smartian/build")
                for source in paths[:-1]
            )
        if PurePosixPath(paths[-1]) == PurePosixPath("/work/docker/vendor/smartian/build"):
            artifact_copies.append((options, paths))
    assert artifact_copies
    for options, paths in artifact_copies:
        assert options.get("from") in stages
        stage = stages[options["from"]]
        platform = next(word.split("=", 1)[1] for word in stage if word.startswith("--platform="))
        assert platform.replace("${BUILDPLATFORM}", "$BUILDPLATFORM") == "$BUILDPLATFORM"
        assert PurePosixPath(paths[0]) == PurePosixPath("/work/docker/vendor/smartian/build")


def test_smartian_project_resolves_tracked_source_and_declared_dependencies() -> None:
    project = ROOT / "docker/vendor/smartian/src/Smartian.fsproj"
    tree = ET.parse(project)
    sources = [node.attrib["Include"] for node in tree.findall(".//Compile")]
    assert sources
    tracked = subprocess.run(
        ["git", "ls-files", "-z", "--", "docker/vendor/smartian"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split("\0")
    for source in sources:
        path = project.parent.joinpath(*PureWindowsPath(source).parts)
        assert path.is_file()
        assert path.relative_to(ROOT).as_posix() in tracked
    for dependency in ("nethermind", "EVMAnalysis"):
        assert not any(path.startswith(f"docker/vendor/smartian/{dependency}/") for path in tracked)
    references = {PureWindowsPath(node.attrib["Include"]).as_posix() for node in tree.findall(".//ProjectReference")}
    assert any(path.startswith("../nethermind/") for path in references)
    assert any(path.startswith("../EVMAnalysis/") for path in references)
    assert {PurePosixPath(path).name for path in references} >= {"Nethermind.Logging.csproj", "Nethermind.Store.csproj"}
    packages = {node.attrib["Include"]: node.attrib["Version"] for node in tree.findall(".//PackageReference")}
    assert "MathNet.Numerics.FSharp" in packages


def test_gptscan_dependencies_keep_compatible_version_constraints() -> None:
    lines = (ROOT / "docker/vendor/gptscan/requirements-docker.txt").read_text().splitlines()
    requirements = {}
    for line in lines:
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if line and not line.startswith("#"):
            item = Requirement(line)
            requirements[item.name.lower().replace("_", "-")] = item
    for name, version in (("z3-solver", "4.11.2.0"), ("crytic-compile", "0.3.3"), ("pysha3", "1.0.2")):
        assert requirements[name].specifier == SpecifierSet("==" + version)
    assert "falcon-analyzer" not in requirements


def test_private_and_generated_files_are_ignored_by_git() -> None:
    ignored = ["toolcards/.private/probe.json", "docker/vendor/smartian/build/probe.dll", "build/stale.whl"]
    public = ["toolcards/performance_db.json", "toolcards/passage_store.json", ".env.example"]
    result = subprocess.run(["git", "check-ignore", "--no-index", "--stdin"], cwd=ROOT,
                            input="\n".join(ignored + public) + "\n", capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert set(result.stdout.splitlines()) == set(ignored)
    tracked = subprocess.run(["git", "ls-files", "--", "toolcards/.private"], cwd=ROOT,
                             capture_output=True, text=True, check=True)
    assert not tracked.stdout.splitlines()


@pytest.mark.skipif(
    not os.environ.get("LAKES_TEST_RUNTIME_IMAGE"),
    reason="set LAKES_TEST_RUNTIME_IMAGE to a built image",
)
def test_release_image_runs_smartian_solc_and_falcon() -> None:
    script = r"""
from pathlib import Path
import subprocess
import sys

base = Path('/work/docker/vendor/smartian')
dll = base / 'build/Smartian.dll'
for artifact in (dll, base / 'src/Agent/AttackerContract.bin', base / 'src/Agent/SFuzzContract.bin'):
    assert artifact.stat().st_size > 0, artifact
runtime = subprocess.run(['dotnet', '--info'], capture_output=True, text=True, timeout=10)
assert runtime.returncode == 0, runtime.stdout + runtime.stderr
smartian = subprocess.run(['dotnet', str(dll)], capture_output=True, text=True, timeout=20)
assert 'Usage:' in smartian.stdout + smartian.stderr, smartian.stdout + smartian.stderr
solc = subprocess.run(['solc', '--version'], capture_output=True, text=True, timeout=10)
assert solc.returncode == 0, solc.stdout + solc.stderr
check = subprocess.run([
    '/work/docker/vendor/gptscan/.venv/bin/python', '-c',
    "import platform; from importlib.metadata import version; import z3; from falcon import Falcon; "
    "expected = '4.13.0.0' if platform.machine() == 'aarch64' else '4.11.2.0'; "
    "assert version('z3-solver') == expected"
], capture_output=True, text=True, timeout=15)
assert check.returncode == 0, check.stdout + check.stderr
"""
    result = subprocess.run([
        "docker", "run", "--rm", "--pull=never", "--network=none", "--entrypoint", "python",
        os.environ["LAKES_TEST_RUNTIME_IMAGE"], "-c", script,
    ], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(
    not os.environ.get("LAKES_TEST_RUNTIME_IMAGE"),
    reason="set LAKES_TEST_RUNTIME_IMAGE to enable Docker build-context checks",
)
def test_docker_build_context_excludes_private_and_generated_files(tmp_path) -> None:
    context = tmp_path / "context"
    context.mkdir()
    shutil.copy2(ROOT / ".dockerignore", context / ".dockerignore")
    public = ("public.json", "toolcards/performance_db.json", "toolcards/passage_store.json", ".env.example")
    ignored = (
        "toolcards/.private/credentials.json", "docker/vendor/smartian/build/stale.dll",
        "build/stale.whl", "runtime-jobs/job-a/input/Private.sol", ".env",
    )
    for relative in public + ignored:
        path = context / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative)
    exported = tmp_path / "exported"
    result = subprocess.run([
        "docker", "build", "--network=none", "--progress=plain",
        "--output", f"type=local,dest={exported}", "-f", "-", str(context),
    ], input="FROM scratch\nCOPY . /context/\n",
        env={**os.environ, "BUILDX_CONFIG": str(tmp_path / "buildx")},
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    for relative in public:
        assert (exported / "context" / relative).read_text() == relative
    for relative in ignored:
        assert not (exported / "context" / relative).exists(), relative
