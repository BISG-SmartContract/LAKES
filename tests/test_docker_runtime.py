from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

import pytest

from toolrank import docker_runtime as runtime
from toolrank import process_deadline, runner


ROOT = Path(__file__).resolve().parents[1]
SMARTBUGS = ROOT / "tests/fixtures/smartbugs_spawn"


@pytest.fixture
def external(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setenv("LAKES_DOCKER_MODE", "external")
    monkeypatch.setenv("DOCKER_HOST", "unix:///run/lakes-runtime/docker.sock")
    monkeypatch.setenv("LAKES_SHARED_ROOT", str(shared))
    monkeypatch.setenv("LAKES_JOB_ID", "job-a")
    monkeypatch.setenv("LAKES_DOCKER_CPUS", "1.5")
    monkeypatch.setenv("LAKES_DOCKER_MEMORY", "512m")
    monkeypatch.delenv("LAKES_DOCKER_ATTEMPT", raising=False)
    monkeypatch.setenv("TMPDIR", tempfile.gettempdir())
    monkeypatch.setattr(tempfile, "tempdir", tempfile.gettempdir())
    return shared, shared / "job-a"


def test_standalone_mode_does_not_change_commands_or_temporary_directory(monkeypatch):
    monkeypatch.setenv("LAKES_DOCKER_MODE", "auto")
    before = tempfile.gettempdir()
    args = {"image": "analyzer", "cpu_quota": 20000}
    assert runtime.configure("/any/path") is None
    assert runtime.container_args(args, "slither") is args
    assert runtime.cli_args("slither") == []
    assert runtime.process_env(None) is None
    assert tempfile.gettempdir() == before


@pytest.mark.parametrize("name,value", [
    ("LAKES_DOCKER_MODE", "typo"), ("DOCKER_HOST", ""),
    ("LAKES_JOB_ID", "../other"), ("LAKES_JOB_ID", ""),
    ("LAKES_JOB_ID", "a" * 129), ("LAKES_SHARED_ROOT", "/"),
    ("LAKES_SHARED_ROOT", "relative"), ("LAKES_DOCKER_CPUS", "NaN"),
    ("LAKES_DOCKER_CPUS", "-1"), ("LAKES_DOCKER_CPUS", "Infinity"),
    ("LAKES_DOCKER_CPUS", "0.0001"), ("LAKES_DOCKER_MEMORY", "1m"),
    ("LAKES_DOCKER_MEMORY", "-1g"), ("LAKES_DOCKER_MEMORY", "garbage"),
])
def test_invalid_external_contract_fails_before_work(external, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        runtime.configure()


def test_temporary_files_are_per_job_and_inputs_cannot_escape(external, tmp_path):
    shared, job = external
    runtime.configure(job / "input", job / "output")
    with tempfile.TemporaryDirectory() as temporary:
        assert Path(temporary).is_relative_to(job / "tmp")
    with pytest.raises(ValueError, match="inputs and results"):
        runtime.configure(shared / "job-b/input")
    link = job / "input"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="inputs and results"):
        runtime.configure(link / "Contract.sol")
    with pytest.raises(ValueError, match="bind source"):
        runtime.shared_path(tmp_path / "compiler")


def test_worker_local_compiler_is_staged_for_daemon_bind_mount(external, tmp_path):
    _, job = external
    compiler = tmp_path / "solc"
    compiler.write_bytes(b"complete compiler")
    compiler.chmod(0o755)
    staged = Path(runtime.stage_bind_file(compiler))
    assert staged.is_relative_to(job / "tmp")
    assert staged.read_bytes() == compiler.read_bytes()
    assert staged.stat().st_mode & 0o111
    assert compiler.exists()
    assert Path(runtime.stage_bind_file(compiler)) == staged
    compiler.write_bytes(b"updated compiler")
    updated = Path(runtime.stage_bind_file(compiler))
    assert updated != staged and updated.read_bytes() == b"updated compiler"


def test_sdk_and_cli_carry_job_scope_and_resource_caps(external, monkeypatch):
    _, job = external
    monkeypatch.setenv("LAKES_DOCKER_ATTEMPT", "attempt-a")
    args = runtime.container_args({
        "labels": {"existing": "kept"},
        "volumes": {str(job / "tmp/workspace"): {"bind": "/sb", "mode": "rw"}},
        "cpu_quota": 50000, "cpu_period": 200000, "mem_limit": "128m",
    }, "slither")
    assert args["labels"] == {
        "existing": "kept", runtime.JOB_LABEL: "job-a",
        runtime.TOOL_LABEL: "slither", runtime.ATTEMPT_LABEL: "attempt-a",
    }
    assert args["cpu_period"] == 100000 and args["cpu_quota"] == 25000
    assert args["mem_limit"] == 128 * 1024**2
    flags = runtime.cli_args("sailfish")
    assert f"{runtime.JOB_LABEL}=job-a" in flags
    assert f"{runtime.ATTEMPT_LABEL}=attempt-a" in flags
    assert flags[flags.index("--cpu-quota") + 1] == "150000"
    assert flags[flags.index("--memory") + 1] == str(512 * 1024**2)


@pytest.mark.parametrize("kind", ["sol", "bytecode", "runtime"])
def test_real_smartbugs_spawn_worker_receives_scope_for_every_input_kind(external, kind):
    _, job = external
    project = job / "input"
    project.mkdir(parents=True)
    target = project / ("Main.sol" if kind == "sol" else "Main.hex")
    target.write_text("pragma solidity ^0.8.0; contract Main {}" if kind == "sol" else "6000")
    output = job / "output"
    with runner.prepare_smartbugs_invocation(
        "slither" if kind == "sol" else "mythril", target, output,
        target_root=project, smartbugs_dir=SMARTBUGS, timeout=7, input_kind=kind,
    ) as invocation:
        completed = subprocess.run(
            invocation.command, cwd=invocation.cwd, env=invocation.env,
            capture_output=True, text=True, timeout=20,
        )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    probe = json.loads((output / "result.json").read_text())["probe"]
    assert probe["start_method"] == "spawn"
    args = probe["docker_args"]
    assert args["labels"][runtime.JOB_LABEL] == "job-a"
    assert args["labels"][runtime.TOOL_LABEL] == ("slither" if kind == "sol" else "mythril")
    assert args["cpu_quota"] == 150000
    assert args["mem_limit"] == 512 * 1024**2
    assert all(Path(path).is_relative_to(job / "tmp") for path in args["volumes"])


def test_process_timeout_cleanup_uses_the_same_attempt_as_child(external, monkeypatch):
    captured = []

    def fake_process(command, **kwargs):
        captured.append(dict(kwargs["env"]))
        return process_deadline.DeadlineProcessResult(returncode=124, timed_out=True)

    monkeypatch.setattr(process_deadline, "_run_process_with_deadline", fake_process)
    monkeypatch.setattr(runtime, "cleanup", lambda env: captured.append(dict(env)))
    result = process_deadline.run_process_with_deadline(["worker"], timeout_seconds=1)
    assert result.returncode == 124 and result.timed_out
    assert captured[0]["LAKES_DOCKER_ATTEMPT"] == captured[1]["LAKES_DOCKER_ATTEMPT"]
    assert len(captured[0]["LAKES_DOCKER_ATTEMPT"]) == 32
    assert captured[0]["TMPDIR"].endswith("/job-a/tmp")


@pytest.mark.parametrize("returncode,timed_out", [(0, False), (7, False), (124, True)])
def test_cleanup_failure_cannot_hide_original_failure_or_publish_success(
    external, monkeypatch, returncode, timed_out,
):
    monkeypatch.setattr(process_deadline, "_run_process_with_deadline", lambda *a, **kw:
                        process_deadline.DeadlineProcessResult(returncode=returncode, timed_out=timed_out))

    def unavailable(_env):
        raise RuntimeError("runtime cleanup unavailable")

    monkeypatch.setattr(runtime, "cleanup", unavailable)
    result = process_deadline.run_process_with_deadline(["worker"], timeout_seconds=1)
    assert result.returncode == (returncode or 1)
    assert result.timed_out == timed_out
    assert "cleanup unavailable" in result.stderr


def test_cleanup_filters_both_job_and_attempt_and_rechecks_removal(external, monkeypatch):
    env = dict(runtime.process_env(None))
    env["LAKES_DOCKER_ATTEMPT"] = "attempt-a"
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(command, 0, "abcdef012345\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(runtime.subprocess, "run", fake_run)
    runtime.cleanup(env)
    for command in (calls[0], calls[2]):
        assert f"label={runtime.JOB_LABEL}=job-a" in command
        assert f"label={runtime.ATTEMPT_LABEL}=attempt-a" in command
    assert calls[1] == ["docker", "rm", "--force", "abcdef012345"]
    assert all("prune" not in command for command in calls)


def test_cleanup_failure_keeps_uncertain_containers_visible(external, monkeypatch):
    env = runtime.process_env(None)
    monkeypatch.setattr(runtime.subprocess, "run", lambda command, **kwargs:
                        subprocess.CompletedProcess(command, 0, "abcdef012345\n", ""))
    with pytest.raises(RuntimeError, match="incomplete"):
        runtime.cleanup(env)


def test_image_preparation_lock_serializes_different_job_processes(external):
    shared, _ = external
    events = shared / "events"
    code = (
        "import os,time; from toolrank.docker_runtime import image_lock; "
        f"p={str(events)!r}; "
        "\nwith image_lock('shared:tag'):\n"
        " with open(p,'a') as f:\n"
        "  f.write('enter '+os.environ['LAKES_JOB_ID']+'\\n'); f.flush()\n"
        "  time.sleep(.15)\n"
        "  f.write('exit '+os.environ['LAKES_JOB_ID']+'\\n')\n"
    )
    processes = [subprocess.Popen(
        [sys.executable, "-c", code], cwd=ROOT,
        env={**os.environ, "LAKES_JOB_ID": job}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) for job in ("job-a", "job-b")]
    for process in processes:
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stdout + stderr
    lines = events.read_text().splitlines()
    assert [line.split()[0] for line in lines] == ["enter", "exit", "enter", "exit"]
    assert lines[0].split()[1] == lines[1].split()[1]
    assert lines[2].split()[1] == lines[3].split()[1]


def test_shared_securify_builds_once_but_warm_analyses_run_concurrently(external, monkeypatch):
    _, job = external
    job.mkdir()
    contract = job / "Main.sol"
    contract.write_text("pragma solidity ^0.5.4; contract Main {}")
    adapter = job / "securifyjson.py"
    adapter.touch()
    (job / "Dockerfile").touch()
    monkeypatch.setattr(runner, "SECURIFY2_RUNNER", adapter)
    monkeypatch.setattr(runner, "_SECURIFY2_IMAGE_CACHE", set())
    monkeypatch.setattr(runner, "_solc_lower_bound", lambda *a, **kw: "0.5.4")
    builds = []
    monkeypatch.setattr(runner, "_inspect_docker_image", lambda _image: "exists" if builds else "missing")

    def build(*args, **kwargs):
        builds.append(True)
        return 0

    barrier = threading.Barrier(2)
    monkeypatch.setattr(runner, "_run_securify2_build_process", build)

    def analyze(*args, **kwargs):
        barrier.wait(timeout=5)
        return 0

    monkeypatch.setattr(runner, "_stream_process", analyze)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(runner._run_securify2, contract, job / str(i), target_root=job) for i in range(2)]
        assert [future.result(timeout=10) for future in futures] == [0, 0]
    assert len(builds) == 1


def _adapter(relative):
    name = "test_shared_" + Path(relative).stem
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sailfish_stages_compiler_and_passes_job_and_resource_flags(external, tmp_path, monkeypatch):
    _, job = external
    source = job / "input"
    source.mkdir(parents=True)
    (source / "Main.sol").write_text("contract Main {}")
    compiler = tmp_path / "worker-only-solc"
    compiler.write_bytes(b"compiler")
    compiler.chmod(0o755)
    adapter = _adapter("docker/runners/run_sailfish.py")
    monkeypatch.setattr(adapter, "_discover_local_solc_bins", lambda: {})
    monkeypatch.setattr(adapter, "_select_local_solc_bin", lambda *a: (compiler, "0.5.4", "test"))
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    adapter.run_sailfish(source, "Main.sol", "0.5.4", artifacts_root=job / "output")
    command = calls[-1]
    assert f"{runtime.JOB_LABEL}=job-a" in command
    assert "--cpu-quota" in command and "--memory" in command
    bind = next(value for value in command if value.endswith(":/tmp/host_solc:ro"))
    staged = Path(bind.split(":", 1)[0])
    assert staged.is_relative_to(job / "tmp") and staged.read_bytes() == b"compiler"


def test_securify_cli_carries_job_and_resource_flags(external, monkeypatch):
    _, job = external
    source = job / "input"
    source.mkdir(parents=True)
    contract = source / "Main.sol"
    contract.write_text("contract Main {}")
    adapter = _adapter("docker/vendor/securify2/securifyjson.py")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    rc, *_ = adapter.run_securify_docker(str(contract), str(source), "securify:0.5.4", None, "docker", False, False)
    assert rc == 0
    assert f"{runtime.JOB_LABEL}=job-a" in calls[0]
    assert f"{source}:/share" in calls[0]
    assert "--cpu-quota" in calls[0] and "--memory" in calls[0]


@pytest.mark.parametrize("available", [False, True])
def test_external_entrypoint_never_starts_local_daemon(external, tmp_path, available):
    executable_root = tmp_path / "bin"
    executable_root.mkdir()
    daemon_marker = tmp_path / "unexpected-daemon"
    fake_docker = executable_root / "docker"
    fake_docker.write_text("#!/bin/sh\nexit " + ("0" if available else "1") + "\n")
    fake_docker.chmod(0o755)
    fake_daemon = executable_root / "dockerd"
    fake_daemon.write_text(f"#!/bin/sh\ntouch {daemon_marker}\n")
    fake_daemon.chmod(0o755)
    fake_lakes = executable_root / "lakes"
    fake_lakes.write_text("#!/bin/sh\nprintf 'lakes-started\\n'\n")
    fake_lakes.chmod(0o755)
    fake_python = executable_root / "python"
    fake_python.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    fake_python.chmod(0o755)
    completed = subprocess.run(
        ["bash", str(ROOT / "docker/entrypoint.sh"), "--help"],
        env={**os.environ, "PATH": str(executable_root) + os.pathsep + os.environ["PATH"], "PYTHONPATH": str(ROOT)},
        capture_output=True, text=True, timeout=10,
    )
    assert completed.returncode == (0 if available else 1), completed.stderr
    assert ("lakes-started" in completed.stdout) == available
    assert not daemon_marker.exists()


def test_runtime_command_rejects_external_worker_mode(external):
    result = subprocess.run(
        ["bash", str(ROOT / "docker/entrypoint.sh"), "runtime"],
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 2
    assert "external mode is for workers" in result.stderr


def test_auto_entrypoint_preserves_lakes_arguments(tmp_path, monkeypatch):
    monkeypatch.setenv("LAKES_DOCKER_MODE", "auto")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n")
    docker.chmod(0o755)
    lakes = binaries / "lakes"
    lakes.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    lakes.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "docker/entrypoint.sh"), "recommend", "Contract with spaces.sol", "--emit", "json"],
        env={**os.environ, "PATH": str(binaries) + os.pathsep + os.environ["PATH"]},
        capture_output=True, text=True, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["recommend", "Contract with spaces.sol", "--emit", "json"]
