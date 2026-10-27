from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from toolrank import runner


def _prepare_securify_run(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    securify_root = tmp_path / "securify2"
    securify_root.mkdir()
    securify_runner = securify_root / "securifyjson.py"
    securify_runner.write_text("# test runner\n", encoding="utf-8")
    (securify_root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    contract = tmp_path / "Token.sol"
    contract.write_text(
        "pragma solidity 0.5.4; contract Token {}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(runner, "SECURIFY2_RUNNER", securify_runner)
    monkeypatch.setattr(runner, "_SECURIFY2_IMAGE_CACHE", set())
    monkeypatch.setattr(runner.time, "sleep", lambda _seconds: None)
    return contract, tmp_path / "out"


def test_securify_existing_exact_image_skips_build(tmp_path: Path, monkeypatch) -> None:
    contract, out_dir = _prepare_securify_run(tmp_path, monkeypatch)
    inspected_images = []
    stream_calls = []

    def fake_run(command, **kwargs):
        inspected_images.append(command[command.index("inspect") + 1])
        return SimpleNamespace(returncode=0)

    def fake_stream(command, **kwargs):
        stream_calls.append(command)
        return 0

    def unexpected_build(*args, **kwargs):
        raise AssertionError("an existing analyzer image must be reused")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(runner, "_stream_process", fake_stream)
    monkeypatch.setattr(runner, "_run_securify2_build_process", unexpected_build)

    assert runner._run_securify2(contract, out_dir, target_root=contract) == 0
    assert runner._run_securify2(contract, out_dir, target_root=contract) == 0
    assert inspected_images == ["securify:0.5.4"]
    assert len(stream_calls) == 2
    for command in stream_calls:
        assert command[command.index("--image") + 1] == "securify:0.5.4"
    assert "securify:0.5.4" in runner._SECURIFY2_IMAGE_CACHE


def test_securify_transient_inspect_failure_then_success_skips_build(
    tmp_path: Path,
    monkeypatch,
) -> None:
    contract, out_dir = _prepare_securify_run(tmp_path, monkeypatch)
    inspect_results = iter(
        [
            SimpleNamespace(
                returncode=1,
                stderr="Error response from daemon: context deadline exceeded",
            ),
            SimpleNamespace(returncode=0, stderr=""),
        ]
    )
    inspect_calls: list[list[str]] = []
    build_calls: list[list[str]] = []
    stream_calls: list[list[str]] = []
    sleep_calls: list[float] = []

    def fake_run(command, **kwargs):
        inspect_calls.append(command)
        return next(inspect_results)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(runner.time, "sleep", sleep_calls.append)
    monkeypatch.setattr(
        runner,
        "_run_securify2_build_process",
        lambda command, **kwargs: build_calls.append(command) or 0,
    )
    monkeypatch.setattr(
        runner,
        "_stream_process",
        lambda command, **kwargs: stream_calls.append(command) or 0,
    )

    rc = runner._run_securify2(contract, out_dir, target_root=contract)

    assert rc == 0
    assert inspect_calls == [
        ["docker", "image", "inspect", "securify:0.5.4"],
        ["docker", "image", "inspect", "securify:0.5.4"],
    ]
    assert len(sleep_calls) == 1
    assert sleep_calls[0] <= runner._SECURIFY2_IMAGE_INSPECT_MAX_BACKOFF_SECONDS
    assert build_calls == []
    assert len(stream_calls) == 1
    assert "securify:0.5.4" in runner._SECURIFY2_IMAGE_CACHE


def test_securify_missing_then_existing_image_skips_build(
    tmp_path: Path,
    monkeypatch,
) -> None:
    contract, out_dir = _prepare_securify_run(tmp_path, monkeypatch)
    inspect_results = iter(
        [
            SimpleNamespace(
                returncode=1,
                stderr="Error response from daemon: No such image: securify:0.5.4",
            ),
            SimpleNamespace(returncode=0, stderr=""),
        ]
    )
    inspect_calls: list[list[str]] = []
    build_calls: list[list[str]] = []
    stream_calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        inspect_calls.append(command)
        return next(inspect_results)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(
        runner,
        "_run_securify2_build_process",
        lambda command, **kwargs: build_calls.append(command) or 0,
    )
    monkeypatch.setattr(
        runner,
        "_stream_process",
        lambda command, **kwargs: stream_calls.append(command) or 0,
    )

    rc = runner._run_securify2(contract, out_dir, target_root=contract)

    assert rc == 0
    assert inspect_calls == [
        ["docker", "image", "inspect", "securify:0.5.4"],
        ["docker", "image", "inspect", "securify:0.5.4"],
    ]
    assert build_calls == []
    assert len(stream_calls) == 1
    assert "securify:0.5.4" in runner._SECURIFY2_IMAGE_CACHE


def test_securify_repeated_missing_exact_image_builds_then_executes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    contract, out_dir = _prepare_securify_run(tmp_path, monkeypatch)
    inspect_calls: list[list[str]] = []
    build_calls: list[list[str]] = []
    stream_calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        inspect_calls.append(command)
        return SimpleNamespace(
            returncode=1,
            stderr="Error response from daemon: No such image: securify:0.5.4",
        )

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    def fake_stream(command, **kwargs):
        stream_calls.append(command)
        return 0

    def fake_build(command, **kwargs):
        build_calls.append(command)
        return 0

    monkeypatch.setattr(runner, "_stream_process", fake_stream)
    monkeypatch.setattr(runner, "_run_securify2_build_process", fake_build)

    rc = runner._run_securify2(contract, out_dir, target_root=contract)

    assert rc == 0
    assert inspect_calls == [
        ["docker", "image", "inspect", "securify:0.5.4"]
    ] * runner._SECURIFY2_IMAGE_INSPECT_ATTEMPTS
    assert build_calls == [[
        "docker",
        "build",
        "--platform",
        runner.SECURIFY2_PLATFORM,
        "--build-arg",
        "SOLC=0.5.4",
        "-t",
        "securify:0.5.4",
        ".",
    ]]
    assert len(stream_calls) == 1
    assert stream_calls[0][0:2] == ["python3", str(runner.SECURIFY2_RUNNER)]
    assert "securify:0.5.4" in runner._SECURIFY2_IMAGE_CACHE


def test_securify_failed_build_is_not_cached_or_executed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    contract, out_dir = _prepare_securify_run(tmp_path, monkeypatch)
    inspect_calls: list[list[str]] = []
    build_calls: list[list[str]] = []
    stream_calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        inspect_calls.append(command)
        return SimpleNamespace(
            returncode=1,
            stderr="Error response from daemon: No such image: securify:0.5.4",
        )

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    def fake_build(command, **kwargs):
        build_calls.append(command)
        return 17

    monkeypatch.setattr(
        runner,
        "_stream_process",
        lambda command, **kwargs: stream_calls.append(command) or 0,
    )
    monkeypatch.setattr(runner, "_run_securify2_build_process", fake_build)

    rc = runner._run_securify2(contract, out_dir, target_root=contract)

    assert rc == 17
    assert inspect_calls == [
        ["docker", "image", "inspect", "securify:0.5.4"]
    ] * runner._SECURIFY2_IMAGE_INSPECT_ATTEMPTS
    assert len(build_calls) == 1
    assert build_calls[0][0:3] == ["docker", "build", "--platform"]
    assert stream_calls == []
    assert "securify:0.5.4" not in runner._SECURIFY2_IMAGE_CACHE
    assert not out_dir.exists()


def test_securify_persistent_ambiguous_inspect_failure_fails_closed(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    contract, out_dir = _prepare_securify_run(tmp_path, monkeypatch)
    inspect_calls: list[list[str]] = []
    build_calls: list[list[str]] = []
    stream_calls: list[list[str]] = []
    secret = "inspect-secret-must-not-leak"

    def fake_run(command, **kwargs):
        inspect_calls.append(command)
        return SimpleNamespace(
            returncode=1,
            stderr=f"Cannot connect to the Docker daemon; token={secret}",
        )

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(runner.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        runner,
        "_run_securify2_build_process",
        lambda command, **kwargs: build_calls.append(command) or 0,
    )
    monkeypatch.setattr(
        runner,
        "_stream_process",
        lambda command, **kwargs: stream_calls.append(command) or 0,
    )

    rc = runner._run_securify2(contract, out_dir, target_root=contract)

    assert rc != 0
    assert len(inspect_calls) == runner._SECURIFY2_IMAGE_INSPECT_ATTEMPTS
    assert build_calls == []
    assert stream_calls == []
    assert "securify:0.5.4" not in runner._SECURIFY2_IMAGE_CACHE
    assert not out_dir.exists()
    diagnostic = capsys.readouterr().err
    assert "refusing to build" in diagnostic
    assert secret not in diagnostic


def test_securify_missing_docker_executable_fails_closed(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    contract, out_dir = _prepare_securify_run(tmp_path, monkeypatch)
    stream_calls: list[list[str]] = []

    def missing_docker(command, **kwargs):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(runner.subprocess, "run", missing_docker)
    monkeypatch.setattr(
        runner,
        "_stream_process",
        lambda command, **kwargs: stream_calls.append(command) or 0,
    )

    rc = runner._run_securify2(contract, out_dir, target_root=contract)

    assert rc != 0
    assert stream_calls == []
    assert "securify:0.5.4" not in runner._SECURIFY2_IMAGE_CACHE
    assert not out_dir.exists()
    assert "docker executable unavailable" in capsys.readouterr().err


def test_securify_missing_dockerfile_is_not_cached_or_executed(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    contract, out_dir = _prepare_securify_run(tmp_path, monkeypatch)
    (runner.SECURIFY2_RUNNER.parent / "Dockerfile").unlink()
    build_calls: list[list[str]] = []
    stream_calls: list[list[str]] = []

    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=1,
            stderr="Error response from daemon: No such image: securify:0.5.4",
        ),
    )
    monkeypatch.setattr(
        runner,
        "_run_securify2_build_process",
        lambda command, **kwargs: build_calls.append(command) or 0,
    )
    monkeypatch.setattr(
        runner,
        "_stream_process",
        lambda command, **kwargs: stream_calls.append(command) or 0,
    )

    rc = runner._run_securify2(contract, out_dir, target_root=contract)

    assert rc != 0
    assert build_calls == []
    assert stream_calls == []
    assert "securify:0.5.4" not in runner._SECURIFY2_IMAGE_CACHE
    assert not out_dir.exists()
    assert "Dockerfile not found" in capsys.readouterr().err


def test_securify_build_launch_failure_is_not_cached_or_executed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    contract, out_dir = _prepare_securify_run(tmp_path, monkeypatch)
    stream_calls: list[list[str]] = []

    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=1,
            stderr="Error response from daemon: No such image: securify:0.5.4",
        ),
    )
    monkeypatch.setattr(
        runner.subprocess,
        "Popen",
        lambda command, **kwargs: (_ for _ in ()).throw(FileNotFoundError(command[0])),
    )
    monkeypatch.setattr(
        runner,
        "_stream_process",
        lambda command, **kwargs: stream_calls.append(command) or 0,
    )

    rc = runner._run_securify2(contract, out_dir, target_root=contract)

    assert rc != 0
    assert stream_calls == []
    assert "securify:0.5.4" not in runner._SECURIFY2_IMAGE_CACHE
    assert not out_dir.exists()


def test_securify_build_capture_does_not_wait_for_descendant_stdout(
    tmp_path: Path,
    capsys,
) -> None:
    release = tmp_path / "release-descendant"
    descendant = (
        "import pathlib, time; "
        f"release = pathlib.Path({str(release)!r}); "
        "deadline = time.monotonic() + 3.0; "
        "\nwhile not release.exists() and time.monotonic() < deadline: "
        "time.sleep(0.01)"
    )
    direct_child = (
        "import subprocess, sys; "
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}]); "
        "print('direct build secret', flush=True)"
    )

    started = time.monotonic()
    try:
        rc = runner._run_securify2_build_process(
            [sys.executable, "-c", direct_child],
            cwd=tmp_path,
            env=os.environ.copy(),
            display_command=["docker", "build", "..."],
            redactions=["secret"],
        )
    finally:
        release.touch()
    elapsed = time.monotonic() - started

    assert rc == 0
    assert elapsed < 1.0
    rendered = capsys.readouterr().out
    assert "direct build ***" in rendered
    assert "secret" not in rendered


def test_securify_build_process_inherits_the_outer_process_group(
    tmp_path: Path,
    monkeypatch,
) -> None:
    popen_kwargs: dict[str, object] = {}

    class CompletedProcess:
        def wait(self) -> int:
            return 0

    def fake_popen(command, **kwargs):
        popen_kwargs.update(kwargs)
        return CompletedProcess()

    monkeypatch.setattr(runner.subprocess, "Popen", fake_popen)

    rc = runner._run_securify2_build_process(
        ["docker", "build", "."],
        cwd=tmp_path,
        env=os.environ.copy(),
    )

    assert rc == 0
    assert popen_kwargs.get("start_new_session", False) is False
