from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from toolrank.smartbugs_solc import compiler_path_locked, download_verified_artifact, install_compiler_guards


class Response:
    def __init__(self, target: Path, interrupt=None):
        self.target = target
        self.interrupt = interrupt
        self.closed = False

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size):
        assert not self.target.exists()
        yield b"complete-"
        assert not self.target.exists()
        if self.interrupt:
            raise self.interrupt
        yield b"compiler"
        assert not self.target.exists()

    def close(self):
        self.closed = True


def _download(tmp_path, *, interrupt=None, checksum_failure=False):
    target = tmp_path / "solc-0.8.38"
    response = Response(target, interrupt)
    artifact = SimpleNamespace(file_path=target, download_url="https://example.invalid/compiler")

    def verify(called, handle):
        assert called is artifact
        assert not target.exists()
        handle.seek(0)
        assert handle.read() == b"complete-compiler"
        if checksum_failure:
            raise ValueError("checksum mismatch")

    manager = SimpleNamespace(
        session=SimpleNamespace(get=lambda *args, **kwargs: response), verify_checksum=verify,
    )
    return target, response, manager, artifact


def test_compiler_is_only_visible_after_checksum_verification(tmp_path) -> None:
    target, response, manager, artifact = _download(tmp_path)
    download_verified_artifact(manager, artifact)
    assert target.read_bytes() == b"complete-compiler"
    assert response.closed
    assert list(tmp_path.glob(".*.lakes-*")) == []


@pytest.mark.parametrize("failure", [OSError("connection reset"), KeyboardInterrupt()])
def test_interrupted_download_does_not_publish_a_partial_compiler(tmp_path, failure) -> None:
    target, response, manager, artifact = _download(tmp_path, interrupt=failure)
    with pytest.raises(type(failure)):
        download_verified_artifact(manager, artifact)
    assert not target.exists()
    assert response.closed
    assert list(tmp_path.glob(".*.lakes-*")) == []


def test_checksum_failure_does_not_publish_an_invalid_compiler(tmp_path) -> None:
    target, response, manager, artifact = _download(tmp_path, checksum_failure=True)
    with pytest.raises(ValueError, match="checksum mismatch"):
        download_verified_artifact(manager, artifact)
    assert not target.exists()
    assert response.closed
    assert list(tmp_path.glob(".*.lakes-*")) == []


def test_compiler_guards_are_idempotent_and_keep_null_version_semantics(tmp_path) -> None:
    calls = []
    module = SimpleNamespace(path=lambda version: calls.append(version) or version)
    artifact_manager = type("ArtifactManager", (), {})
    install_compiler_guards(module, tmp_path, artifact_manager)
    guarded = module.path
    install_compiler_guards(module, tmp_path, artifact_manager)
    assert module.path is guarded
    assert module.path(None) is None
    assert module.path("0.8.38") == "0.8.38"
    assert calls == [None, "0.8.38"]
    assert artifact_manager._download_artifact is download_verified_artifact


def _wait_for(path: Path, timeout=5):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() > deadline:
            raise AssertionError(f"child did not reach {path.name}")
        time.sleep(0.01)


def test_parallel_processes_cannot_copy_an_incomplete_compiler(tmp_path) -> None:
    script = tmp_path / "prepare.py"
    script.write_text('''from pathlib import Path
import sys, time
from toolrank.smartbugs_solc import compiler_path_locked

root = Path(sys.argv[1])
name = sys.argv[2]
binary = root / 'solc'
def resolve(version):
    if not binary.exists():
        binary.write_bytes(b'partial')
        (root / 'download-started').touch()
        while not (root / 'release-download').exists():
            time.sleep(0.01)
        binary.write_bytes(b'complete-compiler')
    return binary
if name == 'second':
    (root / 'second-waiting').touch()
path = compiler_path_locked(resolve, root, '0.8.38')
(root / (name + '.copied')).write_bytes(path.read_bytes())
''')
    first = subprocess.Popen([sys.executable, str(script), str(tmp_path), "first"])
    second = None
    try:
        _wait_for(tmp_path / "download-started")
        second = subprocess.Popen([sys.executable, str(script), str(tmp_path), "second"])
        _wait_for(tmp_path / "second-waiting")
        time.sleep(0.1)
        assert not (tmp_path / "second.copied").exists()
        (tmp_path / "release-download").touch()
        assert first.wait(timeout=5) == 0
        assert second.wait(timeout=5) == 0
        assert (tmp_path / "first.copied").read_bytes() == b"complete-compiler"
        assert (tmp_path / "second.copied").read_bytes() == b"complete-compiler"
    finally:
        (tmp_path / "release-download").touch()
        for process in [first, second]:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
