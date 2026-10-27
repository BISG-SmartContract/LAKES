"""Opt-in shared-daemon regressions; never attach the user's existing cache.

LAKES_TEST_SHARED_RUNTIME_ENTRYPOINT optionally mounts a local unified entrypoint
for script-only checks against an existing adapted image without rebuilding it.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import time
from uuid import uuid4

import pytest


IMAGE = os.environ.get("LAKES_TEST_SHARED_RUNTIME_IMAGE", "")
ENTRYPOINT = os.environ.get("LAKES_TEST_SHARED_RUNTIME_ENTRYPOINT", "")
pytestmark = pytest.mark.skipif(not IMAGE, reason="set LAKES_TEST_SHARED_RUNTIME_IMAGE to an adapted local image")
SOCKET = "unix:///run/lakes-runtime/docker.sock"
PROBE_IMAGE = "lakes-shared-runtime-probe:test"


def command(args, *, binary=False, input=None, check=True, timeout=60):
    result = subprocess.run(args, capture_output=True, text=not binary, input=input, timeout=timeout)
    if check and result.returncode != 0:
        raise AssertionError(result.stderr.decode(errors="replace") if binary else result.stderr)
    return result


def daemon(container, *args, **kwargs):
    return command(["docker", "exec", "-e", f"DOCKER_HOST={SOCKET}", container, "docker", *args], **kwargs)


def wait_ready(container):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            if daemon(container, "info", "--format", "{{.ID}}", check=False, timeout=5).returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass
        state = command(["docker", "inspect", "--format", "{{.State.Status}}", container], check=False)
        if state.stdout.strip() == "exited":
            break
        time.sleep(.2)
    logs = command(["docker", "logs", "--tail", "40", container], check=False)
    pytest.fail("shared daemon did not become ready: " + logs.stdout + logs.stderr)


@pytest.fixture(scope="module")
def shared_runtime(tmp_path_factory):
    workspace = tmp_path_factory.mktemp("shared-docker")
    prefix = "lakes-runtime-test-" + uuid4().hex[:10]
    container, cache, socket = prefix, prefix + "-cache", prefix + "-socket"
    for job in ("job-a", "job-b", "job-timeout"):
        (workspace / job / "input").mkdir(parents=True)
        (workspace / job / "output").mkdir()
        (workspace / job / "input/value").write_text(job + "\n")
    for volume in (cache, socket):
        command(["docker", "volume", "create", volume])
    entrypoint_mount = []
    runtime_command = [IMAGE, "runtime"]
    if ENTRYPOINT:
        script = Path(ENTRYPOINT).resolve(strict=True)
        entrypoint_mount = [
            "--mount", f"type=bind,src={script},dst=/usr/local/bin/entrypoint.sh,readonly",
            "--entrypoint", "/bin/bash",
        ]
        runtime_command = [IMAGE, "/usr/local/bin/entrypoint.sh", "runtime"]
    try:
        command([
            "docker", "run", "-d", "--pull=never", "--name", container, "--privileged",
            "--cgroupns=private",
            "--mount", f"type=volume,src={cache},dst=/var/lib/docker",
            "--mount", f"type=volume,src={socket},dst=/run/lakes-runtime",
            "--mount", f"type=bind,src={workspace},dst=/jobs",
            *entrypoint_mount, *runtime_command,
        ])
        wait_ready(container)
        # Import only /bin/sh, /bin/sleep and their dynamic libraries. This tiny
        # fixture needs no pulls, registry access or duplicate LAKES base image.
        archive_code = r'''
import re, subprocess, sys, tarfile
files = {"/bin/sh", "/bin/sleep"}
for executable in list(files):
    output = subprocess.check_output(["ldd", executable], text=True)
    files.update(re.findall(r"(/[^\s()]+)", output))
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|", dereference=True) as archive:
    for filename in sorted(files):
        archive.add(filename, arcname=filename.lstrip("/"), recursive=False)
'''
        archive = command([
            "docker", "run", "--rm", "--pull=never", "--network=none",
            "--entrypoint", "python", IMAGE, "-c", archive_code,
        ], binary=True).stdout
        command([
            "docker", "exec", "-i", "-e", f"DOCKER_HOST={SOCKET}", container,
            "docker", "import", "-", PROBE_IMAGE,
        ], binary=True, input=archive)
        yield container, socket, workspace
    finally:
        command(["docker", "rm", "--force", "--volumes", container], check=False)
        for volume in (socket, cache):
            command(["docker", "volume", "rm", volume], check=False)


def worker(shared, job, code, *, timeout=30):
    _, socket, workspace = shared
    result = command([
        "docker", "run", "--rm", "--pull=never", "--network=none",
        "--mount", f"type=volume,src={socket},dst=/run/lakes-runtime",
        "--mount", f"type=bind,src={workspace},dst=/jobs",
        "-e", "PYTHONPATH=/work", "-e", "LAKES_DOCKER_MODE=external",
        "-e", f"DOCKER_HOST={SOCKET}", "-e", "LAKES_SHARED_ROOT=/jobs",
        "-e", f"LAKES_JOB_ID={job}", "-e", "LAKES_DOCKER_CPUS=0.5",
        "-e", "LAKES_DOCKER_MEMORY=64m",
        "--entrypoint", "/opt/smartbugs/.venv/bin/python", IMAGE, "-c", code,
    ], timeout=timeout)
    return json.loads(result.stdout.strip().splitlines()[-1])


def start_analyzer(shared, job, *, sdk):
    code = '''
import json, os, subprocess
from pathlib import Path
from toolrank import docker_runtime as runtime
runtime.configure()
job = Path("/jobs") / os.environ["LAKES_JOB_ID"]
'''
    # Keep shell quoting inside a Python string literal rather than shell code.
    code += "script = " + repr(
        'read value < /input/value; echo "$value" > /output/value; sleep 120'
    ) + "\n"
    if sdk:
        code += f'''
import docker
client = docker.from_env()
args = runtime.container_args({{
    "detach": True, "network_mode": "none",
    "volumes": {{str(job / "input"): {{"bind": "/input", "mode": "ro"}},
                 str(job / "output"): {{"bind": "/output", "mode": "rw"}}}},
}}, "sdk-probe")
container = client.containers.run({PROBE_IMAGE!r}, ["/bin/sh", "-c", script], **args)
identifier = container.id
image = client.images.get({PROBE_IMAGE!r}).id
'''
    else:
        code += f'''
identifier = subprocess.check_output([
    "docker", "run", "-d", "--network=none", *runtime.cli_args("cli-probe"),
    "-v", f"{{job / 'input'}}:/input:ro", "-v", f"{{job / 'output'}}:/output",
    {PROBE_IMAGE!r}, "/bin/sh", "-c", script,
], text=True).strip()
image = subprocess.check_output(["docker", "image", "inspect", "--format", "{{{{.Id}}}}", {PROBE_IMAGE!r}], text=True).strip()
'''
    code += 'print(json.dumps({"container": identifier, "image": image}))\n'
    return worker(shared, job, code)


def test_concurrent_sdk_and_cli_jobs_share_cache_and_cancel_independently(shared_runtime):
    container, _, workspace = shared_runtime
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(start_analyzer, shared_runtime, "job-a", sdk=False)
        second = pool.submit(start_analyzer, shared_runtime, "job-b", sdk=True)
        a, b = first.result(timeout=30), second.result(timeout=30)
    assert a["image"] == b["image"]
    metadata = json.loads(daemon(container, "inspect", a["container"], b["container"]).stdout)
    assert all(row["State"]["Running"] for row in metadata)
    assert {row["Config"]["Labels"]["lakes.service.job"] for row in metadata} == {"job-a", "job-b"}
    assert all(row["HostConfig"]["CpuQuota"] == 50000 for row in metadata)
    assert all(row["HostConfig"]["Memory"] == 64 * 1024**2 for row in metadata)
    for job in ("job-a", "job-b"):
        assert (workspace / job / "output/value").read_text().strip() == job
    cleanup = "import json; from toolrank.docker_runtime import cleanup; cleanup(whole_job=True); print(json.dumps({'clean': True}))"
    assert worker(shared_runtime, "job-a", cleanup)["clean"]
    assert daemon(container, "inspect", a["container"], check=False).returncode != 0
    assert json.loads(daemon(container, "inspect", b["container"]).stdout)[0]["State"]["Running"]
    worker(shared_runtime, "job-b", cleanup)
    # Cache lifetime belongs to the daemon volume, not to any worker or job.
    command(["docker", "stop", "--time", "10", container])
    command(["docker", "start", container])
    wait_ready(container)
    assert daemon(container, "image", "inspect", "--format", "{{.Id}}", PROBE_IMAGE).stdout.strip() == a["image"]
    command(["docker", "kill", container])
    command(["docker", "start", container])
    wait_ready(container)
    assert daemon(container, "image", "inspect", "--format", "{{.Id}}", PROBE_IMAGE).stdout.strip() == a["image"]


def test_outer_timeout_removes_real_shared_daemon_analyzer(shared_runtime):
    container, _, workspace = shared_runtime
    child = f'''
import subprocess, time
from pathlib import Path
from toolrank import docker_runtime as runtime
runtime.configure()
identifier = subprocess.check_output([
    "docker", "run", "-d", "--network=none", *runtime.cli_args("timeout-probe"),
    {PROBE_IMAGE!r}, "/bin/sleep", "120",
], text=True).strip()
Path("/jobs/job-timeout/output/container-id").write_text(identifier)
time.sleep(120)
'''
    code = f'''
import json, sys
from toolrank.docker_runtime import configure
from toolrank.process_deadline import run_process_with_deadline
configure()
result = run_process_with_deadline([sys.executable, "-c", {child!r}], timeout_seconds=4)
print(json.dumps({{"returncode": result.returncode, "timed_out": result.timed_out}}))
'''
    result = worker(shared_runtime, "job-timeout", code)
    assert result == {"returncode": 124, "timed_out": True}
    identifier = (workspace / "job-timeout/output/container-id").read_text().strip()
    assert daemon(container, "inspect", identifier, check=False).returncode != 0
    assert not daemon(container, "ps", "-aq", "--filter", "label=lakes.service.job=job-timeout").stdout.strip()
