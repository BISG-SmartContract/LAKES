"""Interpret documented command arguments and Docker build configuration."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys


def docker_instructions(source: str) -> list[tuple[str, str]]:
    instructions = []
    pending = ""
    for line in source.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        pending += line
        instruction, value = pending.split(None, 1)
        instructions.append((instruction.upper(), value.strip()))
        pending = ""
    assert not pending, "unfinished Dockerfile instruction"
    return instructions


def docker_copy(value: str) -> tuple[dict[str, str], list[str]]:
    options = {}
    while value.startswith("--"):
        option, value = value.split(None, 1)
        name, separator, argument = option[2:].partition("=")
        if not separator:
            argument, value = value.split(None, 1)
        options[name] = argument
        value = value.lstrip()
    paths = json.loads(value) if value.startswith("[") else shlex.split(value)
    return options, paths


def documented_docker_runs(readme: str, workspace: Path) -> list[list[str]]:
    """Let Bash expand examples while replacing Docker with an argv recorder."""
    executable_root = workspace / "bin"
    executable_root.mkdir()
    recorder = executable_root / "docker"
    code = (
        "import json, os, sys\n"
        "with open(os.environ['LAKES_TEST_ARGV_CAPTURE'], 'a') as output:\n"
        "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
    )
    recorder.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -c " + shlex.quote(code) + ' "$@"\n')
    recorder.chmod(0o755)
    capture = workspace / "docker-argv.jsonl"
    for block in re.findall(r"^```(?:bash|sh|shell)\n(.*?)^```", readme, re.MULTILINE | re.DOTALL):
        if not re.search(r"(?m)^\s*docker\s", block):
            continue
        result = subprocess.run(
            ["bash", "-e", "-c", block], cwd=workspace,
            env={**os.environ,
                 "PATH": str(executable_root) + os.pathsep + os.environ["PATH"],
                 "LAKES_TEST_ARGV_CAPTURE": str(capture),
                 "DEEPSEEK_API_KEY": "test-key", "OPENAI_API_KEY": "test-key"},
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    return [argv for line in capture.read_text().splitlines()
            if (argv := json.loads(line)) and argv[0] == "run"]


def option_value(argv: list[str], *names: str) -> str | None:
    for index, token in enumerate(argv):
        for name in names:
            if token == name:
                return argv[index + 1]
            if token.startswith(name + "="):
                return token[len(name) + 1:]
    return None


def bind_mounts(argv: list[str]) -> list[tuple[Path, PurePosixPath, bool]]:
    mounts = []
    for index, token in enumerate(argv):
        volume = None
        mount = None
        if token in {"-v", "--volume"}:
            volume = argv[index + 1]
        elif token.startswith("--volume="):
            volume = token.split("=", 1)[1]
        elif token == "--mount":
            mount = argv[index + 1]
        elif token.startswith("--mount="):
            mount = token.split("=", 1)[1]
        if volume:
            source, target, *mode = volume.split(":")
            if Path(source).is_absolute():
                mounts.append((Path(source), PurePosixPath(target), bool(mode and "ro" in mode[0].split(","))))
        if mount:
            fields = dict((item.split("=", 1) + [""])[:2] for item in next(csv.reader([mount])))
            source = fields.get("src", fields.get("source", ""))
            target = fields.get("dst", fields.get("destination", fields.get("target", "")))
            if fields.get("type") == "bind":
                readonly = fields.get("readonly", fields.get("ro", "false")).lower() not in {"false", "0"}
                mounts.append((Path(source), PurePosixPath(target), readonly))
    return mounts


def host_path(container_path: str | Path, mounts: list[tuple[Path, PurePosixPath, bool]]) -> Path:
    path = PurePosixPath(container_path)
    for source, target, readonly in sorted(mounts, key=lambda item: len(item[1].parts), reverse=True):
        if path.is_relative_to(target):
            assert not readonly, f"output bind mount is read-only: {target}"
            return source.joinpath(*path.relative_to(target).parts)
    raise AssertionError(f"output is not covered by a host bind mount: {path}")
