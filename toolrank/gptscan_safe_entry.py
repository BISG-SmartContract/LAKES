"""Launch GPTScan in-process without exposing its API key in OS argv."""

from __future__ import annotations

import json
import os
from pathlib import Path
import runpy
import sys


def _compile_project_inputs(entrypoints: list[Path], project_root: Path):
    from crytic_compile import CryticCompile
    from crytic_compile.platform.solc_standard_json import SolcStandardJson
    from falcon import Falcon

    from toolrank.source_project import dependency_closure

    sources = sorted({
        source
        for entrypoint in entrypoints
        for source in dependency_closure(entrypoint, project_root)
    })
    # Project-relative names preserve both relative and root-based imports.
    # The working directory maps Falcon locations back to the staged files.
    platform = SolcStandardJson({
        "sources": {
            source.relative_to(project_root).as_posix(): {
                "content": source.read_text(encoding="utf-8")
            }
            for source in sources
        },
    })
    return Falcon(CryticCompile(platform, solc_working_dir=str(project_root)))


def _install_project_compiler(project_root: Path, names: list[str]) -> None:
    from toolrank.source_project import resolve_project_root

    if not isinstance(names, list) or not names:
        raise ValueError("GPTScan project compilation requires source entrypoints")
    entrypoints = []
    for name in names:
        if not isinstance(name, str) or not name:
            raise ValueError("invalid GPTScan source entrypoint")
        entrypoint = project_root / name
        resolve_project_root(entrypoint, project_root)
        if not entrypoint.is_file() or entrypoint.suffix.lower() != ".sol":
            raise ValueError("GPTScan source entrypoint must be a Solidity file")
        entrypoints.append(entrypoint.resolve())

    import tasks

    original_compile = tasks.compile_project

    def compile_project(source):
        if Path(source).resolve() != project_root:
            return original_compile(source)
        return _compile_project_inputs(entrypoints, project_root)

    tasks.compile_project = compile_project


def main() -> None:
    script = Path(os.environ["LAKES_GPTSCAN_MAIN"]).resolve()
    source = os.environ["LAKES_GPTSCAN_SOURCE"]
    output = os.environ["LAKES_GPTSCAN_OUTPUT"]
    key = os.environ.get("OPENAI_API_KEY", "")
    os.chdir(script.parent)
    sys.path.insert(0, str(script.parent))
    entrypoints = os.environ.get("LAKES_GPTSCAN_ENTRYPOINTS")
    if entrypoints is not None:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        _install_project_compiler(Path(source).resolve(), json.loads(entrypoints))
    sys.argv = [str(script), "-s", source, "-o", output, "-k", key]
    runpy.run_path(str(script), run_name="__main__")


if __name__ == "__main__":
    main()
