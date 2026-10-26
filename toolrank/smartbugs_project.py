"""Launch pinned SmartBugs while preserving a Solidity project's import tree.

SmartBugs 2.1 normally copies only ``task.absfn`` into each analyzer container.
This bridge keeps its CLI/task model but replaces the Docker staging boundary
for Solidity tasks so the entrypoint and its relative imports are mounted
together.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile

from toolrank.source_project import copy_dependency_tree
from toolrank.solc_range import version_satisfies_solidity_constraint
from toolrank.smartbugs_solc import install_compiler_guards


def select_project_solc_version(
    constraints: list[str],
    available: set[str] | list[str],
) -> str | None:
    """Select the newest installed compiler satisfying every project pragma."""

    compatible = [
        version
        for version in available
        if all(
            version_satisfies_solidity_constraint(version, constraint)
            for constraint in constraints
        )
    ]
    if not compatible:
        return None
    return max(
        compatible,
        key=lambda value: tuple(int(part) for part in value.split(".")),
    )


def _install_project_patches() -> None:
    import sb.docker
    import sb.semantic_version

    try:
        import sb.solc
    except ModuleNotFoundError as exc:
        if exc.name != "sb.solc":
            raise
    else:
        try:
            from solc_select.services.artifact_manager import ArtifactManager
        except ModuleNotFoundError:
            # Older user-provided SmartBugs releases still get serialized path lookup.
            ArtifactManager = None
        install_compiler_guards(sb.solc, Path(sb.solc.SOLC_SELECT_DIR), ArtifactManager)

    project_root = Path(os.environ["LAKES_PROJECT_ROOT"]).resolve()
    original_volume = sb.docker.__docker_volume
    original_args = sb.docker.__docker_args
    original_version_match = sb.semantic_version.match
    try:
        project_constraints = json.loads(
            os.environ.get("LAKES_SOLIDITY_CONSTRAINTS", "[]")
        )
    except json.JSONDecodeError:
        project_constraints = []

    def project_version_match(versions, available):
        if not isinstance(project_constraints, list) or not project_constraints:
            return original_version_match(versions, available)
        return select_project_solc_version(project_constraints, available)

    def project_volume(task):
        if task.tool.mode != "solidity":
            return original_volume(task)
        workspace = Path(tempfile.mkdtemp())
        project_dir = workspace / "project"
        try:
            entrypoint = Path(task.absfn).resolve()
            relative_entrypoint = entrypoint.relative_to(project_root)
        except ValueError as exc:
            raise RuntimeError("SmartBugs entrypoint is outside project root") from exc
        copy_dependency_tree(entrypoint, project_root, project_dir)
        if not (project_dir / relative_entrypoint).is_file():
            raise RuntimeError("SmartBugs entrypoint is not a regular in-project Solidity file")
        bin_dir = workspace / "bin"
        if task.tool.bin:
            shutil.copytree(task.tool.absbin, bin_dir)
        else:
            bin_dir.mkdir()
        if task.solc_path:
            shutil.copyfile(task.solc_path, bin_dir / "solc")
        return str(workspace)

    def project_args(task, workspace):
        args = original_args(task, workspace)
        if task.tool.mode != "solidity":
            return args
        try:
            relative = Path(task.absfn).resolve().relative_to(project_root)
        except ValueError:
            relative = Path(task.absfn).name
        filename = f"/sb/project/{Path(relative).as_posix()}"
        timeout = task.settings.timeout or 0
        main_only = "1" if task.settings.main else "0"
        args["command"] = task.tool.command(filename, timeout, "/sb/bin", main_only)
        args["entrypoint"] = task.tool.entrypoint(filename, timeout, "/sb/bin", main_only)
        return args

    sb.docker.__docker_volume = project_volume
    sb.docker.__docker_args = project_args
    sb.semantic_version.match = project_version_match


def main() -> None:
    import sb.cli

    _install_project_patches()
    sb.cli.main()


if __name__ == "__main__":
    main()
elif __name__ == "__mp_main__":
    # SmartBugs uses spawn workers, which reload this entrypoint before
    # importing the analyser target and do not inherit parent monkeypatches.
    _install_project_patches()
