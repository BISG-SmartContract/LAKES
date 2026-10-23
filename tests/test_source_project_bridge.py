from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from toolrank import runner
from toolrank.smartbugs_project import select_project_solc_version
from toolrank.source_project import copy_dependency_tree, source_entrypoints


def test_bridge_stages_only_entrypoint_import_closure_without_symlinks(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    contracts = project / "contracts"
    libraries = project / "lib"
    contracts.mkdir(parents=True)
    libraries.mkdir()
    entrypoint = contracts / "Main.sol"
    dependency = libraries / "Lib.sol"
    unrelated = contracts / "Unrelated.sol"
    entrypoint.write_text(
        'pragma solidity ^0.8.20; import "../lib/Lib.sol"; '
        'import "../.env"; contract Main {}',
        encoding="utf-8",
    )
    dependency.write_text(
        "pragma solidity ^0.8.20; library Lib {}",
        encoding="utf-8",
    )
    unrelated.write_text(
        "pragma solidity ^0.8.20; contract Unrelated {}",
        encoding="utf-8",
    )
    (project / ".env").write_text(
        "SECRET=must-not-cross-boundary",
        encoding="utf-8",
    )
    outside = tmp_path / "Outside.sol"
    outside.write_text("contract Outside {}", encoding="utf-8")
    (libraries / "Outside.sol").symlink_to(outside)
    destination = tmp_path / "staged"

    copy_dependency_tree(entrypoint, project, destination)

    assert (destination / "contracts" / "Main.sol").is_file()
    assert (destination / "lib" / "Lib.sol").is_file()
    assert not (destination / "contracts" / "Unrelated.sol").exists()
    assert not (destination / "lib" / "Outside.sol").exists()
    assert not (destination / ".env").exists()


def test_source_entrypoints_do_not_execute_imported_dependencies(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    contracts = project / "contracts"
    libraries = project / "lib"
    contracts.mkdir(parents=True)
    libraries.mkdir()
    entrypoint = contracts / "Main.sol"
    dependency = libraries / "Lib.sol"
    entrypoint.write_text(
        'import {Lib} from "../lib/Lib.sol"; contract Main {}',
        encoding="utf-8",
    )
    dependency.write_text("library Lib {}", encoding="utf-8")

    assert source_entrypoints([entrypoint, dependency], project) == [
        entrypoint.resolve()
    ]


def test_source_entrypoints_cover_isolated_import_cycle_and_normal_root(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    normal = project / "Main.sol"
    cycle_a = project / "A.sol"
    cycle_b = project / "B.sol"
    normal.write_text("contract Main {}", encoding="utf-8")
    cycle_a.write_text('import "./B.sol"; contract A {}', encoding="utf-8")
    cycle_b.write_text('import "./A.sol"; contract B {}', encoding="utf-8")

    entrypoints = source_entrypoints([normal, cycle_a, cycle_b], project)

    assert entrypoints == [cycle_a.resolve(), normal.resolve()]


def test_quoted_fake_import_does_not_hide_an_independent_source_root(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    main = project / "Main.sol"
    independent = project / "Independent.sol"
    main.write_text(
        "contract Main { "
        "string constant FAKE = 'import \"./Independent.sol\";';"
        " }",
        encoding="utf-8",
    )
    independent.write_text("contract Independent {}", encoding="utf-8")

    assert source_entrypoints([main, independent], project) == [
        independent.resolve(),
        main.resolve(),
    ]


def test_project_bridge_compiler_selection_uses_full_constraint_intersection() -> None:
    assert select_project_solc_version(
        ["^0.8.0", "<0.8.20"],
        {"0.8.19", "0.8.20", "0.8.30"},
    ) == "0.8.19"
    assert select_project_solc_version(
        ["^0.8.20"],
        {"0.8.19", "0.8.30"},
    ) == "0.8.30"
    assert select_project_solc_version(
        ["0.8.20"],
        {"0.8.19", "0.8.30"},
    ) is None


@pytest.mark.parametrize("mode", ["solidity", "bytecode", "runtime"])
def test_bridge_initializes_patches_in_real_spawn_worker(
    tmp_path: Path,
    mode: str,
) -> None:
    project = tmp_path / "project"
    contracts = project / "contracts"
    libraries = project / "lib"
    contracts.mkdir(parents=True)
    libraries.mkdir()
    dependency = libraries / "Lib.sol"
    dependency.write_text("pragma solidity <0.8.20; library Lib {}", encoding="utf-8")
    (project / "Unrelated.sol").write_text("contract Unrelated {}", encoding="utf-8")
    suffix = ".sol" if mode == "solidity" else ".hex"
    entrypoint = contracts / f"Main{suffix}"
    entrypoint.write_text(
        'pragma solidity ^0.8.0; import "../lib/Lib.sol"; contract Main {}'
        if mode == "solidity"
        else "6000",
        encoding="utf-8",
    )
    smartbugs = Path(__file__).resolve().parent / "fixtures" / "smartbugs_spawn"
    with runner.prepare_smartbugs_invocation(
        "slither" if mode == "solidity" else "mythril",
        entrypoint,
        tmp_path / "result",
        target_root=project,
        smartbugs_dir=smartbugs,
        timeout=7,
        input_kind="sol" if mode == "solidity" else mode,
    ) as invocation:
        command = invocation.command
        env = invocation.env
        if mode != "solidity":
            # Exercise the bridge entrypoint for non-source tasks too, checking
            # that worker initialization preserves their original staging.
            command = [
                sys.executable,
                str(runner.SMARTBUGS_PROJECT_RUNNER),
                *invocation.command[1:],
            ]
            env = {
                **os.environ,
                "PYTHONPATH": os.pathsep.join(
                    (str(Path(runner.__file__).resolve().parents[1]), str(smartbugs))
                ),
                "LAKES_PROJECT_ROOT": str(project.resolve()),
            }
        completed = subprocess.run(
            command,
            cwd=invocation.cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=25,
        )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    probe = json.loads((tmp_path / "result" / "result.json").read_text())["probe"]
    assert probe["start_method"] == "spawn"
    assert probe["main_module"] == "__mp_main__"
    assert probe["pid"] != probe["parent_pid"]
    assert probe["parent_pid"] != os.getpid()
    if mode == "solidity":
        assert probe["files"] == {
            "project/contracts/Main.sol": entrypoint.read_text(),
            "project/lib/Lib.sol": dependency.read_text(),
        }
        filename = "/sb/project/contracts/Main.sol"
        assert probe["compiler"] == "0.8.19"
    else:
        staged_name = "Main.rt.hex" if mode == "runtime" else "Main.hex"
        assert probe["files"] == {staged_name: "6000"}
        filename = f"/sb/{staged_name}"
        assert probe["compiler"] is None
    args = probe["docker_args"]
    assert args["command"] == ["analyze", filename, "7", "/sb/bin", "0"]
    assert args["entrypoint"] == ["entrypoint", filename]
    assert list(args["volumes"].values()) == [{"bind": "/sb", "mode": "rw"}]
