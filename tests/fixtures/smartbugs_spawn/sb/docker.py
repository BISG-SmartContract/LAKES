from pathlib import Path
import shutil
import tempfile


def __docker_volume(task):
    # Preserve the upstream single-file behavior so a missing worker patch
    # loses imports, just as the pinned SmartBugs implementation does.
    workspace = Path(tempfile.mkdtemp())
    shutil.copy(task.absfn, workspace)
    (workspace / "bin").mkdir()
    return str(workspace)


def __docker_args(task, workspace):
    filename = f"/sb/{Path(task.absfn).name}"
    timeout = task.settings.timeout or 0
    main = "1" if task.settings.main else "0"
    return {
        "volumes": {workspace: {"bind": "/sb", "mode": "rw"}},
        "command": task.tool.command(filename, timeout, "/sb/bin", main),
        "entrypoint": task.tool.entrypoint(filename, timeout, "/sb/bin", main),
    }


def execute(task):
    workspace = Path(__docker_volume(task))
    try:
        return {
            "docker_args": __docker_args(task, str(workspace)),
            "files": {
                path.relative_to(workspace).as_posix(): path.read_text()
                for path in workspace.rglob("*")
                if path.is_file()
            },
        }
    finally:
        shutil.rmtree(workspace)
