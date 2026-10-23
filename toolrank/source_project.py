"""Solidity import-graph helpers shared by discovery and container staging."""

from __future__ import annotations

from collections import deque
from pathlib import Path
import shutil


def resolve_project_root(
    target_path: str | Path | None,
    project_root: str | Path | None = None,
) -> Path:
    """Resolve the import boundary without changing the selected analysis target."""

    if not target_path:
        raise ValueError("--project-root requires a target path")
    target = Path(target_path).expanduser()
    resolved_target = target.resolve()
    if project_root is None:
        return resolved_target if resolved_target.is_dir() else resolved_target.parent
    root = Path(project_root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"--project-root must be an existing directory: {root}")
    if not resolved_target.is_file() and not resolved_target.is_dir():
        raise ValueError(f"target path not found: {resolved_target}")
    try:
        resolved_target.relative_to(root)
    except ValueError as exc:
        raise ValueError("target must be inside --project-root") from exc
    if target.is_symlink():
        raise ValueError("target must not be a symlink")
    return root


def mask_solidity_noncode_for_pragmas(text: str) -> str:
    """Mask comments and quoted literals while preserving code and newlines.

    Import parsing uses its own directive-aware lexer because it must retain
    quoted paths. Pragma parsing instead masks every quoted literal. Backslash
    escapes keep their quote inside the active literal.
    """
    output: list[str] = []
    index = 0
    state = "code"
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""

        if state == "code":
            if char == "/" and following == "/":
                output.extend((" ", " "))
                state = "line_comment"
                index += 2
                continue
            if char == "/" and following == "*":
                output.extend((" ", " "))
                state = "block_comment"
                index += 2
                continue
            if char in {'"', "'"}:
                output.append(" ")
                state = "double_quote" if char == '"' else "single_quote"
                index += 1
                continue
            output.append(char)
            index += 1
            continue

        if state == "line_comment":
            if char == "\n":
                output.append("\n")
                state = "code"
            else:
                output.append(" ")
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and following == "/":
                output.extend((" ", " "))
                state = "code"
                index += 2
                continue
            output.append("\n" if char == "\n" else " ")
            index += 1
            continue

        quote = '"' if state == "double_quote" else "'"
        if char == "\\":
            output.append(" ")
            index += 1
            if index < len(text):
                escaped = text[index]
                output.append("\n" if escaped == "\n" else " ")
                index += 1
            continue
        output.append("\n" if char == "\n" else " ")
        if char == quote:
            state = "code"
        index += 1

    return "".join(output)


def _consume_quoted(text: str, start: int) -> tuple[int, str]:
    quote = text[start]
    chars: list[str] = []
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            chars.append(text[index + 1])
            index += 2
            continue
        if char == quote:
            return index + 1, "".join(chars)
        chars.append(char)
        index += 1
    return index, "".join(chars)


def _skip_comment(text: str, start: int) -> int | None:
    if text.startswith("//", start):
        newline = text.find("\n", start + 2)
        return len(text) if newline < 0 else newline + 1
    if text.startswith("/*", start):
        end = text.find("*/", start + 2)
        return len(text) if end < 0 else end + 2
    return None


def _solidity_import_paths(text: str) -> list[str]:
    """Extract real import directives without matching quoted Solidity text."""

    imports: list[str] = []
    index = 0
    while index < len(text):
        comment_end = _skip_comment(text, index)
        if comment_end is not None:
            index = comment_end
            continue
        if text[index] in {'"', "'"}:
            index, _value = _consume_quoted(text, index)
            continue
        if text[index].isalpha() or text[index] in {"_", "$"}:
            end = index + 1
            while end < len(text) and (
                text[end].isalnum() or text[end] in {"_", "$"}
            ):
                end += 1
            if text[index:end].lower() != "import":
                index = end
                continue
            index = end
            quoted_paths: list[str] = []
            while index < len(text):
                comment_end = _skip_comment(text, index)
                if comment_end is not None:
                    index = comment_end
                    continue
                if text[index] in {'"', "'"}:
                    index, value = _consume_quoted(text, index)
                    quoted_paths.append(value)
                    continue
                if text[index] == ";":
                    index += 1
                    if quoted_paths:
                        imports.append(quoted_paths[-1])
                    break
                index += 1
            continue
        index += 1
    return imports


def solidity_imports(source: Path) -> list[str]:
    try:
        text = source.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return _solidity_import_paths(text)


def _is_safe_regular_file(path: Path, root: Path) -> bool:
    current = path
    while current != root:
        if current.is_symlink() or root not in current.parents:
            return False
        current = current.parent
    try:
        path.resolve(strict=True).relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return path.is_file()


def _resolve_import(source: Path, import_path: str, root: Path) -> Path | None:
    for candidate in (
        source.parent / import_path,
        root / import_path,
        root / "node_modules" / import_path,
    ):
        if candidate.suffix.lower() == ".sol" and _is_safe_regular_file(candidate, root):
            return candidate.resolve()
    return None


def source_entrypoints(
    source_files: list[Path],
    project_root: Path,
    *,
    follow_imports: bool = False,
) -> list[Path]:
    """Return import-graph roots instead of treating dependencies as targets.

    With ``follow_imports``, traverse dependencies outside the source selection
    while keeping every returned entrypoint inside that selection.
    """

    root = project_root.resolve()
    source_set = {
        path.resolve()
        for path in source_files
        if _is_safe_regular_file(path, project_root)
    }
    graph: dict[Path, set[Path]] = {source: set() for source in source_set}
    pending = deque(sorted(source_set))
    while pending:
        source = pending.popleft()
        for import_path in solidity_imports(source):
            resolved = _resolve_import(source, import_path, root)
            if resolved is not None and (follow_imports or resolved in source_set):
                graph[source].add(resolved)
                if resolved not in graph:
                    graph[resolved] = set()
                    pending.append(resolved)
    if source_files and not graph:
        raise ValueError("source project contains no safe Solidity entrypoint")

    if follow_imports:
        reachable: dict[Path, set[Path]] = {}
        for source in source_set:
            pending_sources = [source]
            visited: set[Path] = set()
            while pending_sources:
                current = pending_sources.pop()
                if current not in visited:
                    visited.add(current)
                    pending_sources.extend(graph[current] - visited)
            reachable[source] = visited & source_set
        # Keep one selected representative per root SCC. A dependency that
        # leaves the selection and returns must not become another target.
        return [
            source
            for source in sorted(source_set)
            if not any(
                source in reachable[other]
                and (other not in reachable[source] or other < source)
                for other in source_set - {source}
            )
        ]

    imported = {dependency for dependencies in graph.values() for dependency in dependencies}
    entrypoints = sorted(source_set - imported)
    covered: set[Path] = set()

    def cover(start: Path) -> None:
        pending = [start]
        while pending:
            source = pending.pop()
            if source in covered:
                continue
            covered.add(source)
            pending.extend(sorted(graph[source] - covered, reverse=True))

    for entrypoint in entrypoints:
        cover(entrypoint)
    # A mutually importing SCC has no indegree-zero node.  Pick one stable
    # representative for each still-uncovered region so no source component
    # disappears silently from execution.
    for source in sorted(source_set):
        if source not in covered:
            entrypoints.append(source)
            cover(source)
    return sorted(entrypoints)


def dependency_closure(entrypoint: Path, project_root: Path) -> list[Path]:
    """Return the safe in-project source files reachable from one entrypoint."""

    root = project_root.resolve()
    start = entrypoint.resolve()
    if not _is_safe_regular_file(entrypoint, project_root):
        raise ValueError("entrypoint is not a regular in-project file")
    pending = deque([start])
    visited: set[Path] = set()
    while pending:
        source = pending.popleft()
        if source in visited:
            continue
        visited.add(source)
        for import_path in solidity_imports(source):
            resolved = _resolve_import(source, import_path, root)
            if resolved is not None and resolved not in visited:
                pending.append(resolved)
    return sorted(visited)


def copy_dependency_tree(
    entrypoint: Path,
    project_root: Path,
    destination: Path,
) -> None:
    """Stage only the entrypoint and its import closure, preserving paths."""

    root = project_root.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    for source in dependency_closure(entrypoint, root):
        relative = source.relative_to(root)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=False)
