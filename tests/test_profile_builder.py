from __future__ import annotations

import json
from pathlib import Path

import pytest

from toolrank import _complexity
from toolrank import profile_builder as builder


def _manifest(path: Path, datasets: list[dict]) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": builder.MANIFEST_SCHEMA,
                "sample_unit": _complexity.PROFILE_SAMPLE_UNIT,
                "datasets": datasets,
            }
        ),
        encoding="utf-8",
    )
    return path


def _source(root: Path, relative: str, marker: int) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"pragma solidity ^0.8.20; contract C{marker} {{}}\n",
        encoding="utf-8",
    )
    return path


def _fake_profile(path: str | Path, *, dataset_root=None) -> dict:
    marker = int(
        Path(path)
        .read_text(encoding="utf-8")
        .split("contract C", 1)[1]
        .split(" ", 1)[0]
    )
    return {
        "solc": "0.8.x",
        "loc": marker,
        "avg_cyc": float(marker),
        "max_cyc": marker,
        "sum_cyc": marker,
        "max_nest": marker,
        "coupling": marker,
        "n_func": marker,
        "profiling_compiler": "0.8.30",
    }


def _single_dataset(tmp_path: Path) -> tuple[Path, Path]:
    corpus = tmp_path / "corpus"
    _source(corpus / "dataset", "A.sol", 1)
    _source(corpus / "dataset", "nested/B.sol", 2)
    manifest = _manifest(
        tmp_path / "manifest.json",
        [{"name": "Dataset", "path": "dataset", "include": True}],
    )
    return corpus, manifest


def test_builder_module_exposes_working_command(capsys) -> None:
    with pytest.raises(SystemExit) as stopped:
        builder.main(["--help"])
    assert stopped.value.code == 0
    help_text = capsys.readouterr().out
    for option in ("--corpus-root", "--manifest", "--output"):
        assert option in help_text


def test_configurable_root_build_is_deterministic_and_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus, manifest = _single_dataset(tmp_path)
    monkeypatch.setattr(builder, "profile_file", _fake_profile)

    first = builder.build_artifact(
        corpus_root=corpus,
        manifest_path=manifest,
        generated_at="2026-07-17T00:00:00Z",
    )
    second = builder.build_artifact(
        corpus_root=corpus,
        manifest_path=manifest,
        generated_at="2026-07-17T00:00:00Z",
    )

    assert first == second
    assert first["_meta"]["sample_counts"] == {
        "attempted": 2,
        "succeeded": 2,
        "skipped": 0,
    }
    assert first["_coverage"]["Dataset"]["root"] == "dataset"
    assert str(corpus) not in json.dumps(first)
    assert first["_ranges"] == {
        dimension: [1, 2] for dimension in _complexity.NUM_DIMS
    }
    assert first["_bandwidth"] in first["_meta"]["bandwidth"]["grid"]
    assert first["_meta"]["bandwidth"]["method"] == (
        "full_leave_one_out_gaussian_grid_v1"
    )
    assert first["_meta"]["bandwidth"]["sample_size"] == 2
    assert first["_meta"]["bandwidth"]["sample_size"] == (
        first["_meta"]["sample_counts"]["succeeded"]
    )
    assert [sample["id"] for sample in first["datasets"]["Dataset"]] == [
        "Dataset::A.sol",
        "Dataset::nested/B.sol",
    ]


def test_missing_required_root_fails_closed(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    manifest = _manifest(
        tmp_path / "manifest.json",
        [{"name": "Missing", "path": "missing", "include": True}],
    )

    with pytest.raises(builder.ProfileBuildError, match="required dataset root is missing"):
        builder.build_artifact(corpus_root=corpus, manifest_path=manifest)


def test_undeclared_duplicate_root_and_corpus_fail_closed(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _source(corpus / "one", "A.sol", 1)
    root_duplicate = _manifest(
        tmp_path / "root-duplicate.json",
        [
            {"name": "One", "path": "one", "include": True},
            {"name": "Two", "path": "one", "include": True},
        ],
    )
    with pytest.raises(builder.ProfileBuildError, match="duplicate dataset root"):
        builder.build_artifact(corpus_root=corpus, manifest_path=root_duplicate)

    _source(corpus / "two", "Renamed.sol", 1)
    corpus_duplicate = _manifest(
        tmp_path / "corpus-duplicate.json",
        [
            {"name": "One", "path": "one", "include": True},
            {"name": "Two", "path": "two", "include": True},
        ],
    )
    with pytest.raises(builder.ProfileBuildError, match="duplicate corpus"):
        builder.build_artifact(corpus_root=corpus, manifest_path=corpus_duplicate)


def test_declared_duplicate_alias_is_excluded_from_scene_mass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus, _unused = _single_dataset(tmp_path)
    manifest = _manifest(
        tmp_path / "manifest.json",
        [
            {"name": "Canonical", "path": "dataset", "include": True},
            {
                "name": "Alias",
                "path": "dataset",
                "include": False,
                "reason": "duplicate_performance_kb_alias",
                "duplicate_of": "Canonical",
            },
        ],
    )
    monkeypatch.setattr(builder, "profile_file", _fake_profile)

    artifact = builder.build_artifact(corpus_root=corpus, manifest_path=manifest)

    assert list(artifact["datasets"]) == ["Canonical"]
    assert artifact["_meta"]["excluded_datasets"] == [
        {
            "name": "Alias",
            "path": "dataset",
            "reason": "duplicate_performance_kb_alias",
            "duplicate_of": "Canonical",
        }
    ]


def test_duplicate_sample_id_is_a_build_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus, manifest = _single_dataset(tmp_path)
    source = corpus / "dataset" / "A.sol"
    monkeypatch.setattr(builder, "discover_solidity_files", lambda _root: ((source, source), 0))
    monkeypatch.setattr(builder, "profile_file", _fake_profile)

    with pytest.raises(builder.ProfileBuildError, match="duplicate profile sample ID"):
        builder.build_artifact(corpus_root=corpus, manifest_path=manifest)


def test_ast_failure_is_counted_with_bounded_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus, manifest = _single_dataset(tmp_path)

    def fail_one(path: str | Path, *, dataset_root=None) -> dict:
        if Path(path).name == "B.sol":
            raise _complexity.AstExtractionError("Unable to build Solidity AST (ParserError)")
        return _fake_profile(path, dataset_root=dataset_root)

    monkeypatch.setattr(builder, "profile_file", fail_one)
    artifact = builder.build_artifact(corpus_root=corpus, manifest_path=manifest)

    assert artifact["_meta"]["sample_counts"] == {
        "attempted": 2,
        "succeeded": 1,
        "skipped": 1,
    }
    assert artifact["_coverage"]["Dataset"]["failure_classes"] == {
        "compilation_error": 1
    }
    assert artifact["_coverage"]["Dataset"]["skipped_samples"] == [
        {
            "id": "Dataset::nested/B.sol",
            "failure_class": "compilation_error",
        }
    ]


def test_profile_file_uses_only_safe_import_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "dataset"
    main = root / "Main.sol"
    library = root / "lib" / "Lib.sol"
    unrelated = root / "Unrelated.sol"
    library.parent.mkdir(parents=True)
    main.write_text(
        'pragma solidity ^0.8.20; import "./lib/Lib.sol"; contract Main {}',
        encoding="utf-8",
    )
    library.write_text("pragma solidity ^0.8.20; library Lib {}", encoding="utf-8")
    unrelated.write_text("pragma solidity ^0.8.20; contract Unrelated {}", encoding="utf-8")
    captured: list[dict[str, str]] = []

    def fake_sources(sources: dict[str, str]) -> dict:
        captured.append(sources)
        return {
            "solc": "0.8.x",
            "loc": 2,
            "avg_cyc": 0.0,
            "max_cyc": 0,
            "sum_cyc": 0,
            "max_nest": 0,
            "coupling": 1,
            "n_func": 0,
            "profiling_compiler": "0.8.30",
        }

    monkeypatch.setattr(builder, "profile_sources", fake_sources)

    builder.profile_file(main, dataset_root=root)

    assert set(captured[0]) == {"Main.sol", "lib/Lib.sol"}


def test_atomic_write_preserves_existing_output_when_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "profiles.json"
    output.write_text("legacy\n", encoding="utf-8")
    attempted: list[Path] = []

    def fail_replace(source, destination) -> None:
        attempted.append(Path(source))
        assert Path(source).is_file()
        assert Path(destination) == output
        raise OSError("fixture replace failure")

    monkeypatch.setattr(builder.os, "replace", fail_replace)
    with pytest.raises(OSError, match="fixture replace failure"):
        builder.write_artifact_atomic({"new": True}, output)

    assert output.read_text(encoding="utf-8") == "legacy\n"
    assert attempted and not attempted[0].exists()
