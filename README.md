# LAKES

LAKES recommends and optionally runs smart-contract vulnerability analyzers for Solidity contracts.

Its scheduling flow is:

1. Stage 1 matches the target contract to benchmark datasets using Gower-KDE weights, ranks feasible tools by historical recall and precision, and selects a primary tool.
2. Stage 2 combines category-level performance evidence with retrieved literature to plan complementary tools for the requested vulnerability categories, subject to the user's preferences and budget.
3. Stage 3 runs the selected tools concurrently for each contract, processes directory contracts sequentially, and fuses findings with their tool provenance. Findings sharing a non-empty `(category, location)` are grouped, while conflicting severity, confidence, or explanation values are retained and marked.

The primary tool remains part of the selected plan. If no suitable complement is selected, LAKES uses a checked primary-only plan.

## Install

Download and extract the repository archive, then run these commands from the
extracted directory containing `pyproject.toml`:

Using [uv](https://docs.astral.sh/uv/):

```bash
uv sync --locked
uv run lakes --help
```

This creates `.venv`, installs the project in editable mode, and includes the
development dependencies. `.python-version` selects Python 3.13, matching a CI
target, and `uv.lock` pins the dependency versions. Use `uv sync --locked --no-dev`
for runtime dependencies only. Run the test suite with `uv run pytest -q`.
Prefix the commands below with `uv run`, or activate the environment with
`source .venv/bin/activate`.

Alternatively, install with pip in an activated virtual environment:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

The editable install is intentional for a source checkout: analyzer
adapters use the tracked resources under `docker/`. The portable full
`--execute` environment is the Docker image described below.

The install also provides `lakes-profile-builder`. It rebuilds the shipped
Gower/KDE benchmark profiles from the tracked manifest and a caller-owned
corpus root:

```bash
python -m solcx.install 0.4.26
python -m solcx.install 0.5.17
python -m solcx.install 0.6.12
python -m solcx.install 0.7.6
python -m solcx.install 0.8.30
lakes-profile-builder \
  --corpus-root /path/to/corpora \
  --manifest toolcards/contract_profile_manifest.json \
  --output toolcards/contract_profiles.json
```

The builder attempts each safe Solidity file with its in-corpus import
closure, records exact compiler and skip provenance, derives ranges from the
emitted AST samples, fits the published bandwidth by full-sample leave-one-out
likelihood over those same samples, and replaces the output atomically. Runtime
scene loading accepts only the matching versioned AST artifact; it never refits
a legacy artifact.

For pragma-constrained sources, profiling tries only intersecting canonical
compiler buckets in `0.4.x` through `0.8.x` order. A source without a pragma
tries `0.8.x` through `0.4.x`. The first compiler that emits the complete AST
owns the recorded Gower bucket and profiling compiler. Rewrites occur only in
the private profiling copy; original constraints, feasibility, and execution
compiler selection remain unchanged.

LAKES chat calls default to the official DeepSeek API at
`https://api.deepseek.com` with model `deepseek-v4-flash`. Only the credential
is required for that default:

```bash
export DEEPSEEK_API_KEY="your-deepseek-api-key"
```

For another OpenAI-compatible chat provider, set `LAKES_OPENAI_BASE_URL`,
`LAKES_OPENAI_MODEL`, and `OPENAI_API_KEY`. The legacy
`TOOLRANK_OPENAI_BASE_URL` and `TOOLRANK_OPENAI_MODEL` aliases remain supported.

## Dynamic knowledge-base updates

The update command requires a local MinerU installation and its models, an
OpenAI-compatible chat endpoint, and an embedding endpoint. Fresh wheels bundle
the default read-only `toolcards` knowledge files used by recommendation.
Ingestion still requires `--toolcards-dir` so the baseline source is explicit
and the writable generation remains under the separate `--kb-root`.

```bash
lakes-kb-update ingest paper.pdf \
  --kb-root /path/to/writable-kb \
  --toolcards-dir /path/to/toolcards \
  --dry-run
```

`--dry-run` performs conversion, extraction, mapping, index construction, and
generation validation against the current generation when one exists, but it
does not create or replace `kb_current.json`. Remove it only when the proposed
generation is ready to publish.

MinerU is invoked locally as `mineru -p PDF -o DIR`; use `--mineru-command` if
it is not on `PATH`. Chat extraction uses the same official DeepSeek defaults
and reads `DEEPSEEK_API_KEY`; the generic chat overrides above remain
available. The separate default SiliconFlow embedding adapter reads
`embeddingAPI`, `SILICONFLOW_API_KEY`, or `QWEN_API_KEY`, plus optional
`SILICONFLOW_BASE_URL` and `SILICONFLOW_EMBEDDING_MODEL`. For another
OpenAI-compatible embedding endpoint, pass `--embedding-base-url` and
`--embedding-model`; its credential is read from `OPENAI_API_KEY`. API keys are
not accepted as command-line options.

## Run

```bash
lakes recommend path/to/Contract.sol --emit summary
```

Evaluate complements for selected DASP categories:

```bash
lakes recommend path/to/Contract.sol \
  --focus-categories reentrancy,access_control \
  --tool-slots 3 \
  --runtime-cap-minutes 30 \
  --emit summary
```

The one-contract estimate is the maximum selected-tool runtime, not their sum. Directory estimates multiply that maximum by the number of sequential Solidity files. `--execution-jobs 0` provides one worker per selected tool; an explicit smaller job cap makes a composition ineligible. The default tool timeout is the runtime budget converted to seconds, while an explicitly shorter timeout is checked before execution. Unknown primary runtime or a primary that exceeds these constraints produces `NO_EXECUTABLE_PLAN`; LAKES does not silently substitute another primary.

Runtime estimates use compatible historical observations in `toolcards/performance_db.json` and are checked against the requested execution budget.

Tools whose ToolCard declares `d8_mode=fuzz` use a separate user-controlled campaign allocation instead of a fabricated historical completion time. The default campaign is the per-tool timeout derived from the runtime budget; `--tool-timeout-sec` sets the per-input campaign explicitly. Concurrent fuzzers each receive the full allocation, directory inputs multiply it sequentially, and the unchanged outer deadline is passed to both execution paths. Historical and literature evidence remains descriptive and cannot affect Stage 1 or replace the checked campaign.

The top-level result status is one of `PRIMARY_NOT_SELECTED`, `NO_EXECUTABLE_PLAN`, `PLAN_READY`, `EXECUTED`, `EXECUTED_PARTIAL`, or `EXECUTION_FAILED`. `EXECUTED_PARTIAL` preserves valid current-run reports when at least one selected tool succeeds and another fails or times out. Objects from later stages are absent after an earlier terminal status.

Run selected analyzers too when the analyzer runtime is already provisioned
(the Docker workflow below is the supported clean-checkout path):

```bash
lakes recommend path/to/Contract.sol --execute --emit summary
```

Outputs are always written under the canonical `LAKES_out/<contract>/`
directory. A custom `--results-root out` places that canonical tree at
`out/LAKES_out/<contract>/`; passing a directory already named `LAKES_out`
does not add another nested `LAKES_out`.

- `fusion_plan.json` records the primary and additive category owner sets.
- `tool_run_statuses.json` records success, partial, failure, timeout, and measured runtime per tool.
- `fused_report.json` preserves source tools, raw findings, field variants, and conflicts.
- `execution.json` records the runner invocation and execution result.

## Docker

Docker includes the analyzer runtime and compiler setup. A fresh image builds
the pinned Smartian revision from tracked source and does not consume a local
`docker/vendor/smartian/build/` directory or a host-specific path.
The outer image and Smartian `.NET` runtime follow the native build
architecture. On ARM hosts, the image also carries the x86-64 runtime libraries
needed by official Linux `solc`; SmartBugs analyzer images remain `linux/amd64`
and use Docker's host platform emulation. The official DeepSeek credential also
supplies GPTScan by default. On official DeepSeek hosts, `DEEPSEEK_API_KEY`
takes precedence over the generic `OPENAI_API_KEY`; custom compatible hosts use
only `OPENAI_API_KEY`.

```bash
docker build -t lakes .
mkdir -p LAKES_out
docker run --rm --privileged \
  -v "$PWD/LAKES_out:/work/LAKES_out" \
  -v "$PWD/path/to/Contract.sol:/work/Contract.sol:ro" \
  -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
  -e OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
  lakes recommend /work/Contract.sol --execute --emit summary --results-root /work/LAKES_out
```

That command publishes the host-visible result directly at
`$PWD/LAKES_out/Contract/`.
