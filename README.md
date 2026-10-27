# LAKES

LAKES 面向 Solidity 智能合约，根据合约特征、历史检测表现和文献证据推荐分析工具，并执行检测、生成融合报告。

方法分为三个阶段：

1. **主工具推荐**：使用 Gower-KDE 权重匹配合约与基准数据集，按历史召回率和精确率对可行工具排序，选出主工具。
2. **互补工具规划**：结合类别级性能证据和检索文献，按关注类别、用户偏好与预算规划互补工具，并校验方案。主工具保留在方案中；未选出合适互补工具时，采用经校验的主工具单独执行方案。
3. **执行与融合**：对每个合约并行运行选定工具，目录中的合约依次处理；按非空的 `(category, location)` 合并发现，保留来源工具、字段差异与冲突。

- [Docker 快速开始](#docker-快速开始)
- [并发任务与常用参数](#并发任务与常用参数)
- [运行配置与任务管理](#运行配置与任务管理)
- [本地安装与推荐](#本地安装与推荐)
- [测试](#测试)
- [数据维护](#数据维护)

## Docker 快速开始

以下示例使用共享 runtime 管理分析器，每个检测任务启动一个 worker。两者使用同一个 `lakes:latest` 镜像。

| 组件 | 作用 | 使用方式 |
| --- | --- | --- |
| runtime | 运行 Docker daemon，管理分析器容器和镜像缓存。 | 启动一次，供后续任务复用。 |
| worker | 为一个任务推荐工具、发起检测并整理结果。 | 每个任务启动一个，完成后退出。 |

`lakes-docker-cache` 保存分析器镜像和镜像层，后续任务复用已下载或构建的镜像；`lakes-runtime-socket` 供 worker 连接 runtime。

准备已启动的 Docker。以下命令均在 **LAKES 仓库根目录**执行；ARM 主机使用 Docker 的 x86-64 平台模拟运行相应分析器和官方 Linux solc。

### 1. 构建镜像并配置模型

```bash
docker build -t lakes:latest .
export DEEPSEEK_API_KEY="your-deepseek-api-key"
```

已有可用镜像时跳过构建。默认聊天服务为 DeepSeek，GPTScan 复用该配置。连接官方 DeepSeek 服务时，`DEEPSEEK_API_KEY` 优先于 `OPENAI_API_KEY`。

其他 OpenAI 兼容服务通过以下环境变量配置：

```bash
export LAKES_OPENAI_BASE_URL="https://your-provider.example/v1"
export LAKES_OPENAI_MODEL="your-model"
export OPENAI_API_KEY="your-api-key"
```

将地址、模型和密钥替换为实际值；配置示例见 [.env.example](.env.example)。后面的 worker 命令会将这些变量传入容器。

### 2. 放入待检测项目

```bash
mkdir -p runtime-jobs/job-a/input runtime-jobs/job-a/output
cp -R /path/to/project/. runtime-jobs/job-a/input/
```

将 `/path/to/project` 替换为项目路径，复制入口文件及导入依赖。本例入口为 `contracts/Main.sol`：

```text
runtime-jobs/job-a/
├── input/
│   ├── contracts/Main.sol
│   └── 其他源码及导入依赖
└── output/
```

### 3. 启动共享 runtime

由一个 runtime 挂载并管理缓存卷。复用已有 `lakes-docker-cache` 时，先停止原先使用它的容器；旧缓存的 daemon 版本和存储后端需与当前环境兼容。

```bash
docker volume create lakes-runtime-socket
docker run -d --name lakes-runtime --privileged --cgroupns=private \
  --mount type=volume,src=lakes-docker-cache,dst=/var/lib/docker \
  --mount type=volume,src=lakes-runtime-socket,dst=/run/lakes-runtime \
  --mount type=bind,src="$PWD/runtime-jobs",dst=/jobs \
  lakes:latest runtime
```

首次使用时 Docker 会创建缓存卷。runtime 已运行时可直接复用，已停止时用 `docker start lakes-runtime` 启动。

检查 runtime 是否就绪：

```bash
docker exec -e DOCKER_HOST=unix:///run/lakes-runtime/docker.sock \
  lakes-runtime docker info
```

命令成功后继续启动任务；运行日志可通过 `docker logs lakes-runtime` 查看。

### 4. 启动检测任务

```bash
job_id=job-a
docker run --rm --name "lakes-$job_id" \
  --mount type=volume,src=lakes-runtime-socket,dst=/run/lakes-runtime \
  --mount type=bind,src="$PWD/runtime-jobs",dst=/jobs \
  -e LAKES_DOCKER_MODE=external \
  -e DOCKER_HOST=unix:///run/lakes-runtime/docker.sock \
  -e LAKES_SHARED_ROOT=/jobs -e LAKES_JOB_ID="$job_id" \
  -e LAKES_DOCKER_CPUS=2 -e LAKES_DOCKER_MEMORY=2g \
  -e DEEPSEEK_API_KEY -e OPENAI_API_KEY \
  -e LAKES_OPENAI_BASE_URL -e LAKES_OPENAI_MODEL \
  lakes:latest recommend "/jobs/$job_id/input/contracts/Main.sol" \
  --project-root "/jobs/$job_id/input" \
  --results-root "/jobs/$job_id/output" \
  --execute --emit summary
```

按实际入口修改 `input/contracts/Main.sol`，也可将目标设为输入目录。`--project-root` 指定 Solidity 导入根目录，`--execute` 表示运行选定工具；去掉它可仅生成推荐方案。

runtime 和 worker 将同一宿主机目录挂载到相同的 `/jobs` 路径。任务输入、项目根目录和输出放在 `/jobs/<job_id>/` 下，临时文件使用该任务的 `tmp/`。worker 通过 socket 访问分析器，缓存卷由 runtime 挂载。

示例中的 `2` CPU、`2g` 内存是**每个分析器容器**的上限。任务准入、总资源分配和多任务生命周期由调用方或调度服务协调。

### 5. 查看结果

本例的融合报告位于宿主机：

```bash
cat runtime-jobs/job-a/output/LAKES_out/Main/fused_report.json
```

| 文件 | 内容 |
| --- | --- |
| `fused_report.json` | 漏洞发现、来源工具和冲突信息。 |
| `tool_run_statuses.json` | 各工具的执行状态、耗时和失败信息。 |
| `fusion_plan.json` | 主工具、互补工具及漏洞类别分工。 |
| `execution.json` | 执行命令与执行结果。 |

文件目标 `Main.sol` 对应输出目录 `Main/`，目录目标使用目录名。输出位于 `--results-root` 下的 `LAKES_out/<目标名>/`；根目录本身叫 `LAKES_out` 时直接使用该目录。

`EXECUTED_PARTIAL` 表示部分工具成功、部分失败或超时，报告保留本轮有效结果。失败证据通过原始结果目录下的 `diagnostics/index.json` 查找。

## 并发任务与常用参数

### 同时检测多个任务

保持 runtime 运行，为每个任务分配独立目录和任务 ID：

1. 准备 `runtime-jobs/job-b/input/` 和 `output/`，按第 2 步复制项目。
2. 在另一个终端进入仓库根目录，并设置模型服务密钥。
3. 重复第 4 步，将第一行改为 `job_id=job-b`，按需修改入口。

两个 worker 共享同一个 runtime 和缓存卷，结果分别写入各自的 `output/`。各任务内部仍按“工具并行、目录合约依次处理”的方式执行。

共享卷缓存分析器镜像和镜像层；worker 使用镜像预装编译器，额外下载的编译器文件保存在各自的文件系统中。

### 常用参数

在 `recommend` 命令中按需添加或修改：

| 需求 | 参数示例 |
| --- | --- |
| 关注指定漏洞类别 | `--focus-categories reentrancy,access_control` |
| 最多选择 3 个工具 | `--tool-slots 3`，默认 `5`。 |
| 设置运行时间预算 | `--runtime-cap-minutes 30`，默认 `30` 分钟。 |
| 设置每个工具、每个输入的超时 | `--tool-timeout-sec 600`，默认由时间预算换算。 |
| 设置工具执行并发上限 | `--execution-jobs 3`；默认 `0`，为每个选定工具分配一个执行进程。 |
| 输出 JSON | `--emit json --no-explain` |

方案评估结合时间预算、工具数量和执行并发约束。单合约耗时估计取所选工具耗时的最大值，目录任务再乘以合约数；模糊测试工具使用分配的检测时长。未形成可执行方案时，结果为 `NO_EXECUTABLE_PLAN`。

查看完整选项：

```bash
docker run --rm --entrypoint lakes lakes:latest recommend --help
```

## 运行配置与任务管理

### 外部 runtime 配置

| 环境变量 | 说明 |
| --- | --- |
| `LAKES_DOCKER_MODE` | worker 使用 `external`；共享 runtime 命令使用默认 `auto`。 |
| `DOCKER_HOST` | Docker daemon 连接端点，支持相应的 Docker TLS 环境配置。 |
| `LAKES_SHARED_ROOT` | runtime 和 worker 共同挂载的现有绝对目录。 |
| `LAKES_JOB_ID` | 1–128 个字符，以英文字母或数字开头，其余可含英文字母、数字、`_`、`-`、`.`；一个 worker 进程对应一个任务。 |
| `LAKES_DOCKER_CPUS` | 可选，每个分析器容器的 CPU 上限，最小 `0.01`。 |
| `LAKES_DOCKER_MEMORY` | 可选，每个分析器容器的内存上限，如 `512m`、`2g`，最小 6 MiB。 |

外部模式配置上述连接端点、共享目录和任务 ID。资源上限与工具原有配置共同生效，取其中更严格的限制。

### 任务取消与清理

正常结束或达到外层超时后，LAKES 按 attempt 标签清理残留分析器，保留共享镜像和卷。取消整个任务时，先停止 worker，再清理该任务在 runtime 上的分析器：

```bash
docker stop lakes-job-a
docker run --rm \
  --mount type=volume,src=lakes-runtime-socket,dst=/run/lakes-runtime \
  --mount type=bind,src="$PWD/runtime-jobs",dst=/jobs \
  -e LAKES_DOCKER_MODE=external \
  -e DOCKER_HOST=unix:///run/lakes-runtime/docker.sock \
  -e LAKES_SHARED_ROOT=/jobs -e LAKES_JOB_ID=job-a \
  --entrypoint python lakes:latest -m toolrank.docker_runtime cleanup
```

其他任务替换相应的 worker 名称和 `LAKES_JOB_ID`。调度服务也可通过 `lakes.service.job` 标签执行任务级清理，并在 runtime 恢复后核对任务状态和截止时间。

### 独立 Docker 模式

单个任务也可在同一容器中运行 LAKES 与内部 Docker daemon，使用默认 `LAKES_DOCKER_MODE=auto` 和 `--privileged`。从共享模式切换时，先停止 `lakes-runtime` 以释放缓存卷。

将项目放入 `input/`，例如入口为 `input/contracts/Main.sol`：

```bash
mkdir -p LAKES_out
docker run --rm --privileged \
  --mount type=volume,src=lakes-docker-cache,dst=/var/lib/docker \
  --mount type=bind,src="$PWD/input",dst=/work/input,readonly \
  --mount type=bind,src="$PWD/LAKES_out",dst=/work/LAKES_out \
  -e DEEPSEEK_API_KEY -e OPENAI_API_KEY \
  -e LAKES_OPENAI_BASE_URL -e LAKES_OPENAI_MODEL \
  lakes:latest recommend /work/input/contracts/Main.sol \
  --project-root /work/input --results-root /work/LAKES_out \
  --execute --emit summary
```

结果写入宿主机的 `LAKES_out/Main/`。

## 本地安装与推荐

需要 Python 3.10 及以上和 uv，仓库默认使用 Python 3.13。在仓库根目录执行：

```bash
uv sync --locked
export DEEPSEEK_API_KEY="your-deepseek-api-key"
uv run lakes recommend /path/to/Contract.sol --emit summary
```

本例生成推荐方案。本地添加 `--execute` 执行检测时，需准备对应分析器环境；Docker 镜像已集成该环境。

## 测试

运行常规测试：

```bash
uv run pytest -q
```

6 个集成测试用例通过环境变量指定镜像后启用：

| 环境变量 | 用例数 | 内容 |
| --- | --- | --- |
| `LAKES_TEST_SHARED_RUNTIME_IMAGE` | 2 | 共享 runtime 并发、资源限制、任务清理和缓存保留。 |
| `LAKES_TEST_RUNTIME_IMAGE` | 4 | 真实 solc/Falcon 编译：单文件、目录、多入口和旧调用方式。 |

启用全部测试：

```bash
LAKES_TEST_RUNTIME_IMAGE=lakes:latest \
LAKES_TEST_SHARED_RUNTIME_IMAGE=lakes:latest \
uv run pytest -q
```

集成测试使用临时容器、测试目录和独立测试卷，通过本地探针及真实编译器验证执行环境。

## 数据维护

### 文献知识库导入

常规推荐使用仓库提供的 `toolcards/` 数据。导入文献需准备本地 MinerU 及其模型、聊天服务和嵌入服务。

默认嵌入服务为 SiliconFlow，可设置 `SILICONFLOW_API_KEY`；自定义嵌入服务使用 `--embedding-base-url`、`--embedding-model` 和 `OPENAI_API_KEY`。

```bash
uv run lakes-kb-update ingest paper.pdf \
  --kb-root /path/to/writable-kb \
  --toolcards-dir toolcards \
  --dry-run
```

`--dry-run` 执行转换、抽取、索引构建和校验；去掉该选项后发布知识库，推荐时通过 `--kb-root /path/to/writable-kb` 读取。

MinerU 不在 `PATH` 时可通过 `--mineru-command` 指定。完整选项见 `uv run lakes-kb-update ingest --help`。

### 合约画像重建

准备 `toolcards/contract_profile_manifest.json` 对应的数据集语料目录，并安装所需编译器：

```bash
for version in 0.4.26 0.5.17 0.6.12 0.7.6 0.8.30; do
  uv run python -m solcx.install "$version"
done
uv run lakes-profile-builder \
  --corpus-root /path/to/corpora \
  --manifest toolcards/contract_profile_manifest.json \
  --output toolcards/contract_profiles.json
```

构建器使用源码及其导入依赖生成 AST 画像，记录编译器和跳过原因，再原子替换输出文件；源文件处理在构建器的临时副本中完成。
