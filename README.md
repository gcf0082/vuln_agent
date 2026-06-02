# vuln-agent — 自动化代码安全分析管道

基于 LLM 的多阶段安全分析管道，自动从源码发现攻击面、深入追踪数据流、识别潜在漏洞并二次验证。

## 前置条件

依赖 [opencode](https://opencode.ai) CLI。

首次运行前初始化环境，从系统配置生成 `.env` 文件：

```bash
python3 init_env.py
```

## 快速开始

对一个目标代码目录运行完整分析管道：

```bash
python3 run.py /path/to/target
```

仅当前目录：

```bash
python3 run.py
```

## 管道阶段

| 阶段 | 模块 | 功能 |
|------|------|------|
| Stage 1 | `collect` | 攻击面收集：扫描项目识别所有攻击面（REST API、MQ、gRPC、WebSocket、脚本、CLI 等） |
| Stage 2 | `analyze` | 攻击面分析：对每个攻击面深入追踪数据流和关键控制点 |
| Stage 2.5 | `vuln_task_plan` | 漏洞任务规划：基于分析结果生成待验证的漏洞分析任务 |
| Stage 3 | `vuln` | 漏洞分析：逐任务验证漏洞是否存在（VULN / DISMISSED / CLEAN / SUSPECTED） |
| Stage 4 | `reanalyze` | 漏洞二次审查：挑战者视角审查上一轮结论并验证 payload 可行性 |

各阶段可独立运行：

```bash
python3 run_collect.py /path/to/target
python3 run_analyze.py /path/to/target
python3 run_vuln.py /path/to/target    # 指定 --vuln-prompt
python3 run_review.py /path/to/target
```

## 命令行参数

```bash
python3 run.py [work_dir] [选项]
```

| 参数 | 说明 |
|------|------|
| `work_dir` | 目标代码目录（默认当前目录） |
| `--collect-prompt TEXT` | 暴露面识别阶段追加提示词 |
| `--vuln-prompt TEXT` | 漏洞分析及二次审查阶段追加提示词 |
| `--thinking` | 启用 LLM 思考模式 |
| `--model MODEL` | 指定模型名称（如 `gpt-4`、`claude-sonnet-4`） |
| `--agent AGENT` | LLM 代理程序名称（`nga` 或 `opencode`），默认自动检测 |
| `--force-surface FILE` | 强制重新分析指定攻击面（逗号分隔，支持 `*` 通配），会清除已有产物 |
| `--test` | 测试 LLM 连通性（询问模型自身名称），不执行管道 |

### 示例

```bash
# 指定模型运行完整管道
python3 run.py /target --model gpt-4

# 测试 LLM 连通性
python3 run.py --test
python3 run.py --test --model gpt-4 --agent nga

# 指定代理程序
python3 run.py /target --agent opencode

# 启用 thinking 模式
python3 run.py /target --thinking

# 强制重新分析特定攻击面
python3 run.py /target --force-surface "iface-upload-*"
```

## 输出产物

```
_output/
├── surfaces/          # Stage 1: 攻击面记录，每文件一个条目
├── analysis/          # Stage 2: 攻击面深度分析（含流程图、数据流追踪）
├── vuln_tasks/        # Stage 2.5: 漏洞分析任务清单
├── vulnerabilities/   # Stage 3: 漏洞结论（VULN-/DISMISSED-/CLEAN-/SUSPECTED-）
├── vuln_review/       # Stage 4: 二次审查结论（VULN-/NOVULN-/SUSPECTED-）
└── meta/              # 排除路径记录、中间分析产物
```

## 配置

`config/analysis-config.yaml` 控制各阶段启用和并行度：

```yaml
max_workers: 3            # 并行线程数
attack_surface_collection: true
vulnerability_analysis: true
```

## 提示词日志

每次 LLM 调用的完整提示词保存在 `logs/prompts/` 目录下，按时间戳命名，可用于复现测试：

```
logs/prompts/20260601_120030_123_prompt.txt
```

## 基础设施

- `opencode_wrapper.py` — OpenCode CLI 的 Python 封装，提供隔离执行环境
- `llm-run.sh` — LLM 调用脚本，处理环境变量、thinking 模式等
- `init_env.py` — 首次初始化工具
- `test_llm.py` — 连通性测试
