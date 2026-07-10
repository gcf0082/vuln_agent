# AGENTS.md

面向在 `vuln_agent` 中工作的 AI agent。仅覆盖核心分析管道。

## 这个项目是什么

基于 LLM 的多阶段源码安全分析**管道**。它**不**使用 Python LLM SDK - 每次 LLM 交互都通过子进程
shell 调用 `opencode` 或 `nga` CLI（每次调用一个子进程）。`requirements.txt` 故意几乎为空（只有
`flask`）；不要为满足 import 而添加 `openai`/`anthropic` SDK - 项目里根本没有。

入口：`python3 run.py <target_dir>` -> `biz_recon/runner.py` -> `biz_recon/pipeline.py`。

## 关键工作流事实

- **可断点续跑的管道。** 每个阶段把产物持久化到 `<target>/.vuln_agent_output/` 下，若产物已存在则跳过。
  重新运行 `python3 run.py <target>` 会从第一个未完成阶段继续。强制重跑某阶段用
  `--stage {recon|flow|vuln|postprocess} --overwrite`。Phase 3（medium/low 漏洞）由 `.phase3_done`
  标记守护 - 删除它即可重做 Phase 3。
- **没有测试、lint、typecheck 或 CI。** `package.json` 的 `test` 是占位 stub；没有
  `pytest.ini`/`pyproject.toml`/`ruff`/`.github` workflow。改动后没有可运行的校验命令 - 靠对样例
  目标执行管道来验证。
- **`--test` 只检查 LLM 连通性**（问模型自己叫什么），不跑管道。在任何新环境里先跑这个：
  `python3 run.py --test`。

## LLM 后端

- 二进制程序由 `--agent nga|opencode` 选择（默认：自动检测 - 优先 `nga`，回退 `opencode`）。
- 模型通过 `--model <id>`（如 `w3/MiniMax-M2.7`）或 `.env` 里的 `OPENCODE_DEFAULT_MODEL`。
  `--model` 会设置 `LLM_MODEL` 环境变量，`llm-run.sh` 把它作为 CLI 的 `--model` 标志透传。
- **`.env` 被 gitignore 且运行时必需**：定义 `OPENCODE_DEFAULT_MODEL` 加上所选 provider/model 的
  API key。像 `w3/`、`opencode-go/` 这类 provider 前缀意味着周边环境里需要自定义 opencode provider 配置。
- 每次调用都在完全隔离的临时 opencode profile 里运行（`opencode_wrapper.py` 创建并清理临时目录；
  系统 skills/plugins/`.claude` 全部禁用）。实际调用脚本：`llm-run.sh`（Linux）/ `llm-run.py` +
  `llm-run.bat`（Windows）。`agent.sh` 用 `agent_env/` 开一个*交互式* LLM 会话。

## 管道架构（`biz_recon/`）

| 阶段 | 模块 | Prompt 模板 | 产物目录 |
|------|------|-------------|----------|
| 1 surface_discover | `surface_discover.py` | `prompts/identify-surfaces.txt` | `discovered_surfaces/` |
| 2 surface_analyze | `surface_analyze.py` | `prompts/analyze-surface.txt` | `analyzed_surfaces/` |
| 2.5 vuln_planner | `vuln_planner.py` | `prompts/vuln-planner.txt` | `vuln_plans/<stem>/` |
| 3 vuln_analyze | `vuln_analyze.py` | `prompts/analyze-vulnerability.txt` | `vuln_findings/` |
| 3.5 review_vuln | `review_vuln.py` | `prompts/review-vulnerability.txt` | `vuln_reviews/` |
| 4 vuln_postprocess | `vuln_postprocess.py` | `prompts/postprocess-vulnerability.txt` | `vuln_postprocess/`（仅当 `prompts-ext/postprocess-prompt.md` 存在时） |

`pipeline.run()` 编排 4 个 phase：发现 -> 每个攻击面的分析+规划 -> 高危漏洞分析+复核（vuln 池）
-> medium/low 漏洞分析+复核（由 `--min-level` 和 `.phase3_done` 守护）。

## 产物文件名就是数据契约

下游阶段会解析文件名 - 不要重命名产物，否则管道断裂：
- `discovered_surfaces/`：`iface-*.md` / `noniface-*.md`。`workspace.read_surface_list` 解析
  markdown 列表字段 `类型`/`分类`/`优先级`/`来源`/`描述`/`输出文件`。
- `vuln_plans/<stem>/`：`high-risk-*.md`、`medium-risk-*.md`、`low-risk-*.md`、`none-risk-*.md`。
- `vuln_findings/` 与 `vuln_reviews/`：`VULN-*.md`、`NOVULN-*.md`、`SUSPECTED-*.md`
  （正则 `^(?:VULN|NOVULN|SUSPECTED)-<stem>-\d+\.md$`）。

## Prompt 系统

- 模板在 `biz_recon/prompts/*.txt`。`prompt.read_prompt()` 做**安全**的 `{key}` 替换（遇到未知
  `{placeholders}` 如 `{METHOD}` 不会崩），并把 `{include:file.md}` 标记解析到
  `biz_recon/references/`（允许嵌套 include，按文件名去重）。
- 标准模板变量：`{tool_dir}`、`{target_work_dir}`、`{surface_file}`、`{surface_stem}`、
  `{extra_prompt}`、`{analysis_plan}`。
- `references/` 存放原则、`FALSE-rules.md`、`surface-format.md` 和 `vuln_rules/*.md`（按漏洞类型的
  规则）- 即注入 prompt 的知识库。

## `prompts-ext/`（策略注入）

放入一个文件即可向对应阶段的 prompt 追加策略；删除即恢复默认。**今天代码真正读取的只有两个：**
- `surface_discover.md` -> 追加到 recon 阶段 prompt（与 `--recon-prompt` 合并）。
- `postprocess-prompt.md` -> 还*守护* Stage 4 是否运行。

`prompts-ext/README.md` 还列了更多映射（`surface_analyze.md`、`plan_vuln_tasks.md`、
`vuln_analyze.md`、`review_vuln.md`），但那些**未接线** - 对应阶段只认 `--*-prompt` CLI 标志。
不要指望那些文件生效，除非在阶段模块里加上加载代码。

## 配置

`config/analysis-config.yaml` 控制阶段/并发/超时。**由 `runner.load_config()` 里的手写解析器解析，
不是 YAML 库**，尽管扩展名是 `.yaml`：它按第一个 `:` 切分每行、剥离 `#` 注释、并做 `true`/`false`/整数
的强转。保持扁平的 `key: value` - 嵌套结构、数组或真正的 YAML 特性会静默失效。

关键 key：`max_workers`、`vuln_workers`、`timeout_surface_discover`、`timeout_default`
（分钟 -> 秒）、`vuln_planning`、`attack_surface_collection`、`vulnerability_analysis`、
`vuln_re_analysis`、`allow_sibling_access`、`decompile`、`bytecode_analysis`。

## 并发与超时

两个 `ThreadPoolExecutor` 线程池：`max_workers`（发现 + 分析/规划）和 `vuln_workers`
（漏洞 + 复核）。每个任务都会 spawn 一个子进程 opencode 调用，所以高并发 = 大量并行 LLM 进程。
超时：surface_discover 120 分钟，其他 60 分钟（可配置）。SIGINT 会设置中断标志（在飞子进程跑完，
但不启动新阶段）。

## 日志

`var/logs/pipeline.log`（INFO）和 `pipeline_thinking.log`（DEBUG - 含完整渲染后的 prompt）。
两者都被 gitignore。

## 仓库布局说明

- `agent_env/`：独立 opencode profile（`llm-config.json` + 可放入的 `skills/` 和 `agents/`，两者都是
  gitkeep 的空目录）。它的 `node_modules`/`package.json` 被 gitignore（opencode 运行时，非项目依赖）。
- 根 `package.json` 只为（非核心的）`analyze_slides.py` intro-deck 生成器拉取 `pptxgenjs`。核心管道
  是纯 Python。
- Windows 通过 `llm-run.py`/`llm-run.bat` 支持；`run.py` 在 Windows 上把 stdout/stderr 包成 UTF-8。
