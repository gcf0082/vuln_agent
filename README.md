# vuln-agent

基于 LLM 的多阶段源码分析工具，从源码发现攻击面、追踪数据流、识别潜在漏洞并二次验证。

## 前置条件

依赖 `nga` 或 `opencode` CLI。

## 快速开始

对一个目标代码目录运行完整分析管道：

```bash
python3 run.py /path/to/target
```

无参数时显示帮助信息：

```bash
python3 run.py
```

## 命令行参数

```bash
python3 run.py [work_dir] [选项]
```

| 参数 | 说明 |
|------|------|
| `work_dir` | 目标代码目录（默认当前目录） |
| `--collect-prompt TEXT` | 暴露面识别阶段追加提示词 |
| `--analyze-prompt TEXT` | 攻击面深度分析阶段追加提示词 |
| `--vuln-prompt TEXT` | 漏洞分析及二次审查阶段追加提示词 |
| `--thinking` | 显示 LLM 思考过程 |
| `--model MODEL` | 指定模型名称（如 `gpt-4`、`claude-sonnet-4`） |
| `--agent AGENT` | LLM 代理程序名称（`nga` 或 `opencode`），默认自动检测 |
| `--force-surface FILE` | 强制重新分析指定攻击面（逗号分隔，支持 `*` 通配），会清除已有产物 |
| `--test` | 测试 LLM 连通性（询问模型自身名称），不执行管道 |

### 示例

```bash
# 指定模型运行完整管道
python3 run.py /target --model gpt-4

# 暴露面识别阶段追加提示
python3 run.py /target --collect-prompt "重点关注登录后接口"

# 攻击面分析阶段追加提示
python3 run.py /target --analyze-prompt "重点分析参数校验逻辑"

# 漏洞分析阶段追加提示
python3 run.py /target --vuln-prompt "优先分析命令注入和路径穿越"

# 测试 LLM 连通性
python3 run.py --test
python3 run.py --test --model gpt-4 --agent nga

# 指定代理程序
python3 run.py /target --agent opencode

# 显示 LLM 思考过程
python3 run.py /target --thinking

# 强制重新分析特定攻击面
python3 run.py /target --force-surface "iface-upload-*"

# 只运行单个阶段
python3 run.py /target --stage recon    # 仅暴露面识别
python3 run.py /target --stage flow     # 仅业务流分析
python3 run.py /target --stage vuln     # 仅漏洞分析
python3 run.py /target --stage verify   # 仅二次审查
```

## 输出产物

```
.vuln_agent_output/
├── discovered_surfaces/   # Stage 1 (surface_discover): 攻击面记录，每文件一个条目
├── analyzed_surfaces/     # Stage 2 (surface_analyze): 攻击面深度分析（含流程图、数据流追踪）
├── vuln_findings/         # Stage 3 (vuln_analyze): 漏洞结论（VULN-/DISMISSED-/CLEAN-/SUSPECTED-）
├── vuln_reviews/          # Stage 4 (review_vuln): 二次审查结论（VULN-/NOVULN-/SUSPECTED-）
└── meta/                  # 排除路径记录、中间分析产物
```

## 示例产物

`<分析目标>/.vuln_agent_output` 目录包含各阶段产出的示例文件，可点击查看：

- [Stage 1 攻击面识别](docs/surfaces/iface-REST-ping.md)
- [Stage 2 攻击面分析](docs/analysis/iface-REST-ping.md)
- [Stage 3 漏洞结论](docs/vulnerabilities/VULN-iface-REST-ping-1-1.md)
- [Stage 4 二次审查](docs/vuln_review/VULN-VULN-iface-REST-ping-1-1.md)


## 日志

```
logs/
├── prompts/               # 每次 LLM 调用的完整提示词，按时间戳命名
│   └── 20260601_120030_123_prompt.txt
├── 20260601_120030_runner.log       # 管道级运行日志
├── 20260601_120030_collect.log      # Stage 1 暴露面收集
├── 20260601_120030_analyze.log      # Stage 2 攻击面分析
├── 20260601_120030_taskplan.log     # Stage 2.5 任务规划
├── 20260601_120030_vuln.log         # Stage 3 漏洞分析
└── 20260601_120030_review.log       # Stage 4 二次审查
```

各阶段日志文件按 `{时间戳}_{阶段}_{文件名}` 命名，并行执行时为每个分析目标独立生成日志文件，避免多线程日志交错。

