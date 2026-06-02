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
- `test_llm.py` — 连通性测试
