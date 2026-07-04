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

## 工具使用建议

1. **先测试连通性** — 执行完整管道前先用 `--test` 确认 LLM 正常响应：

   ```bash
   python3 run.py --test
   python3 run.py --test --model w3/MiniMax-M2.7
   ```

   确认输出为模型自身名称后，直接执行完整分析：

   ```bash
   python3 run.py /path/to/target
   ```

2. **善用断点续跑** — 各阶段产物持久化在 `.vuln_agent_output/` 下，已完成的阶段不会重复执行。例如暴露面识别完成后退出，再次运行 `python3 run.py /target` 会自动跳过 `recon` 从 `flow` 继续。需重跑某阶段时用 `--stage` + `--overwrite`。

3. **提高暴露面识别精度** — `--recon-prompt` 可根据产品类型调整扫描焦点，减少无关噪声。默认扫描会收集所有类型入口（REST/MQ/CLI/脚本等），但不同产品的暴露面差异很大：

   - 纯 REST 后端 → 只需采集 Controller 接口，不应收集脚本
   - 数据处理管道 → 应重点关注 MQ 消费者和文件监听
   - CLI 工具 → 只应收集命令行入口

   通过 `--recon-prompt` 指定范围（如 `"只采集 REST 接口"`），能让识别更精准，提高后续分析效率。

## 命令行参数

```bash
python3 run.py [work_dir] [选项]
```

| 参数 | 说明 |
|------|------|
| `work_dir` | 目标代码目录（默认当前目录） |
| `--recon-prompt TEXT` | 暴露面识别阶段追加提示词 |
| `--flow-prompt TEXT` | 业务流分析阶段追加提示词 |
| `--vuln-prompt TEXT` | 漏洞分析阶段追加提示词 |
| `--verify-prompt TEXT` | 二次审查阶段追加提示词 |
| `--thinking` | 显示 LLM 思考过程 |
| `--model MODEL` | 指定模型名称 |
| `--agent AGENT` | LLM 代理程序名称（`nga` 或 `opencode`），默认自动检测 |
| `--force-surface FILE` | 强制重新分析指定攻击面（逗号分隔，支持 `*` 通配），会清除已有产物 |
| `--stage {recon,flow,vuln,verify}` | 只运行单个阶段 |
| `--overwrite` | 与 `--stage` 搭配，删除该阶段已有产物后重新执行 |
| `--multi` | 多目标模式：将 `work_dir` 作为父目录，对其下每个子目录独立执行完整管道 |
| `--test` | 测试 LLM 连通性（询问模型自身名称），不执行管道 |

### 示例

```bash
# 指定模型运行完整管道
python3 run.py /target --model w3/MiniMax-M2.7

# 暴露面识别阶段追加提示
python3 run.py /target --recon-prompt "从 /path/to/接口清单.xlsx 提取 REST 接口，不要扫描代码"

# 业务流分析阶段追加提示
python3 run.py /target --flow-prompt "重点分析参数校验逻辑"

# 漏洞分析阶段追加提示
python3 run.py /target --vuln-prompt "优先分析命令注入和路径穿越"

# 二次审查阶段追加提示
python3 run.py /target --verify-prompt "重点验证命令注入结论"

# 测试 LLM 连通性
python3 run.py --test
python3 run.py --test --model w3/MiniMax-M2.7

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

# 覆盖重跑单个阶段（删除已有产物）
python3 run.py /target --stage recon --overwrite    # 重新收集暴露面
python3 run.py /target --stage flow --overwrite     # 重新分析业务流
python3 run.py /target --stage vuln --overwrite     # 重新漏洞分析
python3 run.py /target --stage verify --overwrite   # 重新二次审查

# 多目标分析：父目录下的每个子目录独立执行完整管道
python3 run.py /parent --multi

# 多目标 + 指定模型
python3 run.py /parent --multi --model w3/MiniMax-M2.7

# 多目标 + 只跑某个阶段
python3 run.py /parent --multi --stage recon
```

## 输出产物

```
.vuln_agent_output/
├── discovered_surfaces/   # Stage 1 (surface_discover): 攻击面记录，每文件一个条目
├── analyzed_surfaces/     # Stage 2 (surface_analyze): 攻击面深度分析（含流程图、数据流追踪）
├── vuln_findings/         # Stage 3 (vuln_analyze): 漏洞结论（VULN-/DISMISSED-/CLEAN-/SUSPECTED-）
├── vuln_reviews/          # Stage 4 (review_vuln): 二次审查结论（VULN-/NOVULN-/SUSPECTED-）
```

## 示例产物

`<分析目标>/.vuln_agent_output` 目录包含各阶段产出的示例文件，可点击查看：

- [Stage 1 攻击面识别](docs/surfaces/iface-REST-ping.md)
- [Stage 2 攻击面分析](docs/analysis/iface-REST-ping.md)
- [Stage 3 漏洞结论](docs/vulnerabilities/VULN-iface-REST-ping-1-1.md)
- [Stage 4 二次审查](docs/vuln_review/VULN-VULN-iface-REST-ping-1-1.md)



