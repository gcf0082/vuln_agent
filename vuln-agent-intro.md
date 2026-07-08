# vuln-agent

AI 多智能体静态漏洞挖掘工具。

---

## 整体流程

```mermaid
flowchart TD
    subgraph 阶段一 暴露面采集
        A["采集外部暴露面<br/>如 REST 接口、脚本、定时任务等"]
    end

    subgraph 阶段二 业务流分析
        B["以每个暴露面为入口<br/>识别关键业务流<br/>如执行了什么命令、参数是否外部可控、做了哪些校验"]
    end

    subgraph 阶段三 漏洞分析
        C["基于业务流信息<br/>按需加载规则进行漏洞判定"]
    end

    subgraph 阶段四 漏洞复核
        D["独立复核漏洞结论<br/>验证利用路径和防护措施"]
    end

    A --> B --> C --> D
```

---



### 暴露面采集

> 只做暴露面识别，不做深入分析。

扫描代码仓库，识别所有外部可达的入口，包括：

| iface | noniface |
|-------|----------|
| REST 接口（URL、函数入口、代码行号） | 独立脚本工具 |
| MQ 消费者 | 定时任务 |
| gRPC、WebSocket 等 | CLI 命令入口 |

每个条目记录入口类型、精确位置、URL、参数等关键信息。

---

### 业务流分析

> 陈述事实，不下安全结论。

对每个入口点分析其业务逻辑——接收什么参数、经过哪些处理环节、最终操作什么数据。同时从安全视角标注关键控制点，如路径拼接、命令执行、SQL 查询、敏感信息日志等。

产出物是包含**请求表 + 调用链 + 关键控制点 + 入参流向 + 流程图**的分析报告：

#### 请求表

| 维度 | 详情 |
|------|------|
| path | `/ping` |
| query | `host` (default: `"8.8.8.8"`, 无校验) |
| header | 无关 |
| body | 无 |

#### 调用链

入参 `host` 经 4 层传递直达命令执行：

```
PingController.ping(host)
  → PingService.ping(host)
    → PingServiceImpl.ping(host)
      → CommandExecutor.execute(host)
        → ScriptRunner.run(host)   ← 命令拼接 + Runtime.exec
```

#### 关键控制点

```java
// ScriptRunner.java:17-18
String cmd = scriptPath + " " + host;
Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
```

```bash
# ping.sh:2 — $1 未加引号，存在单词拆分
ping -c 3 $1
```

#### 流程图

```mermaid
flowchart TD
    RECV["接收 GET /ping?host={query.host}<br/>默认 8.8.8.8"]
    NO_CHECK{"无任何参数校验<br/>无 @Pattern / @Size / @NotNull"}
    PASS["透传 host → 4 层调用链"]
    BUILD["🔴 cmd = 'scripts/ping.sh ' + {query.host}<br/>ScriptRunner.java:17"]
    EXEC["🔴 Runtime.exec(['/bin/sh','-c',cmd])<br/>ScriptRunner.java:18"]
    RESULT["返回命令输出或 Error 信息"]

    RECV --> NO_CHECK
    NO_CHECK --> PASS
    PASS --> BUILD
    BUILD --> EXEC
    EXEC --> RESULT
```

---

### 漏洞分析

> 根据业务流分析结果，按匹配的场景动态加载规则，无论结果如何均需给出详细分析过程和举证信息。

```mermaid
flowchart TD
    INPUT["业务流分析结果"] --> INDEX["规则索引文件"]
    INDEX --> LLM["LLM 根据代码特征<br/>智能匹配规则"]
    LLM -->|匹配 SQL 操作| SQLR["加载 SQL 注入规则"]
    LLM -->|匹配文件操作| FILER["加载路径穿越规则"]
    LLM -->|匹配命令执行| CMDR["加载命令注入规则"]
    SQLR --> COMP["回到代码逐项比对"]
    FILER --> COMP
    CMDR --> COMP
    COMP --> RESULT["有漏洞 / 无漏洞 / 疑似漏洞"]
```

---

### 漏洞复核

> 挑战者姿态复核漏洞

例如漏洞分析判定参数 `id` 拼入 `SELECT * FROM users WHERE id = ${id}` 存在 SQL 注入，漏洞复核检查发现参数有 `@Pattern(regexp = "^[a-zA-Z0-9]+$")` 校验，id 仅限数字字母，结论为漏洞不成立。

```mermaid
flowchart LR
    A["漏洞分析结论<br/>id 拼入 SQL 存在注入"] --> B["漏洞复核<br/>检查参数 id 的校验"]
    B --> C["有 @Pattern 正则校验<br/>^[a-zA-Z0-9]+$，id 仅限数字字母"]
    C --> D["最终结论<br/>漏洞不成立"]
```
