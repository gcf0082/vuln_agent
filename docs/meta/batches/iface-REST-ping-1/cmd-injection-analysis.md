# 批次分析：命令注入 — GET /ping host 参数

## 分析说明

本批次分析基于漏洞规则索引中的 `cmd-param-injection.md`。

## 分析过程

### 入口 → 参数流向

| 层级 | 文件 | 行号 | 代码 | 是否做校验/过滤 |
|------|------|------|------|----------------|
| Controller | PingController.java | 18 | `@RequestParam(defaultValue = "8.8.8.8") String host` | 否 |
| Service | PingServiceImpl.java | 17-18 | `commandExecutor.execute(host)` | 否，纯透传 |
| Executor | CommandExecutor.java | 14-15 | `scriptRunner.run(host)` | 否，纯透传 |
| ScriptRunner | ScriptRunner.java | 17-18 | 拼接并执行 | 否，直接拼接 |

### 敏感操作槽

**文件**：`ScriptRunner.java:17-18`
```java
String cmd = scriptPath + " " + host;
Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
```

**文件**：`ping.sh:2`
```bash
ping -c 3 $1
```

### 分析结论

所有四层调用均无校验、无转义、无过滤。`host` 完全受控于外部 HTTP 请求，直接拼接到 `/bin/sh -c` 命令字符串中，且脚本中 `$1` 未加引号。

**判定**：命令注入漏洞确认（VULN）

### 匹配规则检查

| 规则模式 | 检查结果 |
|----------|----------|
| cmd-param-injection.md — 高危参数注入 | 无额外参数注入场景，但基本原理（参数可控直接拼命令）完全匹配 |
| cmd-param-injection.md — 空格攻击 | 未加引号的 `$1` 允许单词拆分，附带加剧风险 |
