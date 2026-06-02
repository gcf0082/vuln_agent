# 命令注入 — GET /ping host 参数

**验证目标**：确认是否存在命令注入漏洞

**疑点位置**：
- `src/main/java/com/example/demo/controller/PingController.java:24` — 接收 `host` 参数，无任何校验注解
- `src/main/java/com/example/demo/util/ScriptRunner.java:17-19` — 拼接命令字符串并执行
- `src/main/resources/scripts/ping.sh:2` — `$1` 未加引号，助长注入

**疑点原因**：
- `host` 参数完全由 HTTP query 传入，外部可控，且无 `@Pattern`、`@Size`、`@NotNull` 等任何校验
- `ScriptRunner.run()` 将 `host` 直接拼入 `cmd = scriptPath + " " + host`，通过 `Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd})` 执行
- 即使调用方做了转义，ping.sh 中 `$1` 未加引号，也会发生 shell 单词拆分和通配符扩展，进一步降低利用门槛
- 注意：`host` 的最终来源不限于 HTTP 请求自身；若系统中其他接口或模块（如数据库导入、消息队列消费）能向 `host` 字段写入数据，同样可触发该命令执行路径

**优先级**：高
