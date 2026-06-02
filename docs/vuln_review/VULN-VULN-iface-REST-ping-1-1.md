# VULN-命令注入 — GET /ping host 参数

**审查结论**：有漏洞
**审查理由**：该应用是完整独立系统（`DemoApplication.java:8` 含 `main` 方法启动 Web 服务，`pom.xml` 仅依赖 `spring-boot-starter-web`，无 Spring Security、无过滤器、无拦截器），不存在外部网关或认证层作为补偿措施。`PingController.java:18` 接收的 `host` 参数经 `PingServiceImpl → CommandExecutor → ScriptRunner` 四层纯透传至 `ScriptRunner.java:17` 直接拼接为 `scriptPath + " " + host`，并在 `ScriptRunner.java:18` 通过 `Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd})` 交由 shell 执行——`;`、`` ` ``、`$()`、`|` 等元字符均可触发任意命令。即便 Java 层做了转义，`ping.sh:2` 中 `$1` 未加引号仍可通过 shell 单词拆分/通配符扩展绕过。命令输出经 `BufferedReader` 读取并返回 HTTP 响应，非盲注。证据链完整，无业务层防护措施，CVSS 9.8 合理。
