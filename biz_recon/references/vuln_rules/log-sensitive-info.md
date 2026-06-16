敏感信息（密码、Token、密钥、证书私钥、手机号、邮箱、Cookie等）被写入日志、控制台输出或错误响应：

- 日志框架（`logger.info/warn/error/debug`、`log4j`、`slf4j` 等）字符串拼接敏感参数 → 确认该字段是否确实落入日志文件
- 控制台输出（`System.out.println`、`print`、`console.log` 等）包含敏感字段原文
- 异常消息 / `toString()` / 序列化输出中包含敏感字段值
- HTTP 错误响应体直接返回敏感字段原文
- 请求体/响应体整体落日志（如 `log.info("Request: " + request.toString())`）未排除敏感字段

误报排除：
- 用户 ID、用户名、昵称、非私钥的证书字段不在此范围
- 确认字段是否被 `@JsonIgnore`、`@ToString.Exclude`、脱敏注解或自定义 `toString()` 排除
