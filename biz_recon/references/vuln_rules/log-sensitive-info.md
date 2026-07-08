明文或加密的认证凭据类信息（密码、Token、密钥、证书私钥、Cookie等）、电话号码、邮箱地址被写入日志、控制台输出或错误响应：

- 日志框架（`logger.info/warn/error/debug`、`log4j`、`slf4j` 等）字符串拼接敏感参数 → 确认该字段是否确实落入日志文件
- 控制台输出（`System.out.println`、`print`、`console.log` 等）包含敏感字段原文
- 异常消息 / `toString()` / 序列化输出中包含敏感字段值
- HTTP 错误响应体直接返回敏感字段原文
- 请求体/响应体整体落日志（如 `log.info("Request: " + request.toString())`）未排除敏感字段

误报排除：
- 其他信息（如用户名、昵称、ID、地址、非私钥的证书字段等）不认定为敏感信息，不得因此报告漏洞
- 确认字段是否被 `@JsonIgnore`、`@ToString.Exclude`、脱敏注解或自定义 `toString()` 排除
