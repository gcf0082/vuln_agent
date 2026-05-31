# 漏洞规则索引（哨兵模式）

采用**哨兵模式**：只列出有哪些模式，不包含规则细节。分析过程中发现特定模式时，**按需加载** `{tool_dir}/references/vuln_rules/` 下对应的规则文件进行深入分析。**禁止一次性加载该目录下所有规则文件，也禁止加载不匹配当前场景的规则文件。**

所有规则文件位于 `{tool_dir}/references/vuln_rules/` 目录下，表格中仅列出文件名。

"模式"按分类列出，根据分析过程中发现的特征类型查找对应的规则文件。

| 分类 | 模式 | 规则文件 |
|---|---|---|
| 代码特征 | Java 数组方式执行命令 | java-command-array.md |
| 代码特征 | 代码中直接看到 `/tmp` 路径（非变量引用） | tmp-privesc.md |
| 代码特征 | HTTP 参数作为循环条件 | http-loop-dos.md |
| 代码特征 | 发送 HTTP 请求读取 header、响应 | http-forward-response-dos.md |
| 代码特征 | 监听端口 | port-binding-check.md |
| 代码特征 | 修改第三方对接信息（含认证凭据） | thirdparty-credential-leak.md |
| 代码特征 | 软件包签名校验 | package-signature-bypass.md |
| 代码特征 | 数字签名校验 | digital-signature.md |
| 代码特征 | 解压压缩包 | zip-bomb.md |
| 其他 | 本地提权分析 | local-privilege-escalation.md |
| 代码特征 | 执行命令参数可控 | cmd-param-injection.md |
| 代码特征 | 使用正则表达式 | redos-check.md |
| 代码特征 | 解密并赋值变量 | decrypt-memory-cleanup.md |
