# 经验性高危模式清单

本清单用于漏洞规划阶段快速识别需优先分析的高危模式。
匹配到以下模式时，按对应优先级输出分析计划。
**高优先级先分析，中优先级次之，低优先级最后。**

参考：`{tool_dir}/references/FALSE-rules.md`，命中自动忽略类别的 → 不标记。

## 高优先级 (high-risk)

以下模式存在**明显高危操作**，需深度数据流追踪：

### 命令执行
- Runtime.exec() / ProcessBuilder — 用户输入拼入命令
- os.system() / subprocess — 用户输入拼入命令
- ScriptEngine.eval() / GroovyShell — 用户输入作为脚本

### SQL 注入
- SQL 字符串拼接（`${}` / `+` 拼接，非参数化绑定）
- MyBatis `${}` 插值

### 路径穿越
- File / Path / FileOutputStream — 用户输入拼入路径，未做规范化或 `../` 校验
- Zip Slip — ZipEntry getName 未校验路径穿越

### 反序列化
- ObjectInputStream.readObject() — 外部输入
- XMLDecoder — 外部输入
- XStream fromXML — 外部输入

### 模板注入 (SSTI)
- Freemarker / Velocity / Thymeleaf — 用户输入作为模板内容

### 表达式注入
- OGNL 表达式求值（Struts）
- SpEL 表达式求值（Spring）
- EL 表达式求值（JSP）
- MVEL 表达式求值

### 反射/代码注入
- Class.forName() — 用户输入作为类名
- Method.invoke() — 用户可控方法名
- eval() / exec() — 用户输入作为代码（Python/PHP/JS）

## 中优先级 (medium-risk)

以下模式存在**潜在高危操作**，需深度追踪确认：

### HTTP 外呼 (SSRF)
- URL / HttpURLConnection — 用户输入拼入 URL
- OkHttp / Apache HttpClient — 用户输入拼入 URL
- RestTemplate / WebClient — 用户输入拼入 URL

### XML 安全 (XXE)
- DocumentBuilder / SAXParser / XMLReader — 外部实体未禁用

### XPath 注入
- XPath.compile() / XPath.evaluate() — 用户输入拼入 XPath

### LDAP 注入
- LdapContext.search() — 用户输入拼入 LDAP 查询

### NoSQL 注入
- MongoDB / Redis — 用户输入拼入查询

### 文件上传
- MultipartFile — 未校验文件名/类型/大小

## 低优先级 (low-risk)

以下模式风险较低，标准分析即可覆盖：

### 开放重定向
- response.sendRedirect() — 用户输入作为跳转地址

### 信息泄露
- 异常堆栈返回给客户端
- 调试信息暴露

### 弱加密/不安全随机数
- DES / MD5 / SHA1 用于密码或敏感数据
- java.util.Random 用于安全令牌

### 硬编码凭证
- 代码中硬编码密码、Token、密钥

### 日志注入
- 用户输入直接拼入日志语句
