# 攻击面条目

- **类型**：iface
- **分类**：REST
- **来源**：src/main/java/com/example/demo/controller/PingController.java:18 ping()
- **描述**：接口健康检查，执行系统 ping 命令并返回结果
- **URL**：GET /ping
- **方法**：ping()
- **参数**：query: host (default: "8.8.8.8")
- **发现**：host 参数直接来源于用户 URL 查询参数，未经任何校验即传入后续 shell 命令执行流程
