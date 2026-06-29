---
name: biz-context-analyzer
description: Analyze target business context and map attack surface using industry-standard ASM methodology
---

# 业务上下文与暴露面分析

基于 OWASP Attack Surface Analysis、CAASM 和 EASM 行业方法论，适用于代码级暴露面识别。

## 核心原则：暴露面不在多，在准

**暴露面必须是分析目标外部可到达的入口，不是内部组件。**

判断标准只有一个：**是否有数据从分析目标外部流入？**

| 是暴露面 | 不是暴露面 |
|---------|-----------|
| Controller（收到 HTTP 请求） | Service（被 Controller 调用） |
| MQ 消费者（监听外部队列） | 内部 Event Bus 监听 |
| CLI 命令（接收外部参数） | 不接收参数的内部定时任务 |
| 文件上传处理 | 内部 Filter（仅转发） |
| 对外暴露的 WebSocket | Repository/DAO（数据访问层） |

标记过多内部组件会稀释真正的高风险入口，让分析失焦。

## 阶段一：资产发现（Asset Discovery）

从已知种子开始，向外扩展，发现所有潜在入口点：

- **Web 端点**：扫描所有 `@RequestMapping`、`@GetMapping`、`@PostMapping`、路由注册、Servlet/Filters
- **异步入口**：MQ 消费者（监听外部队列/Topic）、gRPC 服务、WebSocket/SSE 端点、GraphQL Resolver
- **非网络入口**：CLI 命令（main 函数）、Scheduled tasks（**仅接收外部参数的**）、文件 watch/处理
- **第三方集成**：所有 HTTP 外呼（RestTemplate/Feign/WebClient）、数据库访问、远程文件系统调用

> OWASP ASD 原则：不仅要找 Spider 能发现的端点，还要找未链接的隐藏端点。静态分析 route 注册 + 参数定义，而非爬虫。

## 阶段二：入口分类（Classification & Tagging）

每个入口点标记以下维度：

| 维度 | 标签 | 说明 |
|------|------|------|
| 访问级别 | anonymous / authenticated / admin | 是否可匿名访问 |
| 协议 | HTTP / MQ / gRPC / CLI | 入口类型 |
| 数据源 | path / query / body / header / file / env | 参数来源 |
| 外部系统 | service-a / db / s3 / 三方API | 是否调用外部系统 |

OWASP 强调：**远程匿名入口是高危区域**，优先标记。

## 阶段三：信任边界映射（Trust Boundary Mapping）

CAASM 核心思想：通过关系映射理解资产间如何连接。

- **外部边界**：系统接收外部数据的所有入口点
- **内部边界**：Service 层、Repository 层（被 Controller 调用，非独立入口）
- **信任边界**：认证/授权检查的位置，参数校验的位置
- **外部调用**：当前分析范围之外的其他服务、DB、文件系统

**输出** `.vuln_agent_output/meta/trust-boundaries.md`，标注每层入口到信任边界的距离。

## 阶段四：完整性校验（Completeness Check）

防止漏标的行业方法：

1. **框架已知模式**：对比框架已知的 route 注册模式与已发现列表，检查是否有遗漏（如未扫描的子模块）
2. **目录结构推导**：按 `controller/`、`handler/`、`listener/`、`scheduler/`、`job/`、`cmd/` 等模式检查未扫描目录
3. **配置文件交叉验证**：从 `web.xml`、`application.yml`、路由配置类中提取注册的路由和已发现的对照
4. **构建产物验证**：检查编译后的 class 文件/路由清单

## 阶段五：排除项文档化（Exclusion Documentation）

记录已确认的内部组件，避免重复分析：

- 内部定时任务（无外部输入）
- 内部 Event Bus / 领域事件
- 内部 Filter/Interceptor（仅转发内部请求）
- Service 层实现
- 启动类/配置类

## 输出文件

| 文件 | 内容 |
|------|------|
| `meta/biz-context.md` | 系统用途、技术栈、业务实体、数据流简图 |
| `meta/trust-boundaries.md` | 信任边界映射、入口到边界距离 |
| `meta/excluded-paths.md` | 已排除的内部组件清单 |
| `discovered_surfaces/*.md` | 每个入口点一个文件 |

## 参考

- OWASP Attack Surface Analysis Cheat Sheet
- OWASP WSTG - Attack Surface Identification  
- OWASP Attack Surface Detector (ASD)
- CAASM: NIST SP 800-204, Rapid7/Tenable/NetSPI ASM框架
- CISA BOD 23-01: 自动资产发现
