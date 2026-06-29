---
name: surface-discovery
description: 基于超细粒度分析的暴露面识别方法论
---

# 暴露面识别（纯思维方法）

## 目的

本 skill 定义了在扫描代码库时**如何思考**暴露面识别。
不产生输出文件，仅用于指导识别过程。

## 何时使用

- 需要系统性发现所有外部入口点时
- 需要区分内部组件与真实暴露面时
- 需要防漏标、防滥标时

## 核心原则

暴露面不在多，在准。判断标准只有一个：
**是否有数据从分析目标外部流入？**

| 是暴露面 | 不是暴露面 |
|---------|-----------|
| Controller（收到 HTTP 请求） | Service（被 Controller 调用） |
| MQ 消费者（监听外部队列） | 内部 Event Bus 监听 |
| CLI 命令（接收外部参数） | 不接收参数的内部定时任务 |
| 文件上传处理 | 内部 Filter（仅转发） |
| 对外暴露的 WebSocket | Repository/DAO（数据访问层） |

## 阶段一：初始定位（逐文件扫描）

对每个相关的模块/目录，识别：

### 1. Web 端点

扫描 route 注册（注解/xml/代码注册），每个入口记录：
- 真实路径和 HTTP 方法
- 参数来源（path/query/body/header）
- 访问级别（anonymous/auth/admin）
- 代码位置（文件:行号）

### 2. 异步入口

MQ 消费者、gRPC 服务、WebSocket：
- 监听来源（外部队列 vs 内部事件）
- 消息体结构和来源

### 3. 非网络入口

CLI 命令、独立脚本：
- 是否接收外部参数（argv/env/stdin）
- 入口位置（main 函数或文件）

### 4. 排除确认

以下直接排除，不标记为暴露面：
- 内部定时任务（无外部输入）
- 内部 Filter/Interceptor（仅转发）
- Service 层实现
- 内部 Event Bus / 领域事件监听
- 启动类/配置类
- 纯工具类/工具函数

## 方法论（引自 audit-context-building, Trail of Bits）

### 第一性原理

不凭名字推断行为，阅读实际代码。名为 `safeTransfer` 的函数未必安全，名为 `executeCommand` 的函数就一定是入口？

### 5 Whys

追问到这个点到底是不是外部入口：
- 为什么这个 Controller 不算暴露面？→ 因为它没有 route 映射
- 为什么这个 Listener 不算？→ 因为它监听的是内部事件
- 为什么这个 Scheduler 不算？→ 因为它不接收任何外部参数

### 反幻觉规则

- 每行代码引用文件:行号，不凭记忆判断
- 不对函数名做语义猜测，读实际实现
- 不确定性用"需要检查 X"，不用"大概"
- 发现矛盾时显式更新判断

## 参考

- [audit-context-building](https://github.com/trailofbits/skills)（Trail of Bits 超细粒度审计上下文构建）
- OWASP Attack Surface Analysis Cheat Sheet
- OWASP WSTG - Attack Surface Identification
