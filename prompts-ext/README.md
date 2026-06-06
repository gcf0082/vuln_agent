# Pipeline Strategy Files

在 `surface_discover.md` 中写入该阶段的策略 → 自动追加到对应阶段 LLM 的 `{extra_prompt}` 中，与命令行 `--xxx-prompt` 传入的**用户特殊要求**一起走已有占位符。

两种来源最终合并为同一段内容传给 LLM：

```
**用户特殊要求：**{命令行传入}

**用户自定义策略（来自 prompts-ext/<stage>.md）**
{文件内容}
```

## 文件名 → 阶段对照

| 文件名 | 对应阶段 |
|--------|---------|
| `surface_discover.md` | surface_discover（暴露面识别） |
| `surface_analyze.md` | surface_analyze（攻击面分析） |
| `plan_vuln_tasks.md` | plan_vuln_tasks（漏洞分析任务规划） |
| `vuln_analyze.md` | vuln_analyze（漏洞分析） |
| `review_vuln.md` | review_vuln（漏洞审查） |

## 回退

删除对应文件即恢复默认行为。
