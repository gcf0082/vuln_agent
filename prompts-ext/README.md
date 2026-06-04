# Pipeline Strategy Files

在 `collect.md` 中写入收集策略 → 自动追加到该阶段 LLM 的 `{extra_prompt}` 中，与命令行 `--extra` 传入的**用户特殊要求**一起走已有占位符。

两种来源最终合并为同一段内容传给 LLM：

```
**用户特殊要求：**{命令行传入}

**用户自定义策略（来自 agent_env/pipeline-ext/collect.md）**
{文件内容}
```

## 文件名 → 阶段对照

| 文件名 | 对应阶段 |
|--------|---------|
| `collect.md` | surface collection |

## 回退

删除对应文件即恢复默认行为。
