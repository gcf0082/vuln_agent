# opencode_wrapper — Python 封装 OpenCode CLI

通过 Python 调用 OpenCode CLI，每次调用运行在完全独立的环境中，支持自定义 skills 和 agents 的多选加载。

## 快速开始

### 2. 准备 skills 和 agents 仓库

目录结构：

```
my_skills/                  # skills 仓库（名称不限）
├── formal-responder/
│   └── SKILL.md            # OpenCode 原生 skill 格式
└── json-mode/
    └── SKILL.md

my_agents/                  # agents 仓库（名称不限）
├── planner.md              # OpenCode 原生 agent 格式（.md + frontmatter）
└── qa-reviewer.md
```

### 3. 调用

```python
from opencode_wrapper import OpenCodeClient, SkillsRepo, AgentsRepo, ProfileConfig

client = OpenCodeClient(
    skills_repo=SkillsRepo("./my_skills"),
    agents_repo=AgentsRepo("./my_agents"),
)

result = client.run("写一个 Python 装饰器示例", ProfileConfig(
    skills=["formal-responder"],      # 从仓库中选取
    agents=["planner"],
))
print(result.text)
```

## 核心概念

### 每次调用完全独立

每次 `client.run()` 创建一个临时 Profile 目录，包含完整独立的配置、skills、agents、数据、缓存、日志、状态。调用结束后自动清理，互不干扰。

```
/tmp/opencode-profile-xxx/
├── .opencode/
│   ├── skills/               # 仅本次选中的 skills
│   │   └── formal-responder/
│   │       └── SKILL.md
│   └── agents/               # 仅本次选中的 agents
│       └── planner.md
├── config.json                # 本次配置
├── data/                      # session 数据
├── cache/                     # 缓存
├── logs/                      # 日志
└── state/                     # UI 状态
```

### 只有你指定的 skill 才可见

系统 skill（如 `~/.config/opencode/skills/`、插件提供的 skill）会被以下三重机制屏蔽：

- `--pure`：禁用所有外部插件
- `OPENCODE_DISABLE_CLAUDE_CODE_SKILLS=true`：禁用 `.claude/skills/`
- 配置文件中的 `permission.skill`：拒绝所有未指定的 skill

### Skills 和 Agents 多选

从统一仓库中按名称选取，支持任意组合：

```python
# 只加载 skill
ProfileConfig(skills=["formal-responder"])

# 只加载 agent
ProfileConfig(agents=["qa-reviewer"])

# 同时加载多个
ProfileConfig(skills=["formal-responder", "json-mode"],
              agents=["planner", "qa-reviewer"])

# 不加载任何 skill/agent
ProfileConfig()
```

## API 参考

### `OpenCodeClient`

```python
client = OpenCodeClient(
    opencode_bin="opencode",       # opencode 命令路径
    skills_repo=None,              # SkillsRepo 实例
    agents_repo=None,              # AgentsRepo 实例
    env_path=".env",               # .env 文件路径
)
```

#### `client.run(prompt, profile=None, verbose=False) -> OpenCodeResult`

- `prompt`：发送给 opencode 的提示词
- `profile`：`ProfileConfig` 实例，指定本次使用的 skills/agents/model
- `verbose`：是否打印 stderr 日志

返回 `OpenCodeResult`，包含 `text`（响应文本）和 `exit_code`。

输出在生成时逐段实时打印。

### `ProfileConfig`

```python
@dataclass
class ProfileConfig:
    skills: list[str] = []        # 要加载的 skill 名称
    agents: list[str] = []        # 要加载的 agent 名称
    model: str | None = None      # 覆盖默认模型
    profile_dir: str | None = None # 持久化 profile 路径（调试用）
```

- `model` 留空则使用 `.env` 中的 `OPENCODE_DEFAULT_MODEL`
- `profile_dir` 用于调试或持久化场景，不指定则自动创建临时目录

### `SkillsRepo`

```python
repo = SkillsRepo("./my_skills")
repo.list()               # -> ['formal-responder', 'json-mode', ...]
```

仓库目录要求：每个 skill 一个子目录，内含 `SKILL.md` 文件。

### `AgentsRepo`

```python
repo = AgentsRepo("./my_agents")
repo.list()               # -> ['planner', 'qa-reviewer', ...]
```

仓库目录要求：每个 agent 一个 `.md` 文件，内含 YAML frontmatter。

### `OpenCodeResult`

```python
@dataclass
class OpenCodeResult:
    text: str             # 响应文本
    exit_code: int        # 退出码
```

## 完整示例

```python
from opencode_wrapper import OpenCodeClient, SkillsRepo, AgentsRepo, ProfileConfig

# 初始化仓库
skills_repo = SkillsRepo("./my_skills")
agents_repo = AgentsRepo("./my_agents")

print("Available skills:", skills_repo.list())
print("Available agents:", agents_repo.list())

# 创建客户端
client = OpenCodeClient(
    skills_repo=skills_repo,
    agents_repo=agents_repo,
)

# 基础查询
r1 = client.run("Say hello.")
print(r1.text)

# 带 skill
r2 = client.run("Explain API.",
                ProfileConfig(skills=["formal-responder"]))

# 带 agent
r3 = client.run("What is 2+2?",
                ProfileConfig(agents=["qa-reviewer"]))

# 多选组合
r4 = client.run("Suggest Python project ideas.",
                ProfileConfig(skills=["formal-responder", "json-mode"],
                              agents=["planner", "qa-reviewer"]))

# 模型覆盖
r5 = client.run("What model?",
                ProfileConfig(model="opencode-go/deepseek-v4-pro"))
```

## 文件说明

| 文件 | 用途 |
|------|------|
| `opencode_wrapper.py` | 核心封装（Client、Repo、ProfileConfig） |

| `example.py` | 多场景示例 |
| `.env` | 环境配置（API key、默认模型） |
| `my_skills/` | skills 仓库目录 |
| `my_agents/` | agents 仓库目录 |
