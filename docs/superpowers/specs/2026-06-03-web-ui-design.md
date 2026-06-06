# Web UI + Project Management Design

为 vuln_agent 增加 Web 界面和项目管理功能。

## 目录结构

```
vuln_agent/
├── db.py                          # SQLite 操作封装 + import_stage()
├── run.py                         # CLI 入口，新增 --project 参数
├── web/
│   ├── __init__.py
│   ├── app.py                     # Flask 入口
│   ├── api.py                     # REST API 路由
│   └── static/                    # 纯静态 SPA
│       ├── index.html             # 入口页，hash 路由
│       ├── app.js                 # 前端路由 / 交互逻辑
│       └── style.css              # 样式
├── biz_recon/
│   └── runner.py                  # 每阶段后调 db.import_stage()
└── var/projects/                  # 项目数据根目录
    └── {project_name}/
        ├── results.db             # SQLite 数据库
        ├── logs/                  # 项目日志（原 logs/ 的内容）
        │   ├── {ts}_runner.log
        │   ├── {ts}_collect.log
        │   ├── {ts}_analyze.log
        │   ├── {ts}_taskplan.log
        │   ├── {ts}_vuln.log
        │   ├── {ts}_review.log
        │   └── prompts/           # LLM 提示词日志
        └── _output/               # 原始输出文件（同现有结构）
```

## 数据库

每个项目一个独立的 `var/projects/{project_name}/results.db`。

### 表结构

```sql
CREATE TABLE project_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE surfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE vuln_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE vuln_review (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);
```

`projects` 表存项目注册信息（Web 端通过 API 创建的项目会写入此表）：

```sql
CREATE TABLE projects (
    name TEXT PRIMARY KEY,
    target_dir TEXT NOT NULL,
    collect_prompt TEXT DEFAULT '',
    analyze_prompt TEXT DEFAULT '',
    vuln_prompt TEXT DEFAULT '',
    model TEXT DEFAULT '',
    agent TEXT DEFAULT '',
    force_surface TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now'))
);
```

status 取值：`pending` / `running` / `done` / `error`。

## REST API

| 方法 | 路径 | 功能 |
|------|------|------|
| GET | `/api/projects` | 项目列表 |
| POST | `/api/projects` | 创建项目 |
| GET | `/api/projects/<id>` | 项目详情 |
| POST | `/api/projects/<id>/run` | 触发分析管道 |
| DELETE | `/api/projects/<id>` | 删除项目 |
| GET | `/api/projects/<id>/files/<stage>` | 按阶段取文件列表 |
| GET | `/api/projects/<id>/files/<stage>/<file_id>` | 取单个文件 Markdown 内容 |

### POST /api/projects 请求体

```json
{
  "name": "my-project",
  "target_dir": "/path/to/target",
  "collect_prompt": "",
  "analyze_prompt": "",
  "vuln_prompt": "",
  "model": "gpt-4",
  "agent": "",
  "force_surface": ""
}
```

### GET /api/projects/:id/files/:stage 响应

```json
{
  "stage": "vulnerabilities",
  "files": [
    {"id": 1, "filename": "VULN-iface-REST-ping-1-1.md", "created_at": "2026-06-03 12:00:00"},
    {"id": 2, "filename": "SUSPECTED-iface-REST-ping-1-2.md", "created_at": "2026-06-03 12:01:00"}
  ]
}
```

### GET /api/projects/:id/files/:stage/:file_id 响应

```json
{
  "id": 1,
  "filename": "VULN-iface-REST-ping-1-1.md",
  "content": "# 命令注入...\n**类型**：命令注入...",
  "created_at": "2026-06-03 12:00:00"
}
```

## CLI 改动

`run.py` 新增 `--project` 参数：

```bash
python3 run.py /target --project my-project
python3 run.py /target --project my-project --vuln-prompt "重点关注XSS"
python3 run.py --test --project my-project
```

- 指定 `--project` 时：项目目录 `var/projects/{name}/` 若不存在则创建，初始化 `results.db`
- 未指定时：扫描 `var/projects/` 下 `project_N` 模式，取最大 N+1 作为项目名
- 项目创建后自动写入 `project_meta`（目标目录、参数等）

## 日志目录变更

当前日志写在工作目录的 `logs/` 下。项目模式下改为每个项目自己的日志目录：

```
# 非项目模式（无 --project）：保持原路径 logs/
# 项目模式（有 --project）：var/projects/{name}/logs/
```

`setup_logging()` 接收可选的 base_dir 参数，项目模式下传入项目路径作为 base_dir。
- `logs/` → `{project_path}/logs/`
- `logs/prompts/` → `{project_path}/logs/prompts/`

## 阶段后导入

`biz_recon/runner.py` 每阶段完成后调用 `db.import_stage(db_path, stage_name, stage_dir)`：

- `import_stage` 扫描 `stage_dir` 下所有 `.md` 文件
- 对每个文件执行 `INSERT OR IGNORE` 到对应表
- stage_name → table_name 映射：`surfaces`, `analysis`, `vuln_tasks`, `vulnerabilities`, `vuln_review`

`db.py` 放在项目根目录，作为共享模块，被 `web/` 和 `biz_recon/` 共同引用。

## 前端

纯静态 SPA，Hash 路由：

```
#/projects                          项目列表 + 创建表单
#/projects/<id>                     项目详情（阶段文件树 + 基本信息）
#/projects/<id>/<stage>             阶段文件列表
#/projects/<id>/<stage>/<file_id>   文件 Markdown 渲染
```

- `fetch` 调 REST API
- `marked.js`（CDN）渲染 Markdown → HTML
- `highlight.js`（CDN）代码高亮
- 原生 JS 或 `petite-vue` 做数据绑定和路由

## Web 后端

```python
# web/app.py — Flask 入口
from flask import Flask
from .api import api_bp

def create_app():
    app = Flask(__name__, static_folder='static')
    app.register_blueprint(api_bp, url_prefix='/api')
    return app
```

```python
# web/api.py — REST API 路由
from flask import Blueprint, jsonify, request
...
```

- `create_project()`：创建项目目录、初始化 `results.db`、写入 `project_meta`
- `/api/projects/:id/run`：`subprocess.Popen` 异步调用 `python3 run.py`，不阻塞 API

## 依赖变更

新增依赖（`requirements.txt`）：
- `flask` — Web 框架
- `marked`（前端 CDN）— Markdown 渲染
- `highlight.js`（前端 CDN）— 代码高亮
