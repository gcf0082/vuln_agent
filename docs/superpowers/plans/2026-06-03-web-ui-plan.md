# Web UI + Project Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Flask web UI, per-project SQLite database, CLI `--project` parameter, and per-project log directories.

**Architecture:** Flask REST API (JSON-only) serves a static SPA frontend. A shared `db.py` module handles SQLite operations for both CLI and web. Each stage in `runner.py` imports generated files into the project database after completion.

**Tech Stack:** Flask (backend), static HTML/JS/CSS + marked.js + highlight.js (frontend), SQLite (storage)

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `vuln_agent/db.py` | Create | SQLite init, import_stage(), query helpers for each stage table |
| `vuln_agent/run.py` | Modify | Add `--project` param, project auto-naming, pass project_path to runner |
| `vuln_agent/biz_recon/runner.py` | Modify | Accept project_path, post-stage import via db.py, set OPENCODE_WORK_DIR |
| `vuln_agent/biz_recon/workspace.py` | Modify | `setup_logging()` accepts optional base_dir, `setup_stage_log()` uses `OPENCODE_WORK_DIR` |
| `vuln_agent/web/__init__.py` | Create | Empty package init |
| `vuln_agent/web/app.py` | Create | Flask app factory |
| `vuln_agent/web/api.py` | Create | REST API blueprint |
| `vuln_agent/web/static/index.html` | Create | SPA entry with hash routing |
| `vuln_agent/web/static/app.js` | Create | SPA client logic |
| `vuln_agent/web/static/style.css` | Create | Minimal styling |
| `vuln_agent/requirements.txt` | Modify | Add flask |

---

### Task 1: `db.py` — SQLite database helpers

**Files:**
- Create: `vuln_agent/db.py`

- [ ] **Step 1: Create `db.py` with table creation and helpers**

```python
"""SQLite database helpers for project file storage."""

import sqlite3
import os
from pathlib import Path

VAR_DIR = Path(__file__).parent / "var" / "projects"


def get_project_path(name: str) -> Path:
    return VAR_DIR / name


def init_db(db_path: str):
    """Create database and all stage tables if they don't exist."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS projects (
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

        CREATE TABLE IF NOT EXISTS surfaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS vuln_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS vuln_review (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    conn.close()


def import_stage(db_path: str, stage: str, stage_dir: str):
    """Scan stage_dir for .md files and insert into the corresponding table.

    stage → table mapping:
        surfaces → surfaces
        analysis → analysis
        vuln_tasks → vuln_tasks
        vulnerabilities → vulnerabilities
        vuln_review → vuln_review
    """
    VALID_STAGES = {"surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review"}
    if stage not in VALID_STAGES:
        raise ValueError(f"Unknown stage: {stage}")

    dir_path = Path(stage_dir)
    if not dir_path.exists():
        return

    conn = sqlite3.connect(db_path)
    for f in sorted(dir_path.glob("*.md")):
        content = f.read_text(encoding="utf-8", errors="replace")
        conn.execute(
            f"INSERT OR IGNORE INTO {stage} (filename, content) VALUES (?, ?)",
            (f.name, content),
        )
    conn.commit()
    conn.close()


def list_projects() -> list[dict]:
    """List all projects by scanning var/projects/ directories."""
    if not VAR_DIR.exists():
        return []
    projects = []
    for d in sorted(VAR_DIR.iterdir()):
        if d.is_dir():
            db_path = d / "results.db"
            if db_path.exists():
                conn = sqlite3.connect(str(db_path))
                row = conn.execute(
                    "SELECT target_dir, status, created_at FROM projects WHERE name=?",
                    (d.name,)
                ).fetchone()
                conn.close()
                if row:
                    projects.append({
                        "name": d.name,
                        "target_dir": row[0],
                        "status": row[1],
                        "created_at": row[2],
                    })
                else:
                    projects.append({
                        "name": d.name,
                        "target_dir": "",
                        "status": "unknown",
                        "created_at": "",
                    })
    return projects


def get_project(name: str) -> dict | None:
    """Get project info from its database."""
    db_path = VAR_DIR / name / "results.db"
    if not db_path.exists():
        return None
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM projects WHERE name=?", (name,)).fetchone()
    conn.close()
    return dict(row) if row else None


def count_files(db_path: str, stage: str) -> int:
    """Count files in a stage table."""
    conn = sqlite3.connect(db_path)
    count = conn.execute(f"SELECT COUNT(*) FROM {stage}").fetchone()[0]
    conn.close()
    return count


def list_files(db_path: str, stage: str) -> list[dict]:
    """List files in a stage table."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        f"SELECT id, filename, created_at FROM {stage} ORDER BY filename"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_file(db_path: str, stage: str, file_id: int) -> dict | None:
    """Get a single file by id from a stage table."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        f"SELECT id, filename, content, created_at FROM {stage} WHERE id=?",
        (file_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None
```

- [ ] **Step 2: Verify `db.py` is importable**

Run: `python3 -c "from db import init_db, import_stage, list_projects; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add db.py
git commit -m "feat: add db.py for project SQLite storage

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `run.py` — Add `--project` parameter with auto-naming

**Files:**
- Modify: `vuln_agent/run.py`

- [ ] **Step 1: Add `--project` argument to argparse**

```python
    parser.add_argument("--agent", default="",
                        help="LLM agent binary (nga or opencode)")
    parser.add_argument("--project", default="",
                        help="Project name for output tracking (auto-generated if omitted)")
```

- [ ] **Step 2: Add project auto-naming logic before calling main()**

```python
def _resolve_project(name: str) -> str:
    """Resolve project name: use given name, or auto-generate project_N."""
    if name:
        return name
    from db import VAR_DIR
    VAR_DIR.mkdir(parents=True, exist_ok=True)
    max_n = 0
    for d in VAR_DIR.iterdir():
        if d.is_dir() and d.name.startswith("project_"):
            try:
                n = int(d.name.split("_")[1])
                max_n = max(max_n, n)
            except (IndexError, ValueError):
                pass
    return f"project_{max_n + 1}"
```

- [ ] **Step 3: Pass project to main()**

```python
    project_name = _resolve_project(args.project)
    main(work_dir=args.work_dir,
         project=project_name,
         collect_prompt=args.collect_prompt,
         ...
```

- [ ] **Step 4: Update the `__main__` block to import from `db` and resolve project**

```python
if __name__ == "__main__":
    args = _parse_args()
    if args.test:
        _test_llm(model=args.model, agent=args.agent)
    else:
        from db import init_db, get_project_path
        project_name = _resolve_project(args.project)
        proj_path = get_project_path(project_name)
        proj_path.mkdir(parents=True, exist_ok=True)
        db_path = proj_path / "results.db"
        init_db(str(db_path))
        # Write project metadata
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT OR REPLACE INTO projects (name, target_dir, collect_prompt, analyze_prompt, vuln_prompt, model, agent, force_surface) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (project_name, args.work_dir or os.getcwd(),
             args.collect_prompt, args.analyze_prompt, args.vuln_prompt,
             args.model, args.agent, args.force_surface)
        )
        conn.commit()
        conn.close()
        main(work_dir=args.work_dir,
             project=project_name,
             collect_prompt=args.collect_prompt,
             analyze_prompt=args.analyze_prompt,
             vuln_prompt=args.vuln_prompt,
             thinking=args.thinking,
             force_surface=args.force_surface,
             model=args.model,
             agent=args.agent)
```

- [ ] **Step 5: Test the project auto-naming**

Run: `python3 -c "
import os, sys; sys.path.insert(0, '.')
from db import VAR_DIR, _resolve_project
print(repr(_resolve_project('')))  # should be project_1 first time
"`
Expected: `project_1`

- [ ] **Step 6: Commit**

```bash
git add run.py
git commit -m "feat: add --project parameter with auto-naming

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `biz_recon/workspace.py` — Flexible log directory

**Files:**
- Modify: `vuln_agent/biz_recon/workspace.py`

- [ ] **Step 1: Modify `setup_logging()` to accept optional `log_base` parameter**

Change signature: `def setup_logging(work_dir: Path, log_base: Path | None = None):`

When `log_base` is provided, use it as the parent for `logs/` instead of `work_dir`. For non-project mode, `log_base` = `work_dir` (backward compatible).

```python
def setup_logging(work_dir: Path, log_base: Path | None = None):
    global _logger, _prompt_logger
    base = log_base or work_dir
    log_dir = base / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    # ... rest unchanged
```

- [ ] **Step 2: Modify `setup_stage_log()` and `set_prompt_log_path()` to use `OPENCODE_WORK_DIR` for log path**

These functions currently use `Path.cwd()`. In project mode, `OPENCODE_WORK_DIR` is set to the project path.

For `set_prompt_log_path`:
```python
def set_prompt_log_path(stage: str, target: str = ""):
    work_dir = Path(os.environ.get("OPENCODE_WORK_DIR", Path.cwd()))
    # ... use work_dir instead of Path.cwd()
```

For `setup_stage_log`:
```python
def setup_stage_log(stage: str, target: str = ""):
    work_dir = Path(os.environ.get("OPENCODE_WORK_DIR", Path.cwd()))
    # ... use work_dir instead of Path.cwd()
```

- [ ] **Step 3: Commit**

```bash
git add biz_recon/workspace.py
git commit -m "refactor: setup_logging accepts log_base, stage_log uses OPENCODE_WORK_DIR

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `biz_recon/runner.py` — Project mode and post-stage import

**Files:**
- Modify: `vuln_agent/biz_recon/runner.py`

- [ ] **Step 1: Add `project` parameter to `main()`**

```python
def main(work_dir: str | None = None,
         project: str = "",
         collect_prompt: str = "",
         ...
```

- [ ] **Step 2: Resolve project path and set OPENCODE_WORK_DIR**

After `setup_logging`, add:

```python
    if project:
        from db import get_project_path, import_stage
        proj_path = get_project_path(project)
        proj_output_dir = proj_path / "_output"
        os.environ["OPENCODE_WORK_DIR"] = str(proj_path)
        db_path = str(proj_path / "results.db")
    else:
        proj_path = None
        db_path = None
        proj_output_dir = None
```

Change `setup_logging(Path.cwd())` to pass project path as log_base:

```python
    if project:
        setup_logging(Path.cwd(), log_base=proj_path)
    else:
        setup_logging(Path.cwd())
```

- [ ] **Step 3: Set OPENCODE_WORK_DIR for subprocess environment**

Set `os.environ["OPENCODE_WORK_DIR"]` to project path in project mode, so `llm-run.sh` writes logs to the project's log directory.

```python
    if project:
        os.environ["OPENCODE_WORK_DIR"] = str(proj_path)
        # Also ensure _output dirs are relative to project path
```

- [ ] **Step 4: Add import_stage calls after each stage**

```python
    try:
        collect.run(work_path, extra_prompt=collect_prompt)
        if db_path:
            import_stage(db_path, "surfaces", str(work_path / OUTPUT_PARENT / "surfaces"))

        analyze.run(work_path, max_workers, extra_prompt=analyze_prompt, only_surfaces=force_list or None)
        if db_path:
            import_stage(db_path, "analysis", str(work_path / OUTPUT_PARENT / "analysis"))

        vuln_task_plan.run(work_path, max_workers, force_list=force_list or None)
        if db_path:
            import_stage(db_path, "vuln_tasks", str(work_path / OUTPUT_PARENT / "vuln_tasks"))

        vuln.run(work_path, max_workers, extra_prompt=vuln_prompt, force_list=force_list)
        if db_path:
            import_stage(db_path, "vulnerabilities", str(work_path / OUTPUT_PARENT / "vulnerabilities"))

        reanalyze.run(work_path, max_workers, extra_prompt=vuln_prompt, force_list=force_list)
        if db_path:
            import_stage(db_path, "vuln_review", str(work_path / OUTPUT_PARENT / "vuln_review"))
```

- [ ] **Step 5: Update project status on completion/error**

```python
    except RuntimeError as e:
        if db_path:
            conn = sqlite3.connect(db_path)
            conn.execute("UPDATE projects SET status=? WHERE name=?", ("error", project))
            conn.commit()
            conn.close()
        runner_log(f"Pipeline aborted: {e}")
        sys.exit(1)

    # ... after success
    if db_path:
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE projects SET status=? WHERE name=?", ("done", project))
        conn.commit()
        conn.close()
```

- [ ] **Step 6: Commit**

```bash
git add biz_recon/runner.py
git commit -m "feat: project mode with post-stage file import

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Web backend — Flask app and REST API

**Files:**
- Create: `vuln_agent/web/__init__.py` (empty)
- Create: `vuln_agent/web/app.py`
- Create: `vuln_agent/web/api.py`

- [ ] **Step 1: Create `web/__init__.py`**

Empty file.

- [ ] **Step 2: Create `web/app.py`**

```python
"""Flask application entry point."""

from flask import Flask, send_from_directory
from .api import api_bp


def create_app():
    app = Flask(__name__, static_folder="static")
    app.register_blueprint(api_bp, url_prefix="/api")

    @app.route("/")
    @app.route("/<path:path>")
    def serve_spa(path=""):
        return send_from_directory("static", "index.html")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
```

- [ ] **Step 3: Create `web/api.py`**

```python
"""REST API blueprint for project management."""

import os
import subprocess
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

api_bp = Blueprint("api", __name__)

# Import from parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))
import db

VAR_DIR = Path(__file__).parent.parent / "var" / "projects"


@api_bp.route("/projects", methods=["GET"])
def handle_list_projects():
    return jsonify(db.list_projects())


@api_bp.route("/projects", methods=["POST"])
def handle_create_project():
    data = request.get_json()
    if not data or not data.get("name"):
        return jsonify({"error": "name is required"}), 400

    name = data["name"]
    proj_path = db.get_project_path(name)

    if proj_path.exists():
        return jsonify({"error": "project already exists"}), 409

    proj_path.mkdir(parents=True, exist_ok=True)
    db_path = proj_path / "results.db"
    db.init_db(str(db_path))

    # Write project metadata
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO projects (name, target_dir, collect_prompt, analyze_prompt, vuln_prompt, model, agent, force_surface, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (name, data.get("target_dir", ""), data.get("collect_prompt", ""),
         data.get("analyze_prompt", ""), data.get("vuln_prompt", ""),
         data.get("model", ""), data.get("agent", ""),
         data.get("force_surface", ""), "pending"),
    )
    conn.commit()
    conn.close()

    return jsonify({"name": name, "status": "pending"}), 201


@api_bp.route("/projects/<name>", methods=["GET"])
def handle_get_project(name):
    proj = db.get_project(name)
    if proj is None:
        return jsonify({"error": "not found"}), 404

    db_path = str(db.get_project_path(name) / "results.db")
    proj["file_counts"] = {}
    for stage in ("surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review"):
        proj["file_counts"][stage] = db.count_files(db_path, stage)
    return jsonify(proj)


@api_bp.route("/projects/<name>", methods=["DELETE"])
def handle_delete_project(name):
    import shutil
    proj_path = db.get_project_path(name)
    if not proj_path.exists():
        return jsonify({"error": "not found"}), 404
    shutil.rmtree(proj_path)
    return jsonify({"status": "deleted"})


@api_bp.route("/projects/<name>/run", methods=["POST"])
def handle_run_project(name):
    proj = db.get_project(name)
    if proj is None:
        return jsonify({"error": "not found"}), 404

    # Update status to running
    db_path = str(db.get_project_path(name) / "results.db")
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE projects SET status=? WHERE name=?", ("running", name))
    conn.commit()
    conn.close()

    # Build command
    cmd = [sys.executable, "run.py", proj["target_dir"], "--project", name]
    if proj.get("collect_prompt"):
        cmd += ["--collect-prompt", proj["collect_prompt"]]
    if proj.get("analyze_prompt"):
        cmd += ["--analyze-prompt", proj["analyze_prompt"]]
    if proj.get("vuln_prompt"):
        cmd += ["--vuln-prompt", proj["vuln_prompt"]]
    if proj.get("model"):
        cmd += ["--model", proj["model"]]
    if proj.get("agent"):
        cmd += ["--agent", proj["agent"]]
    if proj.get("force_surface"):
        cmd += ["--force-surface", proj["force_surface"]]

    # Launch asynchronously
    subprocess.Popen(
        cmd,
        cwd=str(Path(__file__).parent.parent),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return jsonify({"status": "running"}), 202


@api_bp.route("/projects/<name>/files/<stage>", methods=["GET"])
def handle_list_files(name, stage):
    VALID_STAGES = {"surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review"}
    if stage not in VALID_STAGES:
        return jsonify({"error": f"invalid stage: {stage}"}), 400

    db_path = str(db.get_project_path(name) / "results.db")
    if not Path(db_path).exists():
        return jsonify({"error": "project not found"}), 404

    return jsonify({"stage": stage, "files": db.list_files(db_path, stage)})


@api_bp.route("/projects/<name>/files/<stage>/<int:file_id>", methods=["GET"])
def handle_get_file(name, stage, file_id):
    VALID_STAGES = {"surfaces", "analysis", "vuln_tasks", "vulnerabilities", "vuln_review"}
    if stage not in VALID_STAGES:
        return jsonify({"error": f"invalid stage: {stage}"}), 400

    db_path = str(db.get_project_path(name) / "results.db")
    if not Path(db_path).exists():
        return jsonify({"error": "project not found"}), 404

    file_data = db.get_file(db_path, stage, file_id)
    if file_data is None:
        return jsonify({"error": "file not found"}), 404
    return jsonify(file_data)
```

- [ ] **Step 4: Verify Flask startup**

Run: `cd /root/projects/vuln_agent && python3 -c "from web.app import create_app; app = create_app(); print('OK')"`
Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add web/
git commit -m "feat: Flask REST API for project management

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Frontend SPA

**Files:**
- Create: `vuln_agent/web/static/index.html`
- Create: `vuln_agent/web/static/app.js`
- Create: `vuln_agent/web/static/style.css`

- [ ] **Step 1: Create `static/index.html`**

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vuln Agent</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css">
<link rel="stylesheet" href="style.css">
</head>
<body>
<div id="app"></div>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script src="app.js"></script>
</body>
</html>
```

- [ ] **Step 2: Create `static/style.css`**

A clean, minimal stylesheet for the project list, detail view, file list, and markdown content display. Include responsive basics, card layout for projects, sidebar or tree view for stages, and markdown body styling with code highlighting support.

```css
/* === Reset & Base === */
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }

/* === Layout === */
.container { max-width: 960px; margin: 0 auto; padding: 20px; }
.card { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1); padding: 20px; margin-bottom: 16px; }
.card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }

/* === Nav === */
.nav { display: flex; align-items: center; gap: 12px; padding: 12px 0; margin-bottom: 20px; border-bottom: 1px solid #e0e0e0; }
.nav a { color: #0366d6; text-decoration: none; font-size: 14px; }
.nav a:hover { text-decoration: underline; }
.nav-title { font-size: 18px; font-weight: 600; color: #333; }

/* === Buttons === */
.btn { display: inline-block; padding: 8px 16px; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
.btn-primary { background: #0366d6; color: #fff; }
.btn-primary:hover { background: #0256b3; }
.btn-danger { background: #d73a49; color: #fff; }
.btn-outline { background: transparent; border: 1px solid #d0d0d0; }

/* === Forms === */
.form-group { margin-bottom: 12px; }
.form-group label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 4px; color: #555; }
.form-group input, .form-group textarea { width: 100%; padding: 8px 12px; border: 1px solid #d0d0d0; border-radius: 6px; font-size: 14px; }

/* === Stage List === */
.stage-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; }
.stage-card { padding: 16px; background: #f8f9fa; border-radius: 8px; border: 1px solid #e8e8e8; cursor: pointer; transition: border-color .2s; }
.stage-card:hover { border-color: #0366d6; }
.stage-card h3 { font-size: 14px; margin-bottom: 4px; }
.stage-card .count { font-size: 24px; font-weight: 700; color: #0366d6; }

/* === File List === */
.file-list { list-style: none; }
.file-list li { padding: 10px 12px; border-bottom: 1px solid #eee; cursor: pointer; font-size: 14px; }
.file-list li:hover { background: #f0f6ff; }
.file-list li:last-child { border-bottom: none; }

/* === Markdown Content === */
.markdown-body { padding: 20px; background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
.markdown-body h1 { font-size: 24px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #eee; }
.markdown-body h2 { font-size: 20px; margin: 20px 0 10px; }
.markdown-body h3 { font-size: 16px; margin: 16px 0 8px; }
.markdown-body p { margin: 8px 0; }
.markdown-body pre { background: #f6f8fa; padding: 16px; border-radius: 6px; overflow-x: auto; margin: 12px 0; }
.markdown-body code { font-size: 13px; }
.markdown-body table { border-collapse: collapse; width: 100%; margin: 12px 0; }
.markdown-body th, .markdown-body td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
.markdown-body th { background: #f6f8fa; }
.markdown-body blockquote { border-left: 4px solid #0366d6; padding: 0 16px; color: #666; margin: 12px 0; }
.markdown-body strong { font-weight: 600; }
```

- [ ] **Step 3: Create `static/app.js`**

A single-page app with hash routing and API calls. Functions for each view:

```javascript
// State
const API = '/api';

// Router
function route() {
  const hash = location.hash.slice(1) || '/projects';
  const parts = hash.split('/').filter(Boolean);
  
  if (hash === '/projects') renderProjectList();
  else if (parts.length === 2 && parts[0] === 'projects') renderProjectDetail(parts[1]);
  else if (parts.length === 3 && parts[0] === 'projects') renderStageFiles(parts[1], parts[2]);
  else if (parts.length === 4 && parts[0] === 'projects') renderFileDetail(parts[1], parts[2], parseInt(parts[3]));
}

window.addEventListener('hashchange', route);
window.addEventListener('load', route);

// API helpers
async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: {'Content-Type': 'application/json'},
    ...opts,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function navigate(hash) { location.hash = hash; }

// View: Project List
async function renderProjectList() {
  const projects = await api('/projects');
  document.getElementById('app').innerHTML = `
    <div class="container">
      <div class="nav"><span class="nav-title">Vuln Agent</span></div>
      <div class="card">
        <h2>创建项目</h2>
        <form id="create-form">
          <div class="form-group"><label>项目名</label><input name="name" required></div>
          <div class="form-group"><label>目标目录</label><input name="target_dir" required></div>
          <div class="form-group"><label>Collect Prompt</label><input name="collect_prompt"></div>
          <div class="form-group"><label>Analyze Prompt</label><input name="analyze_prompt"></div>
          <div class="form-group"><label>Vuln Prompt</label><input name="vuln_prompt"></div>
          <div class="form-group"><label>Model</label><input name="model"></div>
          <div class="form-group"><label>Agent</label><input name="agent"></div>
          <button type="submit" class="btn btn-primary">创建</button>
        </form>
      </div>
      <h2>项目列表</h2>
      ${projects.length === 0 ? '<p>暂无项目</p>' : projects.map(p => `
        <div class="card" onclick="navigate('/projects/${p.name}')" style="cursor:pointer">
          <div class="card-header">
            <strong>${p.name}</strong>
            <span class="badge ${p.status}">${p.status}</span>
          </div>
          <div>目标: ${p.target_dir}</div>
          <div>创建时间: ${p.created_at || '-'}</div>
        </div>
      `).join('')}
    </div>
  `;
  document.getElementById('create-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    await api('/projects', {method: 'POST', body: JSON.stringify(data)});
    navigate('/projects');
  });
}

// View: Project Detail
async function renderProjectDetail(name) {
  const proj = await api(`/projects/${name}`);
  document.getElementById('app').innerHTML = `
    <div class="container">
      <div class="nav">
        <a href="#" onclick="navigate('/projects'); return false">← 项目列表</a>
        <span class="nav-title">${proj.name}</span>
      </div>
      <div class="card">
        <p><strong>目标目录:</strong> ${proj.target_dir}</p>
        <p><strong>状态:</strong> ${proj.status}</p>
        <p><strong>创建时间:</strong> ${proj.created_at || '-'}</p>
        ${proj.status === 'pending' ? '<button class="btn btn-primary" onclick="runProject(\'' + proj.name + '\')">开始分析</button>' : ''}
        <button class="btn btn-danger" onclick="deleteProject('${proj.name}')">删除</button>
      </div>
      <h2>分析结果</h2>
      <div class="stage-grid">
        ${['surfaces','analysis','vuln_tasks','vulnerabilities','vuln_review'].map(s => `
          <div class="stage-card" onclick="navigate('/projects/${proj.name}/${s}')">
            <h3>${stageLabel(s)}</h3>
            <div class="count">${proj.file_counts?.[s] ?? 0}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

async function runProject(name) {
  await api(`/projects/${name}/run`, {method: 'POST'});
  navigate(`/projects/${name}`);
}

async function deleteProject(name) {
  if (!confirm('确定删除该项目？')) return;
  await api(`/projects/${name}`, {method: 'DELETE'});
  navigate('/projects');
}

// View: Stage File List
async function renderStageFiles(name, stage) {
  const data = await api(`/projects/${name}/files/${stage}`);
  document.getElementById('app').innerHTML = `
    <div class="container">
      <div class="nav">
        <a href="#" onclick="navigate('/projects/${name}'); return false">← ${name}</a>
        <span class="nav-title">${stageLabel(stage)}</span>
      </div>
      <div class="card">
        ${data.files.length === 0 ? '<p>暂无文件</p>' : '<ul class="file-list">' + data.files.map(f => `
          <li onclick="navigate('/projects/${name}/${stage}/${f.id}')">${f.filename}</li>
        `).join('') + '</ul>'}
      </div>
    </div>
  `;
}

// View: File Detail
async function renderFileDetail(name, stage, fileId) {
  const file = await api(`/projects/${name}/files/${stage}/${fileId}`);
  document.getElementById('app').innerHTML = `
    <div class="container">
      <div class="nav">
        <a href="#" onclick="navigate('/projects/${name}/${stage}'); return false">← ${stageLabel(stage)}</a>
        <span class="nav-title">${file.filename}</span>
      </div>
      <div class="markdown-body">${marked.parse(file.content)}</div>
    </div>
  `;
  document.querySelectorAll('.markdown-body pre code').forEach(block => hljs.highlightElement(block));
}

function stageLabel(s) {
  const labels = {
    surfaces: '暴露面',
    analysis: '攻击面分析',
    vuln_tasks: '漏洞分析任务',
    vulnerabilities: '漏洞分析结论',
    vuln_review: '二次审查结论',
  };
  return labels[s] || s;
}
```

- [ ] **Step 4: Test frontend loading**

Start dev server: `cd /root/projects/vuln_agent && python3 -c "from web.app import create_app; app = create_app(); app.run(host='0.0.0.0', port=5000, debug=True)"` and open `http://localhost:5000/`

- [ ] **Step 5: Commit**

```bash
git add web/static/
git commit -m "feat: static SPA frontend with project management views

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: `requirements.txt` update

**Files:**
- Modify: `vuln_agent/requirements.txt`

- [ ] **Step 1: Add flask**

```
flask>=3.0
```

- [ ] **Step 2: Commit**

```bash
git add requirements.txt
git commit -m "chore: add flask dependency

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Self-Review Checklist

1. **Spec coverage:**
   - `db.py` → SQLite tables, import_stage(), list/query helpers ✓
   - `run.py --project` → CLI parameter + auto-naming ✓
   - `workspace.py` → flexible log base + OPENCODE_WORK_DIR support ✓
   - `runner.py` → post-stage import, project path, status updates ✓
   - `web/app.py` + `api.py` → Flask REST API with all endpoints ✓
   - `web/static/` → SPA with hash routing, file list, markdown rendering ✓
   - Log directory → `setup_logging()` accepts `log_base` → project logs go to project dir ✓
   - `requirements.txt` → flask dependency ✓

2. **Placeholder scan:** No TBD/TODO/filler patterns ✓

3. **Type consistency:**
   - `_resolve_project()` used in run.py, resolves to string ✓
   - `db.import_stage()` signature matches usage in runner.py ✓
   - API endpoints match expected paths from spec ✓
   - Stage names consistent across db.py, api.py, app.js ✓
