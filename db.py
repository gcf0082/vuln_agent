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
        conn.execute(f"DELETE FROM {stage} WHERE filename=?", (f.name,))
        conn.execute(
            f"INSERT INTO {stage} (filename, content) VALUES (?, ?)",
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


def delete_file(db_path: str, stage: str, file_id: int) -> str | None:
    """Delete a file by id from a stage table. Returns the filename if deleted, else None."""
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        f"SELECT filename FROM {stage} WHERE id=?", (file_id,)
    ).fetchone()
    if row is None:
        conn.close()
        return None
    filename = row[0]
    conn.execute(f"DELETE FROM {stage} WHERE id=?", (file_id,))
    conn.commit()
    conn.close()
    return filename


def clear_stage(db_path: str, stage: str):
    """Delete all records from a stage table."""
    conn = sqlite3.connect(db_path)
    conn.execute(f"DELETE FROM {stage}")
    conn.commit()
    conn.close()


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
