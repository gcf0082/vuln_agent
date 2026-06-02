# -*- coding: utf-8 -*-
"""Stage 2.5: Vulnerability task planning — generate vuln analysis tasks per file."""

import concurrent.futures
import re
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, find_surface_files, log


GENERIC_TASK_TEMPLATE = """\
# {name} — 通用漏洞扫描

分析文件：{analysis_file}
"""


def _ensure_generic_task(work_dir: Path, analysis_file: str):
    """Auto-generate the generic task -0.md for a surface if not exists."""
    tasks_dir = work_dir / OUTPUT_PARENT / "vuln_tasks"
    tasks_dir.mkdir(parents=True, exist_ok=True)
    stem = analysis_file.replace(".md", "")
    generic_path = tasks_dir / f"{stem}-0.md"
    if not generic_path.exists():
        generic_path.write_text(
            GENERIC_TASK_TEMPLATE.format(
                name=stem,
                analysis_file=analysis_file,
            )
        )
        log(f"  + {generic_path.name}")
    return generic_path


def run(work_dir: Path, max_workers: int = 3):
    log(f"\n=== Stage 2.5: Vulnerability Task Planning ===")

    analysis_files = find_surface_files(work_dir)
    if not analysis_files:
        log("  No analysis files found.")
        return []

    tasks_dir = work_dir / OUTPUT_PARENT / "vuln_tasks"

    # Always ensure generic task -0.md exists for each surface
    for sf in analysis_files:
        _ensure_generic_task(work_dir, sf.name)

    # Check if specific tasks (excluding -0.md) already exist
    existing_specific = sorted(
        f for f in tasks_dir.glob("*.md")
        if not f.name.startswith("_") and not f.stem.endswith("-0")
    ) if tasks_dir.exists() else []
    if existing_specific:
        log(f"  SKIP: specific tasks already exist ({len(existing_specific)} files)")
        return sorted(tasks_dir.glob("*.md"))

    tasks_dir.mkdir(parents=True, exist_ok=True)
    log(f"  Planning tasks from {len(analysis_files)} analysis files (workers={max_workers})...")
    vars = build_vars(work_dir)
    failures: list[str] = []

    def plan_one(sf_path):
        log(f"  ▶ {sf_path.name}")
        local_vars = {**vars,
            "surface_file": sf_path.name,
            "surface_stem": sf_path.stem,
        }
        prompt = read_prompt("plan-vuln-tasks.txt", local_vars)

        client = OpenCodeClient()
        result = client.run(prompt)
        if result.exit_code != 0:
            log(f"  ✗ {sf_path.name}")
            return False
        log(f"  ✓ {sf_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for sf_path, ok in zip(analysis_files, pool.map(plan_one, analysis_files)):
            if not ok:
                failures.append(sf_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        log(msg)
        print(msg, flush=True)

    return sorted(tasks_dir.glob("*.md"))
