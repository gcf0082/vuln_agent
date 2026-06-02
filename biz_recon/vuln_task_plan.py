# -*- coding: utf-8 -*-
"""Stage 2.5: Vulnerability task planning — generate vuln analysis tasks per file."""

import concurrent.futures
import re
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, find_surface_files, log


GENERIC_TASK_TEMPLATE = """\
分析给定输入文件
"""


def _ensure_generic_task(work_dir: Path, analysis_file: str):
    """Auto-generate the generic task -0.md for a surface if not exists."""
    tasks_dir = work_dir / OUTPUT_PARENT / "vuln_tasks"
    tasks_dir.mkdir(parents=True, exist_ok=True)
    stem = analysis_file.replace(".md", "")
    generic_path = tasks_dir / f"{stem}-0.md"
    if not generic_path.exists():
        generic_path.write_text(GENERIC_TASK_TEMPLATE.strip())
        log(f"  + {generic_path.name}")
    return generic_path


def run(work_dir: Path, max_workers: int = 3,
        force_list: list[str] | None = None):
    log(f"\n=== Stage 2.5: Vulnerability Task Planning ===")

    analysis_files = find_surface_files(work_dir)
    if not analysis_files:
        log("  No analysis files found.")
        return []

    # Filter to forced surfaces if specified
    if force_list:
        stems = [n.replace(".md", "") for n in force_list]
        analysis_files = [sf for sf in analysis_files if sf.stem in stems]
        if not analysis_files:
            log("  No analysis files matched force_list.")
            return []
        log(f"  Force surfaces: {[sf.name for sf in analysis_files]}")

    tasks_dir = work_dir / OUTPUT_PARENT / "vuln_tasks"

    # Always ensure generic task -0.md exists for each surface
    for sf in analysis_files:
        _ensure_generic_task(work_dir, sf.name)

    # Per-surface: skip if already has corresponding files (except -0)
    def _has_existing(stem: str) -> bool:
        if not tasks_dir.exists():
            return False
        # _no_tasks-{stem}.md exists
        if (tasks_dir / f"_no_tasks-{stem}.md").exists():
            return True
        # {stem}-{n}.md for n>=1 exists
        return any(re.search(r'-\d+$', f.stem) for f in tasks_dir.glob(f"{stem}-*.md"))

    need_planning = [sf for sf in analysis_files if not _has_existing(sf.stem)]
    if not need_planning:
        log(f"  All surfaces already have task files ({len(analysis_files)}/{len(analysis_files)})")
        return sorted(tasks_dir.glob("*.md"))

    skipped = len(analysis_files) - len(need_planning)
    log(f"  Planning tasks for {len(need_planning)} surfaces ({skipped} already have tasks, workers={max_workers})...")
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
        for sf_path, ok in zip(need_planning, pool.map(plan_one, need_planning)):
            if not ok:
                failures.append(sf_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        log(msg)
        print(msg, flush=True)

    return sorted(tasks_dir.glob("*.md"))
