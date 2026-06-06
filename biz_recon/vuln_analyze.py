# -*- coding: utf-8 -*-
"""Stage 4: vuln_analyze — execute vulnerability analysis per planned task, parallel."""

import concurrent.futures
import re
from pathlib import Path
from opencode_wrapper import OpenCodeClient
from .prompt import read_prompt
from .workspace import OUTPUT_PARENT, build_vars, find_vuln_files, log


def _task_has_vuln_output(task_stem: str, vuln_dir: Path) -> bool:
    """Check if a task file already has corresponding vulnerability analysis results."""
    if not vuln_dir.exists():
        return False
    pattern = re.compile(rf'^(?:VULN|DISMISSED|CLEAN|SUSPECTED)-{re.escape(task_stem)}-\d+\.md$')
    return any(pattern.match(f.name) for f in vuln_dir.iterdir())


def run(work_dir: Path, max_workers: int = 3,
        extra_prompt: str = "",
        force_list: list[str] | None = None):
    from .workspace import ensure_dirs, setup_stage_log
    va_log = setup_stage_log("vuln_analyze")
    va_log(f"\n=== Stage 4: Vulnerability Analysis ===")
    ensure_dirs(work_dir)

    tasks_dir = work_dir / OUTPUT_PARENT / "planned_vuln_tasks"
    if not tasks_dir.exists():
        va_log("  No tasks directory found. Run task planning first.")
        return find_vuln_files(work_dir)

    task_files = sorted(tasks_dir.glob("*.md"))
    # Filter out _no_tasks files — they are not actual analysis tasks
    task_files = [f for f in task_files if not f.name.startswith("_no_tasks")]
    if not task_files:
        va_log("  No task files found. Run task planning first.")
        return find_vuln_files(work_dir)

    vuln_dir = work_dir / OUTPUT_PARENT / "vuln_findings"

    if force_list:
        stems = [n.replace(".md", "") for n in force_list]
        task_files = [f for f in task_files if any(s in f.name for s in stems)]
        if not task_files:
            va_log(f"  No matching tasks for force-list: {force_list}")
            return find_vuln_files(work_dir)
        va_log(f"  Force re-analyzing {len(task_files)} task(s): {[f.name for f in task_files]}")
    else:
        # Per-task skip: only analyze tasks without existing vuln outputs
        need_analysis = [f for f in task_files if not _task_has_vuln_output(f.stem, vuln_dir)]
        skipped = len(task_files) - len(need_analysis)
        if not need_analysis:
            va_log(f"  All {len(task_files)} tasks already have vulnerability analysis results.")
            return find_vuln_files(work_dir)
        task_files = need_analysis
        va_log(f"  Analyzing {len(task_files)} tasks ({skipped} already have results, workers={max_workers})...")

    vars = build_vars(work_dir)
    failures: list[str] = []

    def analyze_one(task_path):
        ao_log = setup_stage_log("vuln_analyze", task_path.name)
        ao_log(f"  ▶ {task_path.name}")
        task_text = task_path.read_text()

        # Derive analysis file name from task filename:
        #   iface-REST-ping-0.md → iface-REST-ping.md
        #   iface-REST-ping-1.md → iface-REST-ping.md
        source_file = re.sub(r'-\d+$', '', task_path.stem) + '.md'

        local_vars = {**vars,
            "task_file": task_path.name,
            "task_stem": task_path.stem,
            "task_content": task_text,
            "surface_file": source_file,
            "surface_stem": source_file.replace(".md", ""),
            "extra_prompt": f"\n**用户特殊要求：**{extra_prompt}" if extra_prompt else "",
        }
        prompt = read_prompt("analyze-vulnerability.txt", local_vars)

        from .workspace import set_prompt_log_path
        set_prompt_log_path("vuln_analyze", task_path.name)
        client = OpenCodeClient()
        result = client.run(prompt)
        if result.exit_code != 0:
            ao_log(f"  ✗ {task_path.name}")
            return False
        ao_log(f"  ✓ {task_path.name}")
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for task_path, ok in zip(task_files, pool.map(analyze_one, task_files)):
            if not ok:
                failures.append(task_path.name)

    if failures:
        msg = f"  FAILURES ({len(failures)}): {', '.join(failures)}"
        va_log(msg)
        print(msg, flush=True)

    return find_vuln_files(work_dir)
